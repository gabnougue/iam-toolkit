<#
.SYNOPSIS
    Detects Active Directory principals (users + computers) whose password is configured
    to never expire (UAC bit DONT_EXPIRE_PASSWORD = 0x10000).

.DESCRIPTION
    Filters AD principals with the DONT_EXPIRE_PASSWORD flag set using a server-side LDAP
    bitwise filter (no client-side enumeration of all accounts). Reports each match with
    the metadata an auditor needs to prioritize: ObjectClass, Enabled state, PasswordAge
    in days, AdminCount, and DistinguishedName.

    Disabled accounts are excluded by default - a disabled-with-PNE account is hygiene,
    not exposure. Use -IncludeDisabled to surface them anyway (relevant when auditing
    accounts like KRBTGT whose password rotation cadence is itself worth reviewing).

    Managed service accounts (gMSAs and sMSAs) are excluded by default because they
    rotate passwords automatically via msDS-ManagedPassword. Use
    -IncludeManagedServiceAccounts to include them for completeness.

    Privileged accounts (AdminCount=1) are surfaced at the top of the report - a
    privileged account with a non-expiring password is the highest-priority finding,
    especially if it also has a Service Principal Name (Kerberoasting target with an
    offline-crackable hash that doesn't rotate).

.PARAMETER IncludeDisabled
    Include disabled accounts in the report. By default only enabled accounts are
    returned.

.PARAMETER IncludeManagedServiceAccounts
    Additionally query Get-ADServiceAccount for gMSAs/sMSAs that have PNE set. By
    default these are excluded because they manage their own password rotation.

.PARAMETER SearchBase
    Distinguished name of an OU to scope the search. Applied to both the user/computer
    query and (when -IncludeManagedServiceAccounts is set) the service account query -
    note that managed service accounts live in `CN=Managed Service Accounts,DC=...`
    by default, so a narrow SearchBase will silently exclude them.

.PARAMETER Server
    Specific domain controller to query. If omitted, the nearest available DC is used.

.PARAMETER OutputPath
    Path of the CSV file to write. Defaults to
    .\PasswordNeverExpires_<yyyyMMdd_HHmmss>.csv in the current directory.

.EXAMPLE
    .\Get-PasswordNeverExpires.ps1
    Reports enabled users and computers with PNE set.

.EXAMPLE
    .\Get-PasswordNeverExpires.ps1 -IncludeDisabled -OutputPath .\pne-all.csv
    Includes disabled accounts (KRBTGT, etc.).

.EXAMPLE
    .\Get-PasswordNeverExpires.ps1 -IncludeManagedServiceAccounts
    Also audits gMSAs/sMSAs.

.EXAMPLE
    .\Get-PasswordNeverExpires.ps1 -SearchBase "OU=Servers,DC=lab,DC=local"
    Restricts the audit to the Servers OU.

.NOTES
    Threat model (why PNE matters):

      Static password risk
        A password that never rotates accumulates exposure over time: credential dumps
        from past compromises, paste-site leaks, and helpdesk slip-ups all stay valid
        indefinitely. Rotation does not eliminate compromise but bounds its useful life.

      Kerberoasting amplification
        A privileged service account with a Service Principal Name (SPN) is a prime
        Kerberoasting target: any authenticated user can request a TGS for the SPN and
        crack the resulting hash offline. When PNE is set, the attacker has unlimited
        time - the password the cracker eventually recovers is still valid years later.

      Common causes
        - Legacy service accounts created before gMSAs existed.
        - Operator convenience ("we keep forgetting to rotate it").
        - Misunderstanding of the impact when applied to admin accounts.

      Recommended remediation
        - Service accounts -> migrate to gMSAs (automatic 30-day rotation).
        - Human admin accounts -> remove PNE, enforce rotation via password policy or PAM.
        - Service accounts that cannot be migrated -> enforce rotation via PAM/vault.

    System accounts:
      KRBTGT is disabled by default and excluded unless -IncludeDisabled is set. It
      legitimately has PNE = true but should be rotated twice (with a 10+ hour gap)
      every 180 days per Microsoft guidance, especially after any DC compromise.
      Built-in Administrator and Guest may also surface depending on configuration.

    Managed service accounts:
      gMSAs (msDS-GroupManagedServiceAccount) and sMSAs (msDS-ManagedServiceAccount)
      handle password rotation natively via msDS-ManagedPassword (default 30 days,
      tunable via the MSA's msDS-ManagedPasswordInterval). They are excluded by default
      to avoid noise. Use -IncludeManagedServiceAccounts to verify none have been
      misconfigured.

    Detection scope:
      This script audits the UAC bit ONLY. Fine-Grained Password Policies (PSOs) with
      MaxPasswordAge = 0 produce equivalent "never expires" behavior at the policy
      layer but require a separate query against msDS-PasswordSettings objects. Cover
      that path with a dedicated PSO audit if needed.

    Sort order:
      AdminCount=1 first, then known PasswordAge before null (pwdLastSet=0 means
      "must change at next logon" - a distinct finding), then PasswordAge descending
      (oldest passwords first), then SamAccountName.

    Requires the ActiveDirectory PowerShell module (RSAT-AD-PowerShell) and read access
    to the directory.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeDisabled,

    [Parameter()]
    [switch]$IncludeManagedServiceAccounts,

    [Parameter()]
    [string]$SearchBase,

    [Parameter()]
    [string]$Server,

    [Parameter()]
    [string]$OutputPath = ".\PasswordNeverExpires_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "The ActiveDirectory module is not installed. Install RSAT (RSAT-AD-PowerShell) and re-run."
}

Import-Module ActiveDirectory -ErrorAction Stop

# UAC bits used by the LDAP bitwise filter and by client-side Enabled decoding
$DONT_EXPIRE_PASSWORD = 0x10000   # 65536
$ACCOUNTDISABLE       = 0x2

# 1.2.840.113556.1.4.803 = LDAP_MATCHING_RULE_BIT_AND (server-side bitwise AND)
$ldapClauses = @(
    '(|(objectCategory=person)(objectCategory=computer))'
    "(userAccountControl:1.2.840.113556.1.4.803:=$DONT_EXPIRE_PASSWORD)"
)
if (-not $IncludeDisabled) {
    $ldapClauses += "(!(userAccountControl:1.2.840.113556.1.4.803:=$ACCOUNTDISABLE))"
}
$ldapFilter = '(&' + ($ldapClauses -join '') + ')'
Write-Verbose "LDAP filter: $ldapFilter"

$adParams = @{ ErrorAction = 'Stop' }
if ($PSBoundParameters.ContainsKey('Server'))     { $adParams.Server     = $Server }
if ($PSBoundParameters.ContainsKey('SearchBase')) { $adParams.SearchBase = $SearchBase }

$queryProps = @(
    'SamAccountName', 'DisplayName', 'ObjectClass',
    'userAccountControl', 'pwdLastSet', 'adminCount', 'DistinguishedName'
)

try {
    $objs = Get-ADObject -LDAPFilter $ldapFilter -Properties $queryProps @adParams
}
catch {
    throw "Failed to query Active Directory: $($_.Exception.Message)"
}

$svcAccts = @()
if ($IncludeManagedServiceAccounts) {
    $svcFilter = if ($IncludeDisabled) { 'PasswordNeverExpires -eq $true' }
                 else                  { 'PasswordNeverExpires -eq $true -and Enabled -eq $true' }
    try {
        $svcAccts = Get-ADServiceAccount -Filter $svcFilter -Properties $queryProps @adParams
    }
    catch {
        Write-Warning "Get-ADServiceAccount failed (managed service accounts will be skipped): $($_.Exception.Message)"
    }
}

$all = @($objs) + @($svcAccts)
Write-Verbose "Retrieved $(@($all).Count) principal(s) with DONT_EXPIRE_PASSWORD"

$now = Get-Date

$rawRows = foreach ($o in $all) {
    $enabled = -not [bool]($o.userAccountControl -band $ACCOUNTDISABLE)

    $pwdLastSetDt = if ($o.pwdLastSet -and $o.pwdLastSet -gt 0) { [DateTime]::FromFileTime($o.pwdLastSet) } else { $null }
    $passwordAge  = if ($pwdLastSetDt) { [int]($now - $pwdLastSetDt).TotalDays } else { $null }

    # Strip the leading CN=... component, handling escaped commas inside the CN
    $ou = ($o.DistinguishedName -split '(?<!\\),', 2)[1]

    [PSCustomObject]@{
        SamAccountName    = $o.SamAccountName
        DisplayName       = $o.DisplayName
        ObjectClass       = $o.ObjectClass
        Enabled           = $enabled
        PasswordLastSetDt = $pwdLastSetDt
        PasswordAge       = $passwordAge
        AdminCount        = $o.adminCount
        OU                = $ou
        DistinguishedName = $o.DistinguishedName
    }
}

# Privileged first, then known PasswordAge before null, then by age desc, then SAM
$results = $rawRows |
    Sort-Object `
        @{Expression = { if ($_.AdminCount -eq 1) { 0 } else { 1 } } }, `
        @{Expression = { if ($null -ne $_.PasswordAge) { 0 } else { 1 } } }, `
        @{Expression = 'PasswordAge'; Descending = $true }, `
        SamAccountName |
    ForEach-Object {
        [PSCustomObject]@{
            SamAccountName    = $_.SamAccountName
            DisplayName       = $_.DisplayName
            ObjectClass       = $_.ObjectClass
            Enabled           = $_.Enabled
            PasswordLastSet   = if ($_.PasswordLastSetDt) { $_.PasswordLastSetDt.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
            PasswordAge       = $_.PasswordAge
            AdminCount        = $_.AdminCount
            OU                = $_.OU
            DistinguishedName = $_.DistinguishedName
        }
    }

if ($results) {
    try {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    }
    catch {
        throw "Failed to write CSV to '$OutputPath': $($_.Exception.Message)"
    }
    Write-Host "Found $(@($results).Count) account(s) with DONT_EXPIRE_PASSWORD. Report written to: $OutputPath"
}
else {
    Write-Host "No accounts found with DONT_EXPIRE_PASSWORD."
}

$results
