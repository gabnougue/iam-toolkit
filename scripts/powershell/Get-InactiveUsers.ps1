<#
.SYNOPSIS
    Detects enabled Active Directory principals (users + managed service accounts) that have
    not logged on for a configurable number of days.

.DESCRIPTION
    Audits enabled principals against an inactivity threshold and reports those that have
    either never logged on or whose last logon predates the threshold. The default mode
    relies on `lastLogonTimestamp` (replicated, ~14-day lag) and is fast; -AccurateMode
    queries every DC for the per-DC `lastLogon` attribute and takes the max, eliminating
    the lag for boundary-sensitive audits.

    Group Managed Service Accounts (gMSAs) and standalone Managed Service Accounts (sMSAs)
    are included via Get-ADServiceAccount. An inactive service account is a dead service
    that should be decommissioned and is just as much an IAM hygiene issue as a stale user.

    Privileged accounts (AdminCount=1) are surfaced at the top of the report — a stale
    privileged account is the highest-priority finding.

.PARAMETER DaysInactive
    Number of days of inactivity that qualifies a principal as inactive. Defaults to 90.

.PARAMETER SearchBase
    Distinguished name of an OU to scope the user search. Applied ONLY to the user query.
    The gMSA/sMSA query is always run domain-wide because managed service accounts live in
    CN=Managed Service Accounts,DC=... and would be silently zeroed out if SearchBase
    pointed at an OU.

.PARAMETER Server
    Specific domain controller to query for the initial principal listing. Under
    -AccurateMode this DC's per-DC `lastLogon` values are captured during the listing pass
    and the per-DC scan deliberately skips it — no DC is queried twice.

.PARAMETER AccurateMode
    Queries every domain controller for the per-DC `lastLogon` attribute (NOT replicated;
    updated in real time) and uses the maximum value across DCs as the authoritative
    last-logon time. In this mode the listing fetches `lastLogon` directly (instead of
    the replicated-but-lagging `lastLogonTimestamp`) so the listing DC contributes its
    value without an extra round-trip. Costs roughly N queries for N DCs.

.PARAMETER OutputPath
    Path of the CSV file to write. Defaults to .\InactiveUsers_<yyyyMMdd_HHmmss>.csv in the
    current directory.

.EXAMPLE
    .\Get-InactiveUsers.ps1
    Reports principals inactive for more than 90 days using replicated lastLogonTimestamp.

.EXAMPLE
    .\Get-InactiveUsers.ps1 -DaysInactive 30 -OutputPath .\inactive-30d.csv
    Lowers the threshold to 30 days.

.EXAMPLE
    .\Get-InactiveUsers.ps1 -AccurateMode
    Cross-references every DC's per-DC lastLogon. Slower but eliminates replication lag.

.EXAMPLE
    .\Get-InactiveUsers.ps1 -SearchBase "OU=IT,DC=lab,DC=local" -DaysInactive 60
    Restricts the user audit to the IT OU (gMSAs are still scanned domain-wide).

.NOTES
    Inactivity logic:
      A principal is reported when:
        - whenCreated <= cutoff (it has been around long enough to have logged on), AND
        - lastLogon is null OR lastLogon < cutoff.
      Principals younger than the cutoff are excluded — they have not had time to log on.

    Replication behavior of last-logon attributes:
      lastLogonTimestamp - replicated to every DC, but with up to 14-day lag controlled by
                           the forest attribute msDS-LogonTimeSyncInterval. Default mode.
      lastLogon          - per-DC, NOT replicated, updated in real time. Used by
                           -AccurateMode which queries every DC and takes the max.

    AccurateMode round-trip optimization:
      The DC used for the initial listing is identified up front; its `lastLogon` values
      are gathered during the listing query itself. The per-DC scan then iterates only
      the *remaining* DCs. Net result: one listing query + (N-1) lightweight `lastLogon`
      queries, never N+1.

    SearchBase scoping:
      Applied only to the user query. The gMSA/sMSA query runs domain-wide because
      managed service accounts are not located under organizational OUs. Documenting
      this asymmetry avoids silent omission of service-account findings when an auditor
      scopes the run to an OU.

    System accounts:
      KRBTGT, Guest, and DefaultAccount are disabled by default and naturally excluded
      by the Enabled=true filter. The built-in Administrator user is enabled by default
      and will appear in the report if it is dormant — that itself is a legitimate
      finding (the account should either be used regularly with strong controls in
      place, or disabled in favor of named admin accounts).

    Managed Service Accounts:
      Both gMSAs (msDS-GroupManagedServiceAccount) and sMSAs (msDS-ManagedServiceAccount)
      are included via Get-ADServiceAccount. They have lastLogonTimestamp populated by
      whichever host most recently used them. PasswordLastSet on a gMSA reflects the
      automatic 30-day password rotation managed by AD, not human action.

    Sort order:
      Rows are ordered with AdminCount=1 entries first, then by oldest LastLogon
      ("Never" first within each tier), then by SamAccountName. The privileged stale
      accounts appear at the top of the report.

    Requires the ActiveDirectory PowerShell module (RSAT-AD-PowerShell) and read access
    to the directory.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [Parameter()]
    [string]$SearchBase,

    [Parameter()]
    [string]$Server,

    [Parameter()]
    [switch]$AccurateMode,

    [Parameter()]
    [string]$OutputPath = ".\InactiveUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "The ActiveDirectory module is not installed. Install RSAT (RSAT-AD-PowerShell) and re-run."
}

Import-Module ActiveDirectory -ErrorAction Stop

$cutoff = (Get-Date).AddDays(-$DaysInactive)
Write-Verbose "Cutoff date: $cutoff (DaysInactive = $DaysInactive)"

# In AccurateMode the listing fetches `lastLogon` (per-DC, real time) so the listing DC's
# value is captured for free. In default mode we use the replicated `lastLogonTimestamp`.
$listingProps = @(
    'SamAccountName', 'DisplayName', 'ObjectClass',
    'pwdLastSet', 'whenCreated', 'Enabled', 'adminCount', 'DistinguishedName'
)
$listingProps += if ($AccurateMode) { 'lastLogon' } else { 'lastLogonTimestamp' }

# Resolve the listing DC up front so the per-DC scan can deliberately skip it
$dcs = $null
$listingDc = $null
if ($AccurateMode) {
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
    }
    catch {
        throw "Failed to enumerate domain controllers for -AccurateMode: $($_.Exception.Message)"
    }
    if (-not $dcs) {
        throw "No domain controllers returned for -AccurateMode."
    }

    if ($PSBoundParameters.ContainsKey('Server')) {
        try {
            $listingDc = Get-ADDomainController -Identity $Server -ErrorAction Stop
        }
        catch {
            throw "Failed to resolve -Server '$Server' to a domain controller: $($_.Exception.Message)"
        }
    }
    else {
        $listingDc = $dcs[0]
    }
}

# Build the base listing param set
$listingParams = @{ ErrorAction = 'Stop' }
if ($AccurateMode) {
    $listingParams.Server = $listingDc.HostName
}
elseif ($PSBoundParameters.ContainsKey('Server')) {
    $listingParams.Server = $Server
}

# User listing also accepts SearchBase; gMSA listing does not (see .NOTES)
$userListingParams = $listingParams.Clone()
if ($PSBoundParameters.ContainsKey('SearchBase')) {
    $userListingParams.SearchBase = $SearchBase
}

try {
    $users = Get-ADUser -Filter 'Enabled -eq $true' -Properties $listingProps @userListingParams
}
catch {
    throw "Failed to query Active Directory users: $($_.Exception.Message)"
}

$svcAccts = @()
try {
    $svcAccts = Get-ADServiceAccount -Filter 'Enabled -eq $true' -Properties $listingProps @listingParams
}
catch {
    Write-Warning "Get-ADServiceAccount failed (gMSAs/sMSAs will be skipped): $($_.Exception.Message)"
}

$principals = @($users) + @($svcAccts)
Write-Verbose "Retrieved $(@($principals).Count) enabled principal(s) from listing DC"

# Accurate mode: seed the dict from the listing DC's lastLogon, then scan ONLY the remaining DCs
$accurateLastLogon = @{}
if ($AccurateMode) {
    foreach ($p in $principals) {
        if ($p.lastLogon -and $p.lastLogon -gt 0) {
            $accurateLastLogon[$p.SamAccountName] = [DateTime]::FromFileTime($p.lastLogon)
        }
    }
    Write-Verbose "Seeded $($accurateLastLogon.Count) lastLogon entr(y/ies) from listing DC '$($listingDc.HostName)'"

    $remainingDcs = $dcs | Where-Object { $_.HostName -ne $listingDc.HostName }
    foreach ($dc in $remainingDcs) {
        Write-Verbose "Querying additional DC: $($dc.HostName)"
        try {
            $perDcUsers = Get-ADUser -Filter 'Enabled -eq $true' -Properties lastLogon -Server $dc.HostName -ErrorAction Stop
            $perDcSvc   = try { Get-ADServiceAccount -Filter 'Enabled -eq $true' -Properties lastLogon -Server $dc.HostName -ErrorAction Stop }
                          catch { @() }

            foreach ($p in (@($perDcUsers) + @($perDcSvc))) {
                $ticks = $p.lastLogon
                if ($ticks -and $ticks -gt 0) {
                    $dt = [DateTime]::FromFileTime($ticks)
                    $sam = $p.SamAccountName
                    if (-not $accurateLastLogon.ContainsKey($sam) -or $accurateLastLogon[$sam] -lt $dt) {
                        $accurateLastLogon[$sam] = $dt
                    }
                }
            }
        }
        catch {
            Write-Warning "Failed to query DC '$($dc.HostName)': $($_.Exception.Message)"
        }
    }
}

$rawRows = foreach ($p in $principals) {
    # Skip principals younger than the cutoff — they have not had time to log on
    if ($p.whenCreated -and $p.whenCreated -gt $cutoff) { continue }

    $lastLogon = $null
    if ($AccurateMode) {
        if ($accurateLastLogon.ContainsKey($p.SamAccountName)) {
            $lastLogon = $accurateLastLogon[$p.SamAccountName]
        }
    }
    elseif ($p.LastLogonDate) {
        $lastLogon = $p.LastLogonDate
    }

    $isDormant = ($null -eq $lastLogon) -or ($lastLogon -lt $cutoff)
    if (-not $isDormant) { continue }

    # Strip the leading CN=... component, handling escaped commas inside the CN
    $ou = ($p.DistinguishedName -split '(?<!\\),', 2)[1]

    [PSCustomObject]@{
        SamAccountName    = $p.SamAccountName
        DisplayName       = $p.DisplayName
        ObjectClass       = $p.ObjectClass
        LastLogonRaw      = $lastLogon
        PasswordLastSet   = $p.PasswordLastSet
        WhenCreated       = $p.whenCreated
        Enabled           = $p.Enabled
        AdminCount        = $p.adminCount
        OU                = $ou
        DistinguishedName = $p.DistinguishedName
    }
}

# Privileged first, then oldest LastLogon (Never first within each tier), then SAM
$results = $rawRows |
    Sort-Object `
        @{Expression = { if ($_.AdminCount -eq 1) { 0 } else { 1 } } }, `
        @{Expression = { if ($_.LastLogonRaw)     { $_.LastLogonRaw } else { [DateTime]::MinValue } } }, `
        SamAccountName |
    ForEach-Object {
        [PSCustomObject]@{
            SamAccountName    = $_.SamAccountName
            DisplayName       = $_.DisplayName
            ObjectClass       = $_.ObjectClass
            LastLogon         = if ($_.LastLogonRaw)    { $_.LastLogonRaw.ToString('yyyy-MM-dd HH:mm:ss') }    else { 'Never' }
            PasswordLastSet   = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
            WhenCreated       = if ($_.WhenCreated)     { $_.WhenCreated.ToString('yyyy-MM-dd HH:mm:ss') }     else { $null }
            Enabled           = $_.Enabled
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
    Write-Host "Found $(@($results).Count) inactive principal(s). Report written to: $OutputPath"
}
else {
    Write-Host "No inactive principals found (threshold: $DaysInactive days)."
}

$results
