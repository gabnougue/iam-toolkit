<#
.SYNOPSIS
    Idempotently populates an Active Directory lab with intentionally misconfigured users,
    groups, and OUs that exercise every detection vector of the IAM Toolkit scripts.

.DESCRIPTION
    Creates ~31 users distributed across realistic OUs (IT, HR, Finance, Management, Service
    Accounts, Disabled Users) with deliberate IAM misconfigurations clustered to mirror
    patterns seen in production audits: stale privileged accounts, legacy service accounts
    with DA + PNE, never-logged-in provisioning leftovers, empty/orphan groups, and a
    too-young account that demonstrates the `Get-InactiveUsers.ps1` exclusion filter.

    The script is idempotent: re-running it leaves the lab in the same final state and
    reports what was created vs. updated vs. left untouched.

    Every seeded object carries the marker "[SEEDED-LAB]" at the start of its Description
    attribute so a future cleanup script can identify them precisely.

    Safety: by default the script refuses to run against any domain other than `lab.local`.
    Pass -Force to override (you assume responsibility for the target).

.PARAMETER DomainDN
    Distinguished name of the target domain. Auto-detected via Get-ADDomain when omitted.

.PARAMETER DefaultPassword
    Password assigned to every seeded user. Must satisfy the domain password policy.
    Default: 'LabPass!2026Demo' (meets default Win Server policy: 16 chars, 4 character
    classes, no username substring).

.PARAMETER Force
    Bypass the lab.local safety check. Use only when you have verified the target domain
    is isolated and intended for IAM toolkit testing.

.EXAMPLE
    .\seed-test-users.ps1
    Seeds the lab using auto-detected lab.local domain.

.EXAMPLE
    .\seed-test-users.ps1 -DefaultPassword 'CustomLab!2026'
    Uses a different password for seeded users.

.NOTES
    Misconfiguration coverage (as observed against the lab after seed run — the
    inactivity intent is preserved via the InactiveDays / NeverLoggedIn markers on
    New-LabUser, but AD prevents backdating lastLogonTimestamp via LDAP so both
    kinds of accounts appear as never-authenticated in Get-InactiveUsers.ps1):

      Never-authenticated (visible with Get-InactiveUsers -IncludeNewlyCreated) : 9 enabled
        - 5 carry InactiveDays intent  : mlefevre, sysadmin-legacy, alopez, ccfo, svc-legacy
        - 4 carry NeverLoggedIn intent : cstein, ldubois, jthomas, svc-print
      Privileged (direct DA membership)         : 4  (spec: 3+)
      Privileged (other sensitive groups)       : 3
      PasswordNeverExpires set                  : 9  (spec: 5+)
      Service account with DA                   : 2  (spec: 1+)
      Empty/orphan groups                       : 2  (spec: 2+)
      Nested group memberships (privilege)      : 2 chains
      Must-change-at-next-logon                 : 1  (edge-case finding)

    Cross-vector findings (the gold for lab demos):
      svc-legacy        : DA + PNE + never authenticated since creation — nobody
                          knows what it is for, nobody watches it, and it holds DA
      sysadmin-legacy   : BackupOp + PNE + never authenticated
      svc-backup        : DA + PNE (Kerberoasting target — the SPN will be added
                          when the seed is extended for Get-KerberosRisks.ps1)
      mlefevre          : DA + never authenticated (stale-privileged semantic)
      ldubois           : created today, never authenticated — demonstrates the
                          too-young filter of Get-InactiveUsers.ps1

    Why every seeded user has whenCreated = today AND appears never-authenticated:
      Three AD-owned attributes cannot be backdated via LDAP writes, regardless of
      caller privilege:
        - whenCreated        - schema flags OPERATIONAL + NO_USER_MODIFY. Absolute refusal.
        - lastLogonTimestamp - owned by the SAM ("Access to the attribute is not
                               permitted because the attribute is owned by the
                               Security Accounts Manager"). Populated only by real
                               authentications.
        - pwdLastSet         - accepts only 0 (force change at next logon) and -1
                               (mark as just changed). Any past FileTime value is
                               rejected with "The parameter is incorrect".
      Consequences for the lab:
        - InactiveDays and NeverLoggedIn are semantic markers (visible in the
          account Description). They do NOT drive AD attribute writes.
        - PasswordAge in the Get-PasswordNeverExpires.ps1 report is uniform (~seed
          run day) across seeded accounts. The lab demonstrates PNE detection, not
          age comparison across accounts.
        - lab-scenarios.md is calibrated for this reality: privileged service
          accounts never used since creation are themselves a finding at least as
          severe as "inactive for 400 days".

    Backdating that would work but is not attempted here:
      Manipulating the DC clock (Set-Date on the DC while stopped, or Azure VM
      snapshot / restore) can produce past PasswordLastSet values organically. That
      belongs to a separate lab-helper if ever needed — the seed stays LDAP-only.

    Idempotency:
      OUs:           queried by Name under parent; created only if absent.
      Users:         queried by SamAccountName; created if absent, updated if
                     Description / Enabled / PasswordNeverExpires /
                     ChangePasswordAtLogon differ.
      Groups:        queried by Name; created if absent.
      Memberships:   Get-ADGroupMember checked before Add-ADGroupMember.

    Requires the ActiveDirectory PowerShell module (RSAT-AD-PowerShell) and Domain
    Admin rights (to add members to protected groups; adminCount propagation depends
    on SDProp scheduling — see lab-setup.md for the forcing procedure).
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$DomainDN,

    [Parameter()]
    [string]$DefaultPassword = 'LabPass!2026Demo',

    [Parameter()]
    [switch]$Force
)

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "The ActiveDirectory module is not installed. Install RSAT (RSAT-AD-PowerShell) and re-run."
}
Import-Module ActiveDirectory -ErrorAction Stop

# --- Safety: refuse non-lab domains unless -Force ---
try {
    $domain = Get-ADDomain -ErrorAction Stop
}
catch {
    throw "Cannot reach an Active Directory domain. Run this script on a domain controller or a host with RSAT and a working domain context."
}

if (-not $DomainDN) { $DomainDN = $domain.DistinguishedName }
$domainName = $domain.DNSRoot

if ($domainName -ne 'lab.local' -and -not $Force) {
    throw "Refusing to seed: current domain '$domainName' is not 'lab.local'. Re-run with -Force only after verifying the target is an isolated lab environment."
}

Write-Host "Seeding lab domain: $domainName ($DomainDN)" -ForegroundColor Cyan

# Single upfront advisory (replaces the per-account backdate warnings from earlier versions)
Write-Warning @"
Backdating notice: lastLogonTimestamp and pwdLastSet cannot be aged via LDAP writes
(lastLogonTimestamp is SAM-owned, pwdLastSet accepts only 0 / -1). Accounts marked
InactiveDays=N or NeverLoggedIn=true in the seed plan will appear as never-authenticated
in Get-InactiveUsers.ps1 output. The semantic intent lives in each account's Description
and in the seed plan itself. See the .NOTES block of this script for the full explanation.
"@

# --- Summary state ---
$summary = [PSCustomObject]@{
    OUsCreated             = 0
    OUsExisting            = 0
    UsersCreated           = 0
    UsersUpdated           = 0
    UsersExistingUnchanged = 0
    GroupsCreated          = 0
    GroupsExisting         = 0
    MembershipsAdded       = 0
    MembershipsExisting    = 0
    Warnings               = New-Object System.Collections.Generic.List[string]
}

$marker = '[SEEDED-LAB]'

# --- Helpers ---

function New-LabOU {
    param([string]$Name, [string]$ParentDN)

    $existing = Get-ADOrganizationalUnit -Filter "Name -eq `"$Name`"" -SearchBase $ParentDN -SearchScope OneLevel -ErrorAction SilentlyContinue
    if ($existing) {
        $script:summary.OUsExisting++
        return $existing.DistinguishedName
    }
    try {
        $ou = New-ADOrganizationalUnit -Name $Name -Path $ParentDN -ProtectedFromAccidentalDeletion $false -PassThru -ErrorAction Stop
        $script:summary.OUsCreated++
        return $ou.DistinguishedName
    }
    catch {
        $script:summary.Warnings.Add("OU '$Name' create failed: $($_.Exception.Message)")
        throw
    }
}

function Add-LabGroupMember {
    param([string]$Group, [string]$MemberSam)

    try {
        $current = Get-ADGroupMember -Identity $Group -ErrorAction Stop
        if ($current | Where-Object { $_.SamAccountName -eq $MemberSam -or $_.Name -eq $MemberSam }) {
            $script:summary.MembershipsExisting++
            return
        }
        Add-ADGroupMember -Identity $Group -Members $MemberSam -ErrorAction Stop
        $script:summary.MembershipsAdded++
    }
    catch {
        $script:summary.Warnings.Add("Add '$MemberSam' to '$Group' failed: $($_.Exception.Message)")
    }
}

function New-LabUser {
    param(
        [Parameter(Mandatory)][string]$Sam,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$OU,
        [Parameter()][string]$Description = $marker,
        [Parameter()][bool]$PNE = $false,
        [Parameter()][bool]$ChangePasswordAtLogon = $false,
        [Parameter()][bool]$Disabled = $false,
        # Semantic-only markers: preserved so the seed plan carries pedagogical
        # intent (readable in the plan and echoed in the Description). NOT applied
        # to lastLogonTimestamp — that attribute is SAM-owned and refuses LDAP writes.
        [Parameter()][bool]$NeverLoggedIn = $false,
        [Parameter()][int]$InactiveDays = 0,
        [Parameter()][string[]]$AddToGroups = @()
    )

    $ouDN = "OU=$OU,$script:DomainDN"
    $existing = Get-ADUser -Filter "SamAccountName -eq `"$Sam`"" -Properties Description, PasswordNeverExpires, Enabled -ErrorAction SilentlyContinue

    if (-not $existing) {
        $securePwd = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force
        $parts = $Name -split ' ', 2
        $first = $parts[0]
        $last  = if ($parts.Count -gt 1) { $parts[1] } else { $parts[0] }

        try {
            New-ADUser `
                -Name              $Name `
                -SamAccountName    $Sam `
                -UserPrincipalName "$Sam@$script:domainName" `
                -GivenName         $first `
                -Surname           $last `
                -DisplayName       $Name `
                -Description       $Description `
                -Path              $ouDN `
                -AccountPassword   $securePwd `
                -Enabled           (-not $Disabled) `
                -PasswordNeverExpires:$PNE `
                -ChangePasswordAtLogon:$ChangePasswordAtLogon `
                -ErrorAction Stop
            $script:summary.UsersCreated++
        }
        catch {
            $script:summary.Warnings.Add("User '$Sam' create failed: $($_.Exception.Message)")
            return
        }
    }
    else {
        # Idempotent update: align only the attributes we care about
        $updateParams = @{}
        if ($existing.Description -ne $Description)         { $updateParams.Description           = $Description }
        if ($existing.Enabled     -eq $Disabled)            { $updateParams.Enabled               = (-not $Disabled) }
        if ($existing.PasswordNeverExpires -ne $PNE)        { $updateParams.PasswordNeverExpires  = $PNE }
        if ($ChangePasswordAtLogon) {
            # ChangePasswordAtLogon is not directly readable as a friendly property; always re-apply when requested
            $updateParams.ChangePasswordAtLogon = $true
        }

        if ($updateParams.Count -gt 0) {
            try {
                Set-ADUser -Identity $existing @updateParams -ErrorAction Stop
                $script:summary.UsersUpdated++
            }
            catch {
                $script:summary.Warnings.Add("User '$Sam' update failed: $($_.Exception.Message)")
            }
        }
        else {
            $script:summary.UsersExistingUnchanged++
        }
    }

    # Group memberships
    foreach ($g in $AddToGroups) { Add-LabGroupMember -Group $g -MemberSam $Sam }
}

function New-LabGroup {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$OU,
        [Parameter()][string]$Description = $marker,
        [Parameter()][string[]]$Members = @(),
        [Parameter()][string[]]$NestedIn = @()
    )

    $ouDN = "OU=$OU,$script:DomainDN"
    $existing = Get-ADGroup -Filter "Name -eq `"$Name`"" -Properties Description -ErrorAction SilentlyContinue

    if (-not $existing) {
        try {
            New-ADGroup -Name $Name -SamAccountName $Name -GroupCategory Security -GroupScope Global -Path $ouDN -Description $Description -ErrorAction Stop
            $script:summary.GroupsCreated++
        }
        catch {
            $script:summary.Warnings.Add("Group '$Name' create failed: $($_.Exception.Message)")
            return
        }
    }
    else {
        $script:summary.GroupsExisting++
        if ($existing.Description -ne $Description) {
            try { Set-ADGroup -Identity $existing -Description $Description -ErrorAction Stop } catch {}
        }
    }

    foreach ($m in $Members)  { Add-LabGroupMember -Group $Name   -MemberSam $m }
    foreach ($p in $NestedIn) { Add-LabGroupMember -Group $p      -MemberSam $Name }
}

# --- Seed plan ---

# OUs
$ouNames = 'IT', 'HR', 'Finance', 'Management', 'Service Accounts', 'Disabled Users'
foreach ($ou in $ouNames) { [void] (New-LabOU -Name $ou -ParentDN $DomainDN) }

# Users (31 total) — clustered to produce realistic cross-vector findings.
# NOTE: PasswordAgeDays was removed after the 26-Aug-2026 lab run — pwdLastSet only
# accepts 0 / -1 via LDAP. InactiveDays / NeverLoggedIn remain as semantic markers.
$users = @(
    # IT (8) — privileged + stale + legacy
    @{ Sam='jadams';          Name='James Adams';        OU='IT'; Description="$marker IT admin, active, Direct DA";                              AddToGroups=@('Domain Admins') }
    @{ Sam='mlefevre';        Name='Marc Lefevre';       OU='IT'; Description="$marker Stale DA - intent inactive 180d (appears never-authenticated in reports)";          AddToGroups=@('Domain Admins'); InactiveDays=180 }
    @{ Sam='sysadmin-legacy'; Name='Legacy Sysadmin';    OU='IT'; Description="$marker Triple finding: BackupOp + PNE + intent inactive 250d";           AddToGroups=@('Backup Operators'); PNE=$true; InactiveDays=250 }
    @{ Sam='ptaylor';         Name='Patricia Taylor';    OU='IT'; Description="$marker Must change password at next logon";                       ChangePasswordAtLogon=$true }
    @{ Sam='akovach';         Name='Anna Kovach';        OU='IT'; Description="$marker Normal IT user (baseline)" }
    @{ Sam='rmills';          Name='Robert Mills';       OU='IT'; Description="$marker PNE set (uniform PasswordAge across seeded PNE accounts)";                                PNE=$true }
    @{ Sam='cstein';          Name='Catherine Stein';    OU='IT'; Description="$marker Provisioning leftover - never logged in";                  NeverLoggedIn=$true }
    @{ Sam='ldubois';         Name='Lucas Dubois';       OU='IT'; Description="$marker Edge case: created today, never logged in (too-young filter demo)"; NeverLoggedIn=$true }

    # HR (6) — mostly normal + a stale PNE
    @{ Sam='mbianchi';        Name='Maria Bianchi';      OU='HR'; Description="$marker HR manager" }
    @{ Sam='ksimon';          Name='Karen Simon';        OU='HR'; Description="$marker HR analyst" }
    @{ Sam='alopez';          Name='Ana Lopez';          OU='HR'; Description="$marker PNE + intent inactive 120d";                                      PNE=$true; InactiveDays=120 }
    @{ Sam='jthomas';         Name='John Thomas';        OU='HR'; Description="$marker Never logged in (HR ghost)";                               NeverLoggedIn=$true }
    @{ Sam='ewright';         Name='Emily Wright';       OU='HR'; Description="$marker Normal HR user" }
    @{ Sam='dweber';          Name='Daniel Weber';       OU='HR'; Description="$marker Normal HR user" }

    # Finance (5)
    @{ Sam='gnakamura';       Name='Gen Nakamura';       OU='Finance'; Description="$marker Finance director" }
    @{ Sam='pkim';            Name='Paul Kim';           OU='Finance'; Description="$marker PNE set";                                              PNE=$true }
    @{ Sam='msanchez';        Name='Maria Sanchez';      OU='Finance'; Description="$marker Normal finance user" }
    @{ Sam='tbrown';          Name='Thomas Brown';       OU='Finance'; Description="$marker Normal finance user" }
    @{ Sam='hwhite';          Name='Henry White';        OU='Finance'; Description="$marker Normal finance user" }

    # Management (4) — excessive privilege + PNE on a key role
    @{ Sam='aceo';            Name='Alex CEO';           OU='Management'; Description="$marker CEO with excessive Account Operators privilege";  AddToGroups=@('Account Operators') }
    @{ Sam='bcoo';            Name='Brian COO';          OU='Management'; Description="$marker Normal exec" }
    @{ Sam='ccfo';            Name='Catherine CFO';      OU='Management'; Description="$marker CFO with PNE + intent inactive 100d";                    PNE=$true; InactiveDays=100 }
    @{ Sam='dvp';             Name='David VP';           OU='Management'; Description="$marker Normal VP" }

    # Service Accounts (5) — the high-value findings
    @{ Sam='svc-backup';      Name='svc-backup';         OU='Service Accounts'; Description="$marker Legacy service account: DA + PNE (Kerberoasting target; SPN pending for Get-KerberosRisks)"; AddToGroups=@('Domain Admins');      PNE=$true }
    @{ Sam='svc-sql';         Name='svc-sql';            OU='Service Accounts'; Description="$marker BackupOp + PNE";                                          AddToGroups=@('Backup Operators');   PNE=$true }
    @{ Sam='svc-print';       Name='svc-print';          OU='Service Accounts'; Description="$marker Service account never logged in (dead service?)";          NeverLoggedIn=$true }
    @{ Sam='svc-monitor';     Name='svc-monitor';        OU='Service Accounts'; Description="$marker PNE, no admin";                                            PNE=$true }
    @{ Sam='svc-legacy';      Name='svc-legacy';         OU='Service Accounts'; Description="$marker WORST CASE: DA + PNE + never authenticated since creation";                     AddToGroups=@('Domain Admins');      PNE=$true; InactiveDays=400 }

    # Disabled Users (3) — should NOT appear in default-mode reports
    @{ Sam='jsmith';          Name='Jane Smith';         OU='Disabled Users'; Description="$marker Disabled, intent inactive 300d";                       Disabled=$true; InactiveDays=300 }
    @{ Sam='rpark';           Name='Ryan Park';          OU='Disabled Users'; Description="$marker Disabled, normal";                             Disabled=$true }
    @{ Sam='wlegacy';         Name='Walter Legacy';      OU='Disabled Users'; Description="$marker Disabled former DA member";                    Disabled=$true; InactiveDays=500 }
)

foreach ($u in $users) {
    $params = @{}
    foreach ($k in $u.Keys) { $params[$k] = $u[$k] }
    New-LabUser @params
}

# Groups (5) — empty/orphan + nesting chains
$groups = @(
    @{ Name='GG-IT-Admins';               OU='IT';               Description="$marker IT admin group, nested in Domain Admins";       Members=@('jadams','mlefevre');   NestedIn=@('Domain Admins') }
    @{ Name='GG-Finance-ReadOnly';        OU='Finance';          Description="$marker Finance read-only group (normal baseline)";     Members=@('gnakamura','pkim','tbrown') }
    @{ Name='GG-Empty-Legacy';            OU='IT';               Description="$marker Empty orphan group (legacy)" }
    @{ Name='GG-Orphan-2018';             OU='IT';               Description="$marker Empty orphan group (created 2018, never cleaned up)" }
    @{ Name='GG-Backup-Operators-Team';   OU='Service Accounts'; Description="$marker Nested in Backup Operators";                    Members=@('svc-sql');             NestedIn=@('Backup Operators') }
)

foreach ($g in $groups) {
    $params = @{}
    foreach ($k in $g.Keys) { $params[$k] = $g[$k] }
    New-LabGroup @params
}

# --- Summary ---
Write-Host ""
Write-Host "=== SEED SUMMARY ===" -ForegroundColor Cyan
$summary | Select-Object * -ExcludeProperty Warnings | Format-List

if ($summary.Warnings.Count -gt 0) {
    Write-Host "Warnings ($($summary.Warnings.Count)):" -ForegroundColor Yellow
    foreach ($w in $summary.Warnings) { Write-Host "  - $w" -ForegroundColor Yellow }
}
else {
    Write-Host "No warnings." -ForegroundColor Green
}

Write-Host ""
Write-Host "Next step: force SDProp so adminCount propagates immediately to the new" -ForegroundColor Cyan
Write-Host "  members of protected groups (otherwise Get-PrivilegedUsers under-reports" -ForegroundColor Cyan
Write-Host "  until SDProp runs — every 60 min of PDC uptime, not wall-clock time)." -ForegroundColor Cyan
Write-Host "  See lab-setup.md for the one-liner and the rationale." -ForegroundColor Cyan

Write-Host ""
Write-Host "Validate with (from the repository root):" -ForegroundColor Cyan
Write-Host "  .\scripts\powershell\Get-InactiveUsers.ps1        -IncludeNewlyCreated"
Write-Host "  .\scripts\powershell\Get-PrivilegedUsers.ps1"
Write-Host "  .\scripts\powershell\Get-PasswordNeverExpires.ps1"
