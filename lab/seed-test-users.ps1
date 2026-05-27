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
    Misconfiguration coverage (exceeds CLAUDE.md spec minimums):

      Inactive (lastLogonTimestamp backdated)  : 7  (spec: 5+)
      Never logged in (lastLogonTimestamp null): 4  (spec: 2+)
      Privileged (direct DA membership)        : 4  (spec: 3+)
      Privileged (other sensitive groups)      : 3
      PasswordNeverExpires set                 : 9  (spec: 5+)
      Service account with DA                  : 2  (spec: 1+)
      Empty/orphan groups                      : 2  (spec: 2+)
      Nested group memberships (privilege)     : 2 chains
      Must-change-at-next-logon                : 1  (edge-case finding)

    Cross-vector findings (the gold for lab demos):
      svc-legacy        : DA + PNE + inactive 400d   - critical, surfaces in all 3 scripts
      sysadmin-legacy   : BackupOp + PNE + inactive 250d  - triple-hit
      svc-backup        : DA + PNE                    - Kerberoasting prime target
      mlefevre          : DA + inactive 180d          - stale privileged
      ldubois           : created today, never logged - demonstrates too-young filter

    Why all seeded users have whenCreated = today:
      The `whenCreated` AD attribute carries the schema flags OPERATIONAL + NO_USER_MODIFY,
      so it cannot be backdated via LDAP. Run `Get-InactiveUsers.ps1 -IncludeNewlyCreated`
      to bypass the too-young filter for lab validation. Without that switch, ldubois
      (never logged in, created today) demonstrates the filter behaviour: all seeded
      users are correctly excluded as too-young.

    Backdating that DOES work:
      lastLogonTimestamp - writable; we set it to past FileTime values.
      pwdLastSet         - writable; we set it for the PasswordAge column in the
                           Get-PasswordNeverExpires.ps1 report.

    Idempotency:
      OUs:           queried by Name under parent; created only if absent.
      Users:         queried by SamAccountName; created if absent, updated if Description /
                     Enabled / PasswordNeverExpires / ChangePasswordAtLogon differ.
      Groups:        queried by Name; created if absent.
      Memberships:   Get-ADGroupMember to check before Add-ADGroupMember.

    Requires the ActiveDirectory PowerShell module (RSAT-AD-PowerShell) and Domain Admin
    rights (to write lastLogonTimestamp and to add members to protected groups).
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
    LastLogonBackdated     = 0
    PwdLastSetBackdated    = 0
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

function Set-LabBackdate {
    param(
        [Parameter(Mandatory)][string]$Sam,
        [Parameter()][int]$InactiveDays,
        [Parameter()][bool]$NeverLoggedIn,
        [Parameter()][int]$PasswordAgeDays
    )

    $user = Get-ADUser -Identity $Sam -Properties lastLogonTimestamp, pwdLastSet -ErrorAction Stop

    if ($NeverLoggedIn) {
        if ($user.lastLogonTimestamp) {
            try {
                Set-ADObject -Identity $user.DistinguishedName -Clear lastLogonTimestamp -ErrorAction Stop
            }
            catch {
                $script:summary.Warnings.Add("Clear lastLogonTimestamp on '$Sam' failed: $($_.Exception.Message)")
            }
        }
    }
    elseif ($InactiveDays -gt 0) {
        $targetTs = (Get-Date).AddDays(-$InactiveDays).ToFileTime()
        if ($user.lastLogonTimestamp -ne $targetTs) {
            try {
                Set-ADObject -Identity $user.DistinguishedName -Replace @{lastLogonTimestamp = $targetTs} -ErrorAction Stop
                $script:summary.LastLogonBackdated++
            }
            catch {
                $script:summary.Warnings.Add("Backdate lastLogonTimestamp on '$Sam' failed: $($_.Exception.Message)")
            }
        }
    }

    if ($PasswordAgeDays -gt 0) {
        $targetPwd = (Get-Date).AddDays(-$PasswordAgeDays).ToFileTime()
        # pwdLastSet may differ slightly from creation time; only rewrite if more than 1 day off
        $current = if ($user.pwdLastSet) { [DateTime]::FromFileTime($user.pwdLastSet) } else { $null }
        $target  = [DateTime]::FromFileTime($targetPwd)
        if ((-not $current) -or ([Math]::Abs(($current - $target).TotalDays) -gt 1)) {
            try {
                Set-ADObject -Identity $user.DistinguishedName -Replace @{pwdLastSet = $targetPwd} -ErrorAction Stop
                $script:summary.PwdLastSetBackdated++
            }
            catch {
                $script:summary.Warnings.Add("Backdate pwdLastSet on '$Sam' failed: $($_.Exception.Message)")
            }
        }
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
        [Parameter()][bool]$NeverLoggedIn = $false,
        [Parameter()][int]$InactiveDays = 0,
        [Parameter()][int]$PasswordAgeDays = 0,
        [Parameter()][string[]]$AddToGroups = @()
    )

    $ouDN = "OU=$OU,$script:DomainDN"
    $existing = Get-ADUser -Filter "SamAccountName -eq `"$Sam`"" -Properties Description, PasswordNeverExpires, Enabled -ErrorAction SilentlyContinue

    if (-not $existing) {
        # Create
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

    # Backdate logon / password attributes
    Set-LabBackdate -Sam $Sam -InactiveDays $InactiveDays -NeverLoggedIn $NeverLoggedIn -PasswordAgeDays $PasswordAgeDays

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

# Users (31 total) — clustered to produce realistic cross-vector findings
$users = @(
    # IT (8) — privileged + stale + legacy
    @{ Sam='jadams';          Name='James Adams';        OU='IT'; Description="$marker IT admin, active, Direct DA";                              AddToGroups=@('Domain Admins') }
    @{ Sam='mlefevre';        Name='Marc Lefevre';       OU='IT'; Description="$marker Stale DA - inactive 180d (cross-vector finding)";          AddToGroups=@('Domain Admins'); InactiveDays=180 }
    @{ Sam='sysadmin-legacy'; Name='Legacy Sysadmin';    OU='IT'; Description="$marker Triple finding: BackupOp + PNE + inactive 250d";           AddToGroups=@('Backup Operators'); PNE=$true; InactiveDays=250; PasswordAgeDays=900 }
    @{ Sam='ptaylor';         Name='Patricia Taylor';    OU='IT'; Description="$marker Must change password at next logon";                       ChangePasswordAtLogon=$true }
    @{ Sam='akovach';         Name='Anna Kovach';        OU='IT'; Description="$marker Normal IT user (baseline)" }
    @{ Sam='rmills';          Name='Robert Mills';       OU='IT'; Description="$marker PNE set, password ~2y old";                                PNE=$true; PasswordAgeDays=730 }
    @{ Sam='cstein';          Name='Catherine Stein';    OU='IT'; Description="$marker Provisioning leftover - never logged in";                  NeverLoggedIn=$true }
    @{ Sam='ldubois';         Name='Lucas Dubois';       OU='IT'; Description="$marker Edge case: created today, never logged in (too-young filter)"; NeverLoggedIn=$true }

    # HR (6) — mostly normal + a stale PNE
    @{ Sam='mbianchi';        Name='Maria Bianchi';      OU='HR'; Description="$marker HR manager" }
    @{ Sam='ksimon';          Name='Karen Simon';        OU='HR'; Description="$marker HR analyst" }
    @{ Sam='alopez';          Name='Ana Lopez';          OU='HR'; Description="$marker PNE + inactive 120d";                                      PNE=$true; InactiveDays=120; PasswordAgeDays=540 }
    @{ Sam='jthomas';         Name='John Thomas';        OU='HR'; Description="$marker Never logged in (HR ghost)";                               NeverLoggedIn=$true }
    @{ Sam='ewright';         Name='Emily Wright';       OU='HR'; Description="$marker Normal HR user" }
    @{ Sam='dweber';          Name='Daniel Weber';       OU='HR'; Description="$marker Normal HR user" }

    # Finance (5)
    @{ Sam='gnakamura';       Name='Gen Nakamura';       OU='Finance'; Description="$marker Finance director" }
    @{ Sam='pkim';            Name='Paul Kim';           OU='Finance'; Description="$marker PNE set";                                              PNE=$true; PasswordAgeDays=400 }
    @{ Sam='msanchez';        Name='Maria Sanchez';      OU='Finance'; Description="$marker Normal finance user" }
    @{ Sam='tbrown';          Name='Thomas Brown';       OU='Finance'; Description="$marker Normal finance user" }
    @{ Sam='hwhite';          Name='Henry White';        OU='Finance'; Description="$marker Normal finance user" }

    # Management (4) — excessive privilege + PNE on a key role
    @{ Sam='aceo';            Name='Alex CEO';           OU='Management'; Description="$marker CEO with excessive Account Operators privilege";  AddToGroups=@('Account Operators') }
    @{ Sam='bcoo';            Name='Brian COO';          OU='Management'; Description="$marker Normal exec" }
    @{ Sam='ccfo';            Name='Catherine CFO';      OU='Management'; Description="$marker CFO with PNE + inactive 100d";                    PNE=$true; InactiveDays=100; PasswordAgeDays=600 }
    @{ Sam='dvp';             Name='David VP';           OU='Management'; Description="$marker Normal VP" }

    # Service Accounts (5) — the high-value findings
    @{ Sam='svc-backup';      Name='svc-backup';         OU='Service Accounts'; Description="$marker Legacy service account: DA + PNE (Kerberoasting target)"; AddToGroups=@('Domain Admins');      PNE=$true; PasswordAgeDays=1100 }
    @{ Sam='svc-sql';         Name='svc-sql';            OU='Service Accounts'; Description="$marker BackupOp + PNE";                                          AddToGroups=@('Backup Operators');   PNE=$true; PasswordAgeDays=800 }
    @{ Sam='svc-print';       Name='svc-print';          OU='Service Accounts'; Description="$marker Service account never logged in (dead service?)";          NeverLoggedIn=$true }
    @{ Sam='svc-monitor';     Name='svc-monitor';        OU='Service Accounts'; Description="$marker PNE, no admin";                                            PNE=$true; PasswordAgeDays=300 }
    @{ Sam='svc-legacy';      Name='svc-legacy';         OU='Service Accounts'; Description="$marker WORST CASE: DA + PNE + inactive 400d";                     AddToGroups=@('Domain Admins');      PNE=$true; InactiveDays=400; PasswordAgeDays=1400 }

    # Disabled Users (3) — should NOT appear in default-mode reports
    @{ Sam='jsmith';          Name='Jane Smith';         OU='Disabled Users'; Description="$marker Disabled, was inactive";                       Disabled=$true; InactiveDays=300 }
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
Write-Host "Validate with:" -ForegroundColor Cyan
Write-Host "  ..\scripts\powershell\Get-InactiveUsers.ps1        -IncludeNewlyCreated"
Write-Host "  ..\scripts\powershell\Get-PrivilegedUsers.ps1"
Write-Host "  ..\scripts\powershell\Get-PasswordNeverExpires.ps1"
