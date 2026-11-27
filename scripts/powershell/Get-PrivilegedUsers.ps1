<#
.SYNOPSIS
    Audits direct and nested members of sensitive Active Directory groups.

.DESCRIPTION
    Walks the membership of a configurable list of high-privilege AD groups (13 by default,
    covering forest, domain, and Built-in scopes - see -Groups). For every leaf principal
    (user, computer, gMSA, FSP) reachable through these groups, the script reports whether
    the membership is Direct or Nested, plus the metadata an auditor needs to triage:
    ObjectClass, Enabled state, AdminCount, and DistinguishedName.

    Membership is resolved by walking the `member` attribute of each group manually rather
    than via Get-ADGroupMember. This avoids the well-known cmdlet failure on Foreign
    Security Principals from trusted domains and on cross-domain memberships.

    Schema Admins and Enterprise Admins live only in the forest root domain; queries from
    a child domain are reported as warnings and skipped, not fatal errors.

    Every path from the audited group down to the principal is enumerated. The report
    keeps one row per (principal, audited group); MembershipType is Direct when at least
    one path is direct, Nested otherwise. All the paths are listed in MembershipPaths
    and counted in PathCount - see .NOTES before remediating.

    Nesting cycles are guarded per path: a group already on the current path is not
    re-entered, while a group reached through a different path is walked again (that
    is a second path, not a cycle).

.PARAMETER Groups
    Names of the sensitive groups to audit. Defaults to 13 groups across three scopes:

      Forest scope (root domain only):
        Enterprise Admins, Schema Admins

      Domain scope:
        Domain Admins, DnsAdmins, Cert Publishers, Group Policy Creator Owners,
        Key Admins, Enterprise Key Admins

      Built-in scope (CN=Builtin):
        Administrators, Account Operators, Backup Operators,
        Server Operators, Print Operators

.PARAMETER Server
    Specific domain controller to query. If omitted, the nearest available DC is used.

.PARAMETER OutputPath
    Path of the CSV file to write. Defaults to .\PrivilegedUsers_<yyyyMMdd_HHmmss>.csv in
    the current directory.

.EXAMPLE
    .\Get-PrivilegedUsers.ps1
    Audits the default 13 sensitive groups.

.EXAMPLE
    .\Get-PrivilegedUsers.ps1 -Groups 'Domain Admins','Enterprise Admins'
    Restricts the audit to two groups.

.EXAMPLE
    .\Get-PrivilegedUsers.ps1 -Server dc01.lab.local -OutputPath .\priv.csv
    Targets a specific DC and writes to an explicit path.

.NOTES
    Why these groups matter (threat model):

      Domain / Enterprise / Schema Admins
        Full administrative control over the domain or forest.

      Administrators (Builtin)
        Most powerful built-in group; nests Domain Admins and Enterprise Admins by default.
        Controls the AdminSDHolder object whose ACL is propagated by SDProp every hour to
        every member of the protected groups.

      Account Operators
        Can create, modify, and delete user/group/computer objects that are NOT in the
        AdminSDHolder protected set. Sufficient to pivot to Domain Admin in many setups.

      Backup Operators
        Holds SeBackupPrivilege on DCs - can read NTDS.dit and the SYSTEM hive, then
        extract the krbtgt hash offline and forge Golden Tickets. Full domain compromise.

      Server Operators
        Can stop/start services and modify service binaries on DCs - privesc to SYSTEM.

      Print Operators
        Can load printer drivers on DCs (SeLoadDriverPrivilege) - code execution path.

      DnsAdmins
        The DNS service runs as SYSTEM on DCs. Members can configure a server-level plugin
        (ServerLevelPluginDll) loaded by the service - code execution as SYSTEM on the DC.

      Group Policy Creator Owners
        Can create GPOs. If a created GPO is later linked to a sensitive OU, the creator
        retains write access to the GPO and can deploy code to the targets.

      Key Admins / Enterprise Key Admins
        Can write the msDS-KeyCredentialLink attribute on user/computer objects, enabling
        the Shadow Credentials attack: authentication as the target principal via PKINIT.

      Cert Publishers
        Can publish certificates to NTDS. Combined with ADCS misconfigurations (ESC1-ESC8)
        this opens authentication-impersonation paths.

    Replication and precision:
      lastLogonTimestamp (referenced indirectly via member objects) replicates with up to
      14-day delay. The membership data itself replicates promptly within a domain.

    MembershipPaths and PathCount - read this before remediating:
      A principal can hold a privileged membership through several paths at once:
      directly, and through one or more nested groups. MembershipType alone shows
      only "Direct" in that case, and the nested path disappears from the report.
      MembershipPaths lists every path, separated by "; ":
        Direct                     the principal is a direct member of the group
        via A > B                  A is a direct member of the audited group, B a
                                   member of A, ... and the principal is a direct
                                   member of the last group named
      Example: "Direct; via GG-IT-Admins" on jadams / Domain Admins.
      PathCount is the total number of paths. Remediation must cut ALL of them:
      removing the direct membership while the account stays in GG-IT-Admins leaves
      the privilege in place, and the next audit reports the same row as Nested.
      Group nesting can make the path count explode. At most 10 paths are written
      out; the rest is summarised as "... (+N)", and PathCount keeps the full count.
      Past 10000 group visits for one audited group, enumeration stops with a
      warning and PathCount is a lower bound for that group's rows.

    Default nesting in AD:
      Domain Admins and Enterprise Admins are themselves Direct members of the Built-in
      Administrators group at provisioning time. This is normal AD architecture, not a
      finding - expect rows showing Domain Admins members as Nested in Administrators.

    Known limitation - primary group membership is not walked:
      The walk reads the `member` attribute. AD does not list in `member` the
      principals whose PRIMARY group (primaryGroupID) is the group itself: that
      membership is implicit, derived from primaryGroupID = RID of the group. An
      account whose primary group were set to Domain Admins (RID 512) would hold
      the privilege and appear on no path, and therefore in no row of this report.
      Rare - the default primary group is Domain Users (513) - but a known way to
      hide a privileged membership from tools that read `member` only. Possible
      future improvement: also list the accounts whose primaryGroupID equals the
      RID of each audited group. Not implemented.

    Known LDAP limitation:
      The `member` attribute is range-limited by AD to 5000 values per fetch. Privileged
      groups with more than 5000 direct members would be silently truncated. In practice
      this never happens - a privileged group with thousands of direct members is itself
      a critical finding (and almost always indicates a control misconfiguration) - but
      the limitation is noted here for transparency.

    adminCount and SDProp - read this before trusting the AdminCount column:
      adminCount is not set at the moment a principal is added to a protected group.
      It is set by the SDProp (Security Descriptor Propagator) task, which runs on
      the PDC emulator every 60 minutes of *PDC uptime* - not calendar time. On a
      lab cloud VM that is deallocated most of the day, or on a DC that was just
      promoted, SDProp may never have run yet: the new DA member exists in the
      Domain Admins `member` list but adminCount is still empty, and this script's
      AdminCount column reads $null for that principal.

      Same phenomenon in production:
        - Right after a remediation that added a user to a protected group.
        - Right after a fresh compromise where the attacker added themselves.
        - On a domain whose PDC emulator has recently rebooted.
      In all of these cases an audit based on adminCount will UNDER-REPORT. The
      membership walk in this script is authoritative regardless of adminCount -
      always cross-check the GroupName column, not just AdminCount.

      Forcing SDProp (Domain Admin only):
        $root = [ADSI]"LDAP://RootDSE"
        $root.Put("runProtectAdminGroupsTask", 1)
        $root.SetInfo()
      After the task completes (seconds to minutes), adminCount is set on every
      current member of the protected groups.

    Validation status - all-paths walk written without a DC (November 2026):
      The last lab run (lab.local, 27-Nov-2026) used the previous walk (run-wide
      visited set, rows collapsed after the walk). The rewrite - path-scoped cycle
      guard, per-run caches, aggregation per leaf DN - has never run.
      VERIFY-ON-FIRST-RUN - non-regression, before looking at the new columns: the
      new output must contain exactly the same 16 rows as
      outputs/sample-results/privileged-users.csv of 27-Nov-2026, compared on
      SamAccountName, GroupName, MembershipType and AdminCount:
        $key = { '{0}|{1}|{2}|{3}' -f $_.SamAccountName, $_.GroupName, $_.MembershipType, $_.AdminCount }
        $old = Import-Csv .\outputs\sample-results\privileged-users.csv | ForEach-Object $key
        $new = Import-Csv .\outputs\privileged.csv                         | ForEach-Object $key
        Compare-Object $old $new     # must return nothing; both counts must be 16
      Then check MembershipPaths / PathCount against lab/lab-scenarios.md
      (scenarios 9 and 11, validation check 3).

    Requires the ActiveDirectory PowerShell module (RSAT-AD-PowerShell) and read access to
    the directory.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$Groups = @(
        # Forest scope (root domain only)
        'Enterprise Admins'
        'Schema Admins'

        # Domain scope
        'Domain Admins'
        'DnsAdmins'                       # DLL-injection privesc via DNS service running as SYSTEM on DCs
        'Cert Publishers'                 # ADCS abuse vectors (ESC1-ESC8)
        'Group Policy Creator Owners'     # GPO-based privesc when a created GPO is later linked sensitively
        'Key Admins'                      # Shadow Credentials attack via msDS-KeyCredentialLink
        'Enterprise Key Admins'           # Forest-wide variant of Key Admins

        # Built-in (CN=Builtin), domain-local
        'Administrators'                  # Most powerful builtin; nests Domain Admins + Enterprise Admins
        'Account Operators'               # Can manage non-AdminSDHolder-protected accounts
        'Backup Operators'                # SeBackupPrivilege on DCs -> NTDS.dit extraction -> Golden Ticket
        'Server Operators'                # Service / system manipulation on DCs
        'Print Operators'                 # SeLoadDriverPrivilege on DCs
    ),

    [Parameter()]
    [string]$Server,

    [Parameter()]
    [string]$OutputPath = ".\PrivilegedUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "The ActiveDirectory module is not installed. Install RSAT (RSAT-AD-PowerShell) and re-run."
}

Import-Module ActiveDirectory -ErrorAction Stop

$adCommonParams = @{ ErrorAction = 'Stop' }
if ($PSBoundParameters.ContainsKey('Server')) { $adCommonParams.Server = $Server }

# UserAccountControl bit 0x2 = ACCOUNTDISABLE
$ACCOUNTDISABLE = 0x2

# MembershipPaths: number of paths written out per (principal, group) row; the
# rest is summarised as "... (+N)". PathCount always carries the full count.
$MAX_LISTED_PATHS = 10

# Path enumeration budget per audited group, counted in group visits. All-paths
# enumeration is exponential on pathological nesting (many groups nesting each
# other in layers); past this budget the walk stops and warns, and PathCount
# becomes a lower bound for that group.
$MAX_GROUP_VISITS = 10000

# Per-run caches keyed by DN. A sub-group reached by several paths, or nested under
# several audited groups (Domain Admins under Administrators), is fetched once.
$script:groupMemberCache = @{}   # group DN  -> member DNs (empty if the fetch failed)
$script:objectCache      = @{}   # member DN -> AD object ($null if resolution failed)

function Get-CachedGroupMember {
    param([Parameter(Mandatory)][string]$GroupDN)

    if (-not $script:groupMemberCache.ContainsKey($GroupDN)) {
        try {
            $g = Get-ADGroup -Identity $GroupDN -Properties member @adCommonParams
            $script:groupMemberCache[$GroupDN] = @($g.member)
        }
        catch {
            Write-Warning "Failed to enumerate group '$GroupDN': $($_.Exception.Message)"
            $script:groupMemberCache[$GroupDN] = @()
        }
    }
    $script:groupMemberCache[$GroupDN]
}

function Get-CachedADObject {
    param([Parameter(Mandatory)][string]$DN)

    if (-not $script:objectCache.ContainsKey($DN)) {
        try {
            $script:objectCache[$DN] = Get-ADObject -Identity $DN `
                -Properties objectClass, sAMAccountName, displayName, userAccountControl, adminCount `
                @adCommonParams
        }
        catch {
            Write-Warning "Failed to resolve member '$DN': $($_.Exception.Message)"
            $script:objectCache[$DN] = $null
        }
    }
    $script:objectCache[$DN]
}

function ConvertTo-PrivilegedRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$AdObject,
        [Parameter(Mandatory)][string]$TargetGroupName,
        [Parameter(Mandatory)][bool]$IsDirect,
        [Parameter(Mandatory)][string]$MembershipPaths,
        [Parameter(Mandatory)][int]$PathCount
    )

    $type = if ($IsDirect) { 'Direct' } else { 'Nested' }

    if ($AdObject.objectClass -eq 'foreignSecurityPrincipal') {
        # FSP CN is the SID of the foreign principal - use it as the identifier
        # since sAMAccountName is not populated for cross-forest principals
        return [PSCustomObject]@{
            SamAccountName    = $AdObject.Name
            DisplayName       = '(foreign security principal)'
            GroupName         = $TargetGroupName
            MembershipType    = $type
            MembershipPaths   = $MembershipPaths
            PathCount         = $PathCount
            ObjectClass       = 'foreignSecurityPrincipal'
            Enabled           = $null
            AdminCount        = $null
            DistinguishedName = $AdObject.DistinguishedName
        }
    }

    $enabled = if ($null -eq $AdObject.userAccountControl) { $null }
               else { -not [bool]($AdObject.userAccountControl -band $ACCOUNTDISABLE) }

    [PSCustomObject]@{
        SamAccountName    = $AdObject.sAMAccountName
        DisplayName       = $AdObject.displayName
        GroupName         = $TargetGroupName
        MembershipType    = $type
        MembershipPaths   = $MembershipPaths
        PathCount         = $PathCount
        ObjectClass       = $AdObject.objectClass
        Enabled           = $enabled
        AdminCount        = $AdObject.adminCount
        DistinguishedName = $AdObject.DistinguishedName
    }
}

function Resolve-GroupMembership {
    # Enumerates every path from the audited group down to each leaf principal and
    # records it in $State.Leaves (leaf DN -> object + list of path strings).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CurrentGroupDN,
        # Names of the groups crossed so far, from the audited group's direct member
        # down to the current group. Empty for the audited group itself.
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$PathNames,
        # Groups on the CURRENT path only. The first call passes an empty HashSet;
        # Mandatory validation on typed collections rejects that unless
        # AllowEmptyCollection is set.
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$Ancestors,
        [Parameter(Mandatory)]$State
    )

    if ($State.Visits -ge $MAX_GROUP_VISITS) {
        $State.Truncated = $true
        return
    }
    $State.Visits++

    # Cycle guard, path-scoped: a group already on the current path closes a cycle
    # and is not re-entered. A group reached again through a DIFFERENT path is a
    # second, legitimate path and is walked again - a run-wide visited set would
    # drop exactly the paths this column exists to show.
    if (-not $Ancestors.Add($CurrentGroupDN)) { return }

    try {
        foreach ($memberDN in (Get-CachedGroupMember -GroupDN $CurrentGroupDN)) {
            $obj = Get-CachedADObject -DN $memberDN
            if ($null -eq $obj) { continue }

            if ($obj.objectClass -eq 'group') {
                Resolve-GroupMembership `
                    -CurrentGroupDN $memberDN `
                    -PathNames      ($PathNames + [string]$obj.Name) `
                    -Ancestors      $Ancestors `
                    -State          $State
            }
            else {
                $path = if ($PathNames.Count -eq 0) { 'Direct' }
                        else { 'via ' + ($PathNames -join ' > ') }
                $key = [string]$obj.DistinguishedName
                if (-not $State.Leaves.ContainsKey($key)) {
                    $State.Leaves[$key] = @{
                        Object = $obj
                        Paths  = [System.Collections.Generic.List[string]]::new()
                    }
                }
                $State.Leaves[$key].Paths.Add($path)
            }
        }
    }
    finally {
        [void]$Ancestors.Remove($CurrentGroupDN)
    }
}

# Path order inside MembershipPaths: Direct first, then shortest nesting first,
# then alphabetical - deterministic, and the path to cut first reads first.
$pathSortKeys = @(
    @{ Expression = { if ($_ -eq 'Direct') { 0 } else { 1 } } }
    @{ Expression = { @($_ -split ' > ').Count } }
    @{ Expression = { $_ } }
)

$results = foreach ($groupName in $Groups) {
    try {
        $group = Get-ADGroup -Identity $groupName @adCommonParams
    }
    catch {
        Write-Warning "Group '$groupName' not found or inaccessible (skipped): $($_.Exception.Message)"
        continue
    }

    $state = @{
        Leaves    = @{}
        Visits    = 0
        Truncated = $false
    }

    # VERIFY-ON-FIRST-RUN: all-paths walk never run against a DC. On lab.local,
    # confirm the row count stays 16 and MembershipPaths / PathCount match
    # lab/lab-scenarios.md (scenarios 9 and 11).
    Resolve-GroupMembership `
        -CurrentGroupDN $group.DistinguishedName `
        -PathNames      @() `
        -Ancestors      ([System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)) `
        -State          $state

    if ($state.Truncated) {
        Write-Warning ("Path enumeration for '{0}' stopped after {1} group visits (pathological nesting). PathCount is a lower bound for this group's rows." -f $groupName, $MAX_GROUP_VISITS)
    }

    if ($state.Leaves.Count -eq 0) {
        Write-Verbose "Group '$groupName' has no resolvable members (empty, or all sub-groups empty)."
        continue
    }

    # One row per (principal, audited group): the row count is unchanged by the
    # path enumeration, only the two path columns are added.
    foreach ($leaf in $state.Leaves.Values) {
        # VERIFY-ON-FIRST-RUN: Sort-Object with scriptblock keys on PowerShell 5.1 -
        # check the order of the paths on jadams / Administrators.
        $paths  = @($leaf.Paths | Sort-Object -Property $pathSortKeys)
        $listed = @($paths | Select-Object -First $MAX_LISTED_PATHS)
        $text   = $listed -join '; '
        if ($paths.Count -gt $MAX_LISTED_PATHS) {
            $text += '; ... (+{0})' -f ($paths.Count - $MAX_LISTED_PATHS)
        }

        ConvertTo-PrivilegedRow `
            -AdObject        $leaf.Object `
            -TargetGroupName $groupName `
            -IsDirect        ($paths -contains 'Direct') `
            -MembershipPaths $text `
            -PathCount       $paths.Count
    }
}

$results = @($results | Sort-Object GroupName, MembershipType, SamAccountName)

if ($results) {
    try {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    }
    catch {
        throw "Failed to write CSV to '$OutputPath': $($_.Exception.Message)"
    }
    Write-Host "Found $(@($results).Count) privileged member entr(y/ies) across $(@($Groups).Count) group(s). Report written to: $OutputPath"
}
else {
    Write-Host "No privileged members found in the specified groups."
}

$results
