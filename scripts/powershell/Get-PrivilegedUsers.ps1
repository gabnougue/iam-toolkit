<#
.SYNOPSIS
    Audits direct and nested members of sensitive Active Directory groups.

.DESCRIPTION
    Walks the membership of a configurable list of high-privilege AD groups (13 by default,
    covering forest, domain, and Built-in scopes — see -Groups). For every leaf principal
    (user, computer, gMSA, FSP) reachable through these groups, the script reports whether
    the membership is Direct or Nested, plus the metadata an auditor needs to triage:
    ObjectClass, Enabled state, AdminCount, and DistinguishedName.

    Membership is resolved by walking the `member` attribute of each group manually rather
    than via Get-ADGroupMember. This avoids the well-known cmdlet failure on Foreign
    Security Principals from trusted domains and on cross-domain memberships.

    Schema Admins and Enterprise Admins live only in the forest root domain; queries from
    a child domain are reported as warnings and skipped, not fatal errors.

    A visited-DN HashSet prevents infinite loops in case of malformed group nesting cycles.

    When a principal is reachable through both a Direct and a Nested path to the same
    target group, the row is collapsed and tagged Direct (the higher-visibility path).

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
        Holds SeBackupPrivilege on DCs — can read NTDS.dit and the SYSTEM hive, then
        extract the krbtgt hash offline and forge Golden Tickets. Full domain compromise.

      Server Operators
        Can stop/start services and modify service binaries on DCs — privesc to SYSTEM.

      Print Operators
        Can load printer drivers on DCs (SeLoadDriverPrivilege) — code execution path.

      DnsAdmins
        The DNS service runs as SYSTEM on DCs. Members can configure a server-level plugin
        (ServerLevelPluginDll) loaded by the service — code execution as SYSTEM on the DC.

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

    Default nesting in AD:
      Domain Admins and Enterprise Admins are themselves Direct members of the Built-in
      Administrators group at provisioning time. This is normal AD architecture, not a
      finding — expect rows showing Domain Admins members as Nested in Administrators.

    Known LDAP limitation:
      The `member` attribute is range-limited by AD to 5000 values per fetch. Privileged
      groups with more than 5000 direct members would be silently truncated. In practice
      this never happens — a privileged group with thousands of direct members is itself
      a critical finding (and almost always indicates a control misconfiguration) — but
      the limitation is noted here for transparency.

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

function ConvertTo-PrivilegedRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$AdObject,
        [Parameter(Mandatory)][string]$TargetGroupName,
        [Parameter(Mandatory)][bool]$IsDirect
    )

    $type = if ($IsDirect) { 'Direct' } else { 'Nested' }

    if ($AdObject.objectClass -eq 'foreignSecurityPrincipal') {
        # FSP CN is the SID of the foreign principal — use it as the identifier
        # since sAMAccountName is not populated for cross-forest principals
        return [PSCustomObject]@{
            SamAccountName    = $AdObject.Name
            DisplayName       = '(foreign security principal)'
            GroupName         = $TargetGroupName
            MembershipType    = $type
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
        ObjectClass       = $AdObject.objectClass
        Enabled           = $enabled
        AdminCount        = $AdObject.adminCount
        DistinguishedName = $AdObject.DistinguishedName
    }
}

function Resolve-GroupMembership {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TargetGroupName,
        [Parameter(Mandatory)][string]$CurrentGroupDN,
        [Parameter(Mandatory)][bool]$IsRoot,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$VisitedGroups
    )

    # Cycle guard: AD prevents cycles in well-formed environments, but defend regardless
    if (-not $VisitedGroups.Add($CurrentGroupDN)) { return }

    try {
        $group = Get-ADGroup -Identity $CurrentGroupDN -Properties member @adCommonParams
    }
    catch {
        Write-Warning "Failed to enumerate group '$CurrentGroupDN': $($_.Exception.Message)"
        return
    }

    foreach ($memberDN in $group.member) {
        try {
            $obj = Get-ADObject -Identity $memberDN `
                -Properties objectClass, sAMAccountName, displayName, userAccountControl, adminCount `
                @adCommonParams
        }
        catch {
            Write-Warning "Failed to resolve member '$memberDN': $($_.Exception.Message)"
            continue
        }

        if ($obj.objectClass -eq 'group') {
            Resolve-GroupMembership `
                -TargetGroupName $TargetGroupName `
                -CurrentGroupDN  $memberDN `
                -IsRoot          $false `
                -VisitedGroups   $VisitedGroups
        }
        else {
            ConvertTo-PrivilegedRow -AdObject $obj -TargetGroupName $TargetGroupName -IsDirect $IsRoot
        }
    }
}

$rawResults = foreach ($groupName in $Groups) {
    try {
        $group = Get-ADGroup -Identity $groupName @adCommonParams
    }
    catch {
        Write-Warning "Group '$groupName' not found or inaccessible (skipped): $($_.Exception.Message)"
        continue
    }

    $visited = [System.Collections.Generic.HashSet[string]]::new()
    $groupRows = @(Resolve-GroupMembership `
        -TargetGroupName $groupName `
        -CurrentGroupDN  $group.DistinguishedName `
        -IsRoot          $true `
        -VisitedGroups   $visited)

    if ($groupRows.Count -eq 0) {
        Write-Verbose "Group '$groupName' has no resolvable members (empty, or all sub-groups empty)."
    }
    $groupRows
}

# Collapse duplicate (SamAccountName, GroupName) rows; prefer Direct when both paths exist
$results = $rawResults |
    Group-Object SamAccountName, GroupName |
    ForEach-Object {
        $row = if ($_.Group.MembershipType -contains 'Direct') {
            $_.Group | Where-Object MembershipType -eq 'Direct' | Select-Object -First 1
        }
        else {
            $_.Group | Select-Object -First 1
        }
        [PSCustomObject]@{
            SamAccountName    = $row.SamAccountName
            DisplayName       = $row.DisplayName
            GroupName         = $row.GroupName
            MembershipType    = $row.MembershipType
            ObjectClass       = $row.ObjectClass
            Enabled           = $row.Enabled
            AdminCount        = $row.AdminCount
            DistinguishedName = $row.DistinguishedName
        }
    } |
    Sort-Object GroupName, MembershipType, SamAccountName

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
