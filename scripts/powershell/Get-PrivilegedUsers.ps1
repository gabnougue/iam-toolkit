<#
.SYNOPSIS
    Lists direct and nested members of sensitive Active Directory groups.

.DESCRIPTION
    Walks the membership of a configurable list of high-privilege AD groups (Domain Admins,
    Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators by
    default) and reports every principal that ultimately holds privilege through them.

    Each member is tagged as either:
      Direct  - the principal is an immediate member of the target group.
      Nested  - the principal inherits membership through one or more intermediate groups.

    The walk follows the `member` attribute of each group (rather than Get-ADGroupMember) so
    that Foreign Security Principals and members from trusted domains do not abort enumeration.

    Schema Admins and Enterprise Admins exist only in the forest root domain; queries against
    them from a child domain are reported as warnings and skipped, not fatal errors.

    When a principal is reachable through both a direct and a nested path to the same target
    group, the row is collapsed and tagged Direct (the higher-visibility path).

.PARAMETER Groups
    Names of the sensitive groups to audit. Defaults to:
      Domain Admins, Enterprise Admins, Schema Admins, Administrators,
      Account Operators, Backup Operators

.PARAMETER Server
    Specific domain controller to query. If omitted, the nearest available DC is used.

.PARAMETER OutputPath
    Path of the CSV file to write. Defaults to .\PrivilegedUsers_<yyyyMMdd_HHmmss>.csv in the
    current directory.

.EXAMPLE
    .\Get-PrivilegedUsers.ps1
    Audits the default six sensitive groups.

.EXAMPLE
    .\Get-PrivilegedUsers.ps1 -Groups 'Domain Admins','Enterprise Admins'
    Restricts the audit to two groups.

.EXAMPLE
    .\Get-PrivilegedUsers.ps1 -Server dc01.lab.local -OutputPath .\priv.csv
    Targets a specific DC and writes to an explicit path.

.NOTES
    Requires the ActiveDirectory PowerShell module (RSAT-AD-PowerShell) and read access to the
    directory.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$Groups = @(
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Administrators',
        'Account Operators',
        'Backup Operators'
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

function Resolve-GroupMembership {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TargetGroupName,
        [Parameter(Mandatory)][string]$CurrentGroupDN,
        [Parameter(Mandatory)][bool]$IsRoot,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$VisitedGroups
    )

    # Cycle guard: AD normally prevents group cycles, but defend against malformed state anyway
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
            $obj = Get-ADObject -Identity $memberDN -Properties objectClass, sAMAccountName, displayName @adCommonParams
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
            [PSCustomObject]@{
                SamAccountName = $obj.sAMAccountName
                DisplayName    = $obj.displayName
                GroupName      = $TargetGroupName
                MembershipType = if ($IsRoot) { 'Direct' } else { 'Nested' }
            }
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
    Resolve-GroupMembership `
        -TargetGroupName $groupName `
        -CurrentGroupDN  $group.DistinguishedName `
        -IsRoot          $true `
        -VisitedGroups   $visited
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
            SamAccountName = $row.SamAccountName
            DisplayName    = $row.DisplayName
            GroupName      = $row.GroupName
            MembershipType = $row.MembershipType
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
