<#
.SYNOPSIS
    Detects enabled Active Directory accounts that have not logged on for a configurable number of days.

.DESCRIPTION
    Queries the `lastLogonTimestamp` attribute for every enabled user in the domain (or a specified
    OU) and reports accounts whose last logon is older than the threshold defined by -DaysInactive.

    Accounts that have never logged on (null lastLogonTimestamp) are included in the result and
    surfaced with a LastLogon value of "Never" — an enabled-but-never-used account is itself an
    IAM hygiene issue.

    Note: lastLogonTimestamp replicates between domain controllers with a delay of up to 14 days
    (controlled by the msDS-LogonTimeSyncInterval forest attribute). Treat the threshold as
    approximate, not authoritative.

.PARAMETER DaysInactive
    Number of days of inactivity that qualifies an account as inactive. Defaults to 90.

.PARAMETER SearchBase
    Distinguished name of an OU to scope the search. If omitted, the entire domain is scanned.

.PARAMETER Server
    Specific domain controller to query. If omitted, the nearest available DC is used.

.PARAMETER OutputPath
    Path of the CSV file to write. Defaults to .\InactiveUsers_<yyyyMMdd_HHmmss>.csv in the
    current directory.

.EXAMPLE
    .\Get-InactiveUsers.ps1
    Reports accounts inactive for more than 90 days and writes a timestamped CSV in the current directory.

.EXAMPLE
    .\Get-InactiveUsers.ps1 -DaysInactive 30 -OutputPath .\inactive-30d.csv
    Lowers the threshold to 30 days and writes to an explicit path.

.EXAMPLE
    .\Get-InactiveUsers.ps1 -SearchBase "OU=IT,DC=lab,DC=local" -DaysInactive 60
    Restricts the audit to the IT OU.

.NOTES
    Requires the ActiveDirectory PowerShell module (RSAT-AD-PowerShell) and read access to the
    directory. Tested against Windows Server 2019 and 2022 domain controllers.
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
    [string]$OutputPath = ".\InactiveUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "The ActiveDirectory module is not installed. Install RSAT (RSAT-AD-PowerShell) and re-run."
}

Import-Module ActiveDirectory -ErrorAction Stop

$cutoff = (Get-Date).AddDays(-$DaysInactive)
Write-Verbose "Cutoff date: $cutoff (DaysInactive = $DaysInactive)"

$adParams = @{
    Filter      = 'Enabled -eq $true'
    Properties  = @('SamAccountName', 'DisplayName', 'lastLogonTimestamp', 'LastLogonDate', 'Enabled', 'DistinguishedName')
    ErrorAction = 'Stop'
}
if ($PSBoundParameters.ContainsKey('SearchBase')) { $adParams.SearchBase = $SearchBase }
if ($PSBoundParameters.ContainsKey('Server'))     { $adParams.Server     = $Server }

try {
    $users = Get-ADUser @adParams
}
catch {
    throw "Failed to query Active Directory: $($_.Exception.Message)"
}

Write-Verbose "Retrieved $(@($users).Count) enabled user(s)"

$results = foreach ($u in $users) {
    # LastLogonDate is the DateTime projection of lastLogonTimestamp; $null when the account has never logged on
    $lastLogon = $u.LastLogonDate

    if (($null -eq $lastLogon) -or ($lastLogon -lt $cutoff)) {
        # Strip the leading CN=... component from the DN to get the parent OU path
        $ou = $u.DistinguishedName -replace '^CN=[^,]+,', ''

        [PSCustomObject]@{
            SamAccountName = $u.SamAccountName
            DisplayName    = $u.DisplayName
            LastLogon      = if ($lastLogon) { $lastLogon.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Never' }
            Enabled        = $u.Enabled
            OU             = $ou
        }
    }
}

if ($results) {
    try {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    }
    catch {
        throw "Failed to write CSV to '$OutputPath': $($_.Exception.Message)"
    }
    Write-Host "Found $(@($results).Count) inactive account(s). Report written to: $OutputPath"
}
else {
    Write-Host "No inactive accounts found (threshold: $DaysInactive days)."
}

$results
