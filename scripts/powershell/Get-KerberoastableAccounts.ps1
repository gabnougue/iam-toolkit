<#
.SYNOPSIS
    Detects user accounts exposed to Kerberoasting: enabled user objects that carry a
    Service Principal Name (SPN), graded by privilege and by the Kerberos encryption
    types the account accepts.

.DESCRIPTION
    Read-only audit. Queries the directory for user objects (never computers) whose
    servicePrincipalName attribute is populated, using a server-side LDAP filter, and
    reports each match with what an auditor needs to prioritise remediation:
    privilege (AdminCount), the encryption types the account accepts for service
    tickets (decoded from msDS-SupportedEncryptionTypes), and the age of its password.

    The script changes nothing in the directory and requests no Kerberos ticket. It
    identifies the configuration that makes an account crackable offline so that the
    configuration can be corrected before anyone exploits it.

    Computer accounts are excluded on purpose: they carry many legitimate SPNs, and
    their passwords are 120-character random values rotated automatically every
    30 days, which puts them out of reach of offline cracking. Group / standalone
    Managed Service Accounts are excluded for the same reason (random, rotated
    passwords) - they are not user objects in the LDAP filter used here.

    Each row is assigned a fixed Severity value:
      Critical  - privileged (AdminCount = 1) AND RC4 still accepted
      High      - privileged AND AES only
      Medium    - not privileged AND RC4 still accepted
      Low       - not privileged AND AES only
    Password age breaks ties inside a tier (oldest first).

.PARAMETER IncludeDisabled
    Include disabled accounts. By default only enabled accounts are returned: the
    KDC does not issue service tickets for a disabled service principal, so a
    disabled account with an SPN is hygiene, not exposure.

.PARAMETER SearchBase
    Distinguished name of an OU to scope the search. If omitted, the whole domain is
    scanned.

.PARAMETER Server
    Specific domain controller to query. If omitted, the nearest available DC is used.

.PARAMETER OutputPath
    Path of the CSV file to write. Defaults to
    .\KerberoastableAccounts_<yyyyMMdd_HHmmss>.csv in the current directory.

.EXAMPLE
    .\Get-KerberoastableAccounts.ps1
    Reports enabled user accounts that carry an SPN, Critical tier first.

.EXAMPLE
    .\Get-KerberoastableAccounts.ps1 -OutputPath .\outputs\kerberoastable.csv
    Writes to an explicit path.

.EXAMPLE
    .\Get-KerberoastableAccounts.ps1 -SearchBase "OU=Service Accounts,DC=lab,DC=local"
    Restricts the audit to the service accounts OU.

.NOTES
    Threat model (why an SPN on a user account is a finding):

      Starting position: any authenticated domain account, no privilege
        Requesting a service ticket (TGS) for an SPN is ordinary Kerberos behaviour:
        every domain user is allowed to do it, for any SPN in the forest. An attacker
        who holds a single low-privilege account - a phished helpdesk laptop, a
        contractor login - is therefore already in position. No elevation, no
        exploit, no foothold on a server is required. That is what makes this
        exposure serious: the bar to start is the lowest one in the domain.

      Mechanism
        Part of the service ticket the KDC returns is encrypted with a key derived
        from the service account's password. The attacker takes that ticket offline
        and runs a password-guessing attack against it, with no further contact with
        the domain. Every successful guess yields the account's cleartext password.
        For a computer account the password is random and the attack is pointless;
        for a user account the password was chosen by a human, so it is guessable.

      Role of the encryption type
        RC4-HMAC: the key is an unsalted MD4 hash of the password. Commodity GPU
        hardware tests billions of candidates per second; a typical human-chosen
        service account password falls in hours.
        AES128 / AES256: the key derivation is salted and iterated (PBKDF2, 4096
        rounds), orders of magnitude slower to attack. AES REDUCES the risk, it does
        not REMOVE it: a weak or reused password under AES is still recovered, just
        later. That is why an AES-only account with an old password stays in the
        report (Low or High tier) rather than disappearing from it.

      Why detect the configuration rather than the attack
        The ticket request is a legitimate operation. On the domain controller it
        produces an ordinary event 4769 indistinguishable, in volume and form, from
        normal service access - unless the environment specifically alerts on RC4
        tickets (encryption type 0x17) or on honey SPNs. The cracking itself happens
        on the attacker's machine and leaves no trace in the domain at all. In
        practice the attack is silent. The defensible move is to find and fix the
        exposed configuration upstream: this script.

      Worst case - tie-in to finding F-01 of the sample audit report
        An account that is both kerberoastable AND privileged turns "any domain
        user" into "Domain Admin" in one offline step. F-01 of
        reports/sample-audit-report.md describes privileged service accounts with
        PasswordNeverExpires (svc-backup, svc-legacy, svc-sql, sysadmin-legacy).
        Add an SPN to any of them and the password never rotates, so a password
        cracked once stays valid indefinitely. That combination is why
        privileged + RC4 is the Critical tier, and why this report should always be
        read next to password-never-expires.csv.

    msDS-SupportedEncryptionTypes decoding:
      The attribute is a bit mask (MS-KILE 2.2.7). Cipher-family bits:
        0x01  DES-CBC-CRC                (legacy, disabled by default since 2008 R2)
        0x02  DES-CBC-MD5                (legacy, idem)
        0x04  RC4-HMAC
        0x08  AES128-CTS-HMAC-SHA1-96
        0x10  AES256-CTS-HMAC-SHA1-96
      Bits that do NOT change how the service ticket is encrypted, and are ignored
      by the EncryptionType column:
        0x20     AES256-CTS-HMAC-SHA1-96-SK (AES session key only, added Nov 2022)
        0x10000+ feature flags (FAST, compound identity, claims, resource SID
                 compression)
      The raw integer is exported in SupportedEncryptionTypesRaw so the decoding can
      be checked by hand.

      EncryptionType values (fixed strings):
        AES            - only AES bits set. The KDC encrypts the ticket with AES.
        RC4            - RC4 set, no AES.
        RC4+AES        - both set. The account keeps an RC4 key and declares RC4
                         as accepted, so it is graded as RC4-exposed - a
                         conservative classification. Whether the KDC actually
                         issues an RC4 ticket for a 0x1C account when the client
                         requests RC4 only is NOT confirmed; it must be tested in
                         the lab (see Validation status, point 5).
        DES / DES+...  - legacy DES bits present. Treated as RC4-exposed (worse).
        NotConfigured  - attribute absent or no cipher bit set. See below.

      NotConfigured - the default behaviour:
        Most user service accounts never have the attribute set. The KDC then falls
        back to the domain default (registry value DefaultDomainSupportedEncTypes
        under HKLM\SYSTEM\CurrentControlSet\Services\KDC on each DC). Historically
        that default produces RC4-encrypted service tickets for such accounts; the
        November 2022 hardening kept RC4 for the ticket while moving the session key
        to AES. Microsoft's ongoing RC4 deprecation is changing the default again,
        and the effective value depends on each DC's patch level and registry. This
        script cannot read the KDC registry, so it treats NotConfigured as
        RC4-exposed - the conservative reading. Confirm on the target DCs before
        downgrading any NotConfigured row.

    AES keys may not exist even when the attribute says AES:
      An account only holds AES keys if its password was last set after the domain
      functional level reached Windows Server 2008. A service account whose password
      predates that raise has no AES keys, and the KDC falls back to RC4 regardless
      of msDS-SupportedEncryptionTypes. A very old PasswordAge on an AES row is the
      cue: reset the password and the AES keys are generated.

    Privilege is read from adminCount - it can be wrong in both directions:
      Under-grading: adminCount is set by SDProp, which runs every 60 minutes of
      PDC uptime. A principal added to a protected group very recently can still
      read AdminCount = null and be graded one tier too low.
      Over-grading: SDProp never clears adminCount. An account removed from a
      protected group keeps adminCount = 1 indefinitely (orphaned adminCount,
      common in production) and surfaces as Critical / High although it no longer
      holds that privilege.
      Scope limit: adminCount only reflects membership of the AdminSDHolder
      protected groups. An account privileged by other means - local admin on
      servers, DCSync rights granted through ACLs, delegated rights on OUs - reads
      as non-privileged and is graded Medium / Low.
      Cross-check with Get-PrivilegedUsers.ps1, whose membership walk is
      authoritative for protected-group membership.

    Exclusions:
      - Computer objects (objectCategory = computer): out of scope, see DESCRIPTION.
      - Managed service accounts: not matched by objectCategory = person.
      - krbtgt (RID 502) and RODC krbtgt_<n> accounts: they carry an SPN
        (kadmin/changepw) and are disabled, so they would surface under
        -IncludeDisabled. Their keys are random and system-managed; they are not a
        Kerberoasting target and are always excluded.

    Remediation, in order of preference:
      1. Remove the SPN if nothing uses it (stale SPNs from decommissioned services
         are common).
      2. Migrate the service to a gMSA: random 120-character password, automatic
         rotation, the attack becomes irrelevant.
      3. If the account must stay a user account: set msDS-SupportedEncryptionTypes
         to AES only (0x18), reset the password to a long random value (25+
         characters) so AES keys are regenerated, and remove privileged group
         membership in favour of narrowly delegated rights.

    Validation status - written blind, NOT yet run against a real directory:
      The original lab.local VM no longer exists: the free Azure credit expired on
      13 September 2026 and the VM was deleted afterwards. The lab is to be
      rebuilt on an Azure for Students subscription, from the repo's lab
      procedure (lab/lab-setup.md), before the first run. This script was
      written in November 2026 with no DC available. Every line tagged
      VERIFY-ON-FIRST-RUN in the code must be checked on the first run (grep for
      the tag). In particular:
        1. msDS-SupportedEncryptionTypes retrieval and decoding - the most likely
           point of failure (hyphenated LDAP name as a property, null vs 0, value
           type returned by the AD module).
        2. Enabled and PasswordLastSet are requested by name: the 26-Aug-2026 run
           showed the AD module does not derive friendly properties from raw ones.
        3. krbtgt / krbtgt_<n> exclusion on a domain that has an RODC.
        4. Against the current seed this script returns zero rows: svc-backup has
           no SPN yet. The seed extension adds it - until then, set an SPN by hand
           on a lab account to exercise the code path.
        5. RC4+AES grading: set msDS-SupportedEncryptionTypes = 0x1C on a test
           account, request its ticket with impacket GetUserSPNs.py, and read the
           hash prefix ($krb5tgs$23$ = RC4, $krb5tgs$18$ = AES256) to confirm or
           refute that a 0x1C account can still yield an RC4 ticket.

    Requires the ActiveDirectory PowerShell module (RSAT-AD-PowerShell) and read
    access to the directory. No privilege beyond an ordinary domain account is
    needed: everything read here is readable by Authenticated Users by default.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeDisabled,

    [Parameter()]
    [string]$SearchBase,

    [Parameter()]
    [string]$Server,

    [Parameter()]
    [string]$OutputPath = ".\KerberoastableAccounts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "The ActiveDirectory module is not installed. Install RSAT (RSAT-AD-PowerShell) and re-run."
}

Import-Module ActiveDirectory -ErrorAction Stop

# UAC bit used by the LDAP bitwise filter
$ACCOUNTDISABLE = 0x2

# msDS-SupportedEncryptionTypes cipher-family bits (MS-KILE 2.2.7). Higher bits
# (0x20 AES session-key, 0x10000+ feature flags) do not change ticket encryption.
$ETYPE_DES_CBC_CRC = 0x01
$ETYPE_DES_CBC_MD5 = 0x02
$ETYPE_RC4_HMAC    = 0x04
$ETYPE_AES128      = 0x08
$ETYPE_AES256      = 0x10

$ETYPE_DES_MASK = $ETYPE_DES_CBC_CRC -bor $ETYPE_DES_CBC_MD5
$ETYPE_AES_MASK = $ETYPE_AES128 -bor $ETYPE_AES256

$ENCTYPES_ATTR = 'msDS-SupportedEncryptionTypes'

function ConvertTo-EncryptionTypeLabel {
    param([AllowNull()]$RawValue)

    # VERIFY-ON-FIRST-RUN: confirm the AD module returns $null (not 0, not an empty
    # collection) when the attribute is absent, and an [int] when it is set.
    if ($null -eq $RawValue) { return 'NotConfigured' }

    $mask = [int]$RawValue
    $families = @()
    if ($mask -band $ETYPE_DES_MASK) { $families += 'DES' }
    if ($mask -band $ETYPE_RC4_HMAC) { $families += 'RC4' }
    if ($mask -band $ETYPE_AES_MASK) { $families += 'AES' }

    if ($families.Count -eq 0) { return 'NotConfigured' }
    return ($families -join '+')
}

# objectCategory=person excludes computers (whose objectClass also contains 'user')
# and managed service accounts. 1.2.840.113556.1.4.803 = LDAP_MATCHING_RULE_BIT_AND.
$ldapClauses = @(
    '(objectCategory=person)'
    '(objectClass=user)'
    '(servicePrincipalName=*)'
)
if (-not $IncludeDisabled) {
    $ldapClauses += "(!(userAccountControl:1.2.840.113556.1.4.803:=$ACCOUNTDISABLE))"
}
$ldapFilter = '(&' + ($ldapClauses -join '') + ')'
Write-Verbose "LDAP filter: $ldapFilter"

$adParams = @{ ErrorAction = 'Stop' }
if ($PSBoundParameters.ContainsKey('Server'))     { $adParams.Server     = $Server }
if ($PSBoundParameters.ContainsKey('SearchBase')) { $adParams.SearchBase = $SearchBase }

# Calculated properties are requested by name: the AD module does not derive
# PasswordLastSet from pwdLastSet on its own (26-Aug-2026 lab run).
# VERIFY-ON-FIRST-RUN: the hyphenated attribute name is accepted by -Properties and
# exposed as a property readable with $u.'msDS-SupportedEncryptionTypes'.
$queryProps = @(
    'DisplayName', 'servicePrincipalName', $ENCTYPES_ATTR,
    'PasswordLastSet', 'adminCount', 'Enabled'
)

try {
    $users = Get-ADUser -LDAPFilter $ldapFilter -Properties $queryProps @adParams
}
catch {
    throw "Failed to query Active Directory: $($_.Exception.Message)"
}

Write-Verbose "Retrieved $(@($users).Count) user account(s) with an SPN"

$now = Get-Date

$rawRows = foreach ($u in $users) {
    # krbtgt (RID 502) and RODC krbtgt_<n>: system-managed random keys, not a target.
    # VERIFY-ON-FIRST-RUN: check on a domain that has an RODC.
    if ($u.SID -and $u.SID.Value -match '-502$') { continue }
    if ($u.SamAccountName -like 'krbtgt_*')     { continue }

    $rawEnc   = $u.$ENCTYPES_ATTR
    $encLabel = ConvertTo-EncryptionTypeLabel -RawValue $rawEnc

    # Only AES-only accounts escape the RC4-exposed grading (see .NOTES)
    $rc4Exposed = $encLabel -ne 'AES'
    $privileged = ($u.adminCount -eq 1)

    $severity = if     ($privileged -and $rc4Exposed) { 'Critical' }
                elseif ($privileged)                  { 'High' }
                elseif ($rc4Exposed)                  { 'Medium' }
                else                                  { 'Low' }

    $passwordAge = if ($u.PasswordLastSet) { [int]($now - $u.PasswordLastSet).TotalDays } else { $null }

    # Strip the leading CN=... component, handling escaped commas inside the CN
    $ou = ($u.DistinguishedName -split '(?<!\\),', 2)[1]

    [PSCustomObject]@{
        Severity                    = $severity
        SamAccountName              = $u.SamAccountName
        DisplayName                 = $u.DisplayName
        ServicePrincipalName        = (@($u.servicePrincipalName) | Sort-Object) -join '; '
        EncryptionType              = $encLabel
        SupportedEncryptionTypesRaw = $rawEnc
        PasswordAge                 = $passwordAge
        PasswordLastSetDt           = $u.PasswordLastSet
        AdminCount                  = $u.adminCount
        Enabled                     = $u.Enabled
        OU                          = $ou
        DistinguishedName           = $u.DistinguishedName
    }
}

$severityRank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }

# Severity tier first, then oldest password (unknown age last), then SAM
$results = $rawRows |
    Sort-Object `
        @{Expression = { $severityRank[$_.Severity] } }, `
        @{Expression = { if ($null -ne $_.PasswordAge) { 0 } else { 1 } } }, `
        @{Expression = 'PasswordAge'; Descending = $true }, `
        SamAccountName |
    ForEach-Object {
        [PSCustomObject]@{
            Severity                    = $_.Severity
            SamAccountName              = $_.SamAccountName
            DisplayName                 = $_.DisplayName
            ServicePrincipalName        = $_.ServicePrincipalName
            EncryptionType              = $_.EncryptionType
            SupportedEncryptionTypesRaw = $_.SupportedEncryptionTypesRaw
            PasswordAge                 = $_.PasswordAge
            PasswordLastSet             = if ($_.PasswordLastSetDt) { $_.PasswordLastSetDt.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
            AdminCount                  = $_.AdminCount
            Enabled                     = $_.Enabled
            OU                          = $_.OU
            DistinguishedName           = $_.DistinguishedName
        }
    }

if ($results) {
    try {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    }
    catch {
        throw "Failed to write CSV to '$OutputPath': $($_.Exception.Message)"
    }
    Write-Host "Found $(@($results).Count) kerberoastable user account(s). Report written to: $OutputPath"
}
else {
    Write-Host "No kerberoastable user accounts found (no enabled user object carries an SPN)."
}

$results
