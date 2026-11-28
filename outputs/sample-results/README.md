# Sample audit results

These CSV files are **not client data**. They were produced by running the toolkit's
four detection scripts against a reproducible lab domain (`lab.local`) populated by
[`lab/seed-test-users.ps1`](../../lab/seed-test-users.ps1), which creates 35 users
across 6 OUs with deliberate IAM misconfigurations. See
[`lab/lab-scenarios.md`](../../lab/lab-scenarios.md) for the full catalogue of seeded
misconfigurations and the threat model behind each one.

Generated on 2026-11-27 against a single-DC Windows Server 2022 forest,
domain functional level 2016 (the lab rebuilt on Azure for Students from
[`lab/lab-setup.md`](../../lab/lab-setup.md)). `privileged-users.csv` was
regenerated on 2026-11-28 on the same lab, after the script gained the
`MembershipPaths` and `PathCount` columns; its 16 rows are otherwise identical to
the 2026-11-27 run.

| File | Script | Rows |
|---|---|---|
| `inactive-users.csv` | `Get-InactiveUsers.ps1 -IncludeNewlyCreated` | 32 |
| `privileged-users.csv` | `Get-PrivilegedUsers.ps1` | 16 |
| `password-never-expires.csv` | `Get-PasswordNeverExpires.ps1` | 9 |
| `kerberoastable-accounts.csv` | `Get-KerberoastableAccounts.ps1` | 5 |

## Reading these results

Two artefacts of the lab environment are worth knowing before interpreting the data.

`LastLogon` is `Never` for every seeded account. `lastLogonTimestamp` is owned by the
SAM and cannot be written through LDAP, so seeded accounts cannot be given a synthetic
logon history — they are genuinely never-authenticated rather than aged. The intended
inactivity of each account is documented in its `Description` attribute and in the
seed plan.

`PasswordAge` is uniform across all accounts for the same reason: `pwdLastSet` accepts
only `0` and `-1`, so password age cannot be backdated either. The column is
meaningful against a real directory but not demonstrable in this lab.

One empty value is expected rather than missing: `ptaylor` has no `PasswordLastSet`
because the account is flagged to change its password at next logon, which sets
`pwdLastSet` to `0`.

In `kerberoastable-accounts.csv`, `svc-default` has an empty
`SupportedEncryptionTypesRaw`: the attribute is absent on that account, which the
script reports as `NotConfigured`. `svc-mixed` (`RC4+AES`) is graded Medium as a
conservative call. Whether the KDC still issues an RC4 ticket for that configuration
by a client that requests RC4 only has not been tested yet (point 5b of the script's
Validation status); a standard client was issued AES256.

In `privileged-users.csv`, `MembershipPaths` lists every path by which the account
reaches the group (`Direct`, or `via` the intermediate groups) and `PathCount`
counts them. A `PathCount` above 1 means removing one membership does not remove the
privilege: `svc-sql` holds `Backup Operators` both directly and via
`GG-Backup-Operators-Team`, and `labadmin` holds `Administrators` by three paths.

`AdminCount` is populated here because SDProp was forced after seeding. Without that
step the column is empty for recently added members of protected groups — SDProp runs
every 60 minutes of PDC *uptime*, not wall-clock time.