# Sample audit results

These CSV files are **not client data**. They were produced by running the toolkit's
three detection scripts against a reproducible lab domain (`lab.local`) populated by
[`lab/seed-test-users.ps1`](../../lab/seed-test-users.ps1), which creates 31 users
across 6 OUs with deliberate IAM misconfigurations. See
[`lab/lab-scenarios.md`](../../lab/lab-scenarios.md) for the full catalogue of seeded
misconfigurations and the threat model behind each one.

Generated on 2026-08-27 against a single-DC Windows Server 2022 forest,
domain functional level 2016.

| File | Script | Rows |
|---|---|---|
| `inactive-users.csv` | `Get-InactiveUsers.ps1 -IncludeNewlyCreated` | 28 |
| `privileged-users.csv` | `Get-PrivilegedUsers.ps1` | 16 |
| `password-never-expires.csv` | `Get-PasswordNeverExpires.ps1` | 9 |

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

`AdminCount` is populated here because SDProp was forced after seeding. Without that
step the column is empty for recently added members of protected groups — SDProp runs
every 60 minutes of PDC *uptime*, not wall-clock time.