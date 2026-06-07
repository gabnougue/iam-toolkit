# Lab Scenarios — IAM Misconfiguration Catalog

This document catalogues every IAM misconfiguration intentionally introduced by
[seed-test-users.ps1](seed-test-users.ps1). For each scenario it documents the real-world
context, the threat model, which detection script surfaces it, and the expected
remediation.

The lab is designed so that **the same principal often appears in two or three reports**.
Those cross-vector findings are the highest-priority items in any real audit — they tell
you that multiple controls failed on the same identity.

## How to use this document

1. Run `seed-test-users.ps1` against your `lab.local` domain.
2. Run the three detection scripts (see the validation walkthrough at the bottom).
3. Open each CSV alongside the relevant scenario section here to interpret the findings.
4. For client-facing work: this catalogue is the source material for explaining "what we
   look for and why" in scoping conversations.

---

## Scenario 1 — Stale Domain Admin

**Persona**: `mlefevre` (Marc Lefevre, OU=IT)

**Configuration in the lab**:
- Direct member of `Domain Admins`
- `lastLogonTimestamp` backdated 180 days
- Password rotated normally, account enabled

**Real-world context**: the IT manager who left the company six months ago and whose
account was never disabled. Sometimes a deliberate "break-glass" account that nobody
remembers documenting. Sometimes the result of an off-boarding ticket that closed without
the AD step actually being performed.

**Threat model**: the account holds full domain administrative rights, **and** nobody is
watching for activity on it. If the credentials leak (laptop never recovered, password
reused on a now-breached SaaS, phishing of the ex-employee's personal email), the
attacker has unmonitored DA. Detection of misuse depends on logon telemetry that nobody
reviews because "that account isn't supposed to be used."

**Detection**:
- `Get-PrivilegedUsers.ps1` → row `mlefevre, Domain Admins, Direct, user, Enabled=true, AdminCount=1`
- `Get-InactiveUsers.ps1 -IncludeNewlyCreated` → surfaces near the top (AdminCount=1 sort
  priority), LastLogon = ~180 days ago

**Cross-vector**: 2 reports — this is the canonical "stale-priv" finding pattern.

**Remediation**: disable the account immediately, then audit recent logon events from
every DC for any sign of recent use. Rotate any service-account or shared credentials
the user had access to.

---

## Scenario 2 — Legacy Sysadmin (Triple Finding)

**Persona**: `sysadmin-legacy` (OU=IT)

**Configuration in the lab**:
- Direct member of `Backup Operators`
- `PasswordNeverExpires = true`
- `lastLogonTimestamp` backdated 250 days
- `pwdLastSet` backdated 900 days

**Real-world context**: the admin account from when the domain was first deployed.
Probably created with `sysadmin / sysadmin` or similar, granted broad rights "until we
finish migrating," never decommissioned. Often shared among the original deployment
team.

**Threat model**: `Backup Operators` membership grants `SeBackupPrivilege` on domain
controllers, which is sufficient to read `NTDS.dit` and the `SYSTEM` registry hive. From
there the attacker extracts the `krbtgt` hash offline and forges Golden Tickets — full
forest compromise without ever touching a DA account. Combined with a 900-day-old
password (likely present in old credential dumps) and inactivity (nobody is watching),
this is a fully pre-staged compromise path.

**Detection**:
- `Get-PrivilegedUsers.ps1` → `sysadmin-legacy, Backup Operators, Direct`
- `Get-InactiveUsers.ps1 -IncludeNewlyCreated` → AdminCount=1, LastLogon ~250 days
- `Get-PasswordNeverExpires.ps1` → AdminCount=1, PasswordAge=900

**Cross-vector**: **3 reports** — the "everything's wrong" tier. In a real audit, this
is page-one of the report.

**Remediation**: rotate the password immediately (twice if `Backup Operators` membership
gave access to `krbtgt`-relevant data — see krbtgt-rotation guidance), then disable
the account. Replace with named admin accounts that go through PIM/JIT access for
backup operations.

---

## Scenario 3 — Service Account With Domain Admin (Kerberoasting Prime Target)

**Persona**: `svc-backup` (OU=Service Accounts)

**Configuration in the lab**:
- Direct member of `Domain Admins`
- `PasswordNeverExpires = true`
- `pwdLastSet` backdated 1100 days
- Active (used regularly by the simulated backup tool)

**Real-world context**: "the backup vendor's documentation said the service account
needs `Domain Admin` rights," nobody pushed back, the account was created in 2022 and
never reviewed. Variant: an internal script that "needs admin" because the original
author didn't want to figure out granular delegation.

**Threat model**: this is the **single most exploited path in mid-market AD breaches**.
The service account exposes a Service Principal Name (SPN) so Windows services can
authenticate to it. Any authenticated user — including an attacker who phished a
help-desk laptop — can request a TGS for that SPN. The returned ticket is encrypted with
a derivation of the account's password, which the attacker takes offline and cracks at
leisure. Because `PasswordNeverExpires` is set, the cracked password remains valid
indefinitely; the attacker can return months later and use it directly to authenticate
as `Domain Admin`.

This is **Kerberoasting**. It is the reason every modern AD security baseline says
service accounts must not hold DA rights and must rotate passwords.

**Detection**:
- `Get-PrivilegedUsers.ps1` → `svc-backup, Domain Admins, Direct, user, AdminCount=1`.
  Naming pattern (`svc-*`) is the human-readable signal that this is a service account
  in DA, not a person.
- `Get-PasswordNeverExpires.ps1` → surfaces at the very top (AdminCount=1, oldest
  PasswordAge among privileged), `PasswordAge=1100`

**Cross-vector**: 2 reports — the privileged-stale-credential combination.

**Remediation** (in order of preference):
1. Migrate to a Group Managed Service Account (gMSA). Automatic 30-day rotation,
   no SPN-to-cleartext path.
2. If migration is impossible (vendor product locked to a specific account):
   - Replace `Domain Admins` membership with the narrowest delegated permission set
     that actually works (e.g., specific OU-level write rights).
   - Remove `PasswordNeverExpires`, enforce rotation via a PAM/vault product that owns
     the account.
   - Set a long, randomly generated password (>=25 chars) to make Kerberoasting
     cracking infeasible in practice.

---

## Scenario 4 — Worst Case: Dormant Privileged Service Account

**Persona**: `svc-legacy` (OU=Service Accounts)

**Configuration in the lab**:
- Direct member of `Domain Admins`
- `PasswordNeverExpires = true`
- `lastLogonTimestamp` backdated 400 days
- `pwdLastSet` backdated 1400 days

**Real-world context**: the service this account supported was decommissioned years ago.
The application owner left. Nobody owns the account anymore, so nobody dares delete it
"in case something breaks." Often discovered by audit teams looking specifically for
service accounts with no recent activity.

**Threat model**: combines every other scenario.
- Same Kerberoasting path as Scenario 3.
- Nobody would notice if it were used — operational blind spot.
- Forgotten = unmonitored = a potential persistence mechanism for an attacker who has
  already compromised the environment.

**Detection**: **all three scripts**.
- `Get-PrivilegedUsers.ps1` → `Direct, Domain Admins, AdminCount=1`
- `Get-InactiveUsers.ps1 -IncludeNewlyCreated` → top of report, LastLogon ~400 days
- `Get-PasswordNeverExpires.ps1` → top of report, PasswordAge=1400

The intersection of all three CSVs (join on SamAccountName) is the audit's
highest-severity findings list. This persona is the worked example for that join.

**Remediation**: disable immediately. Investigate why it remained enabled — the gap in
the off-boarding/decommission process is the underlying finding. Document an account
ownership matrix so the next svc-legacy is impossible.

---

## Scenario 5 — Stale Executive with PasswordNeverExpires

**Persona**: `ccfo` (Catherine CFO, OU=Management)

**Configuration in the lab**:
- No protected-group membership (`AdminCount = 0`)
- `PasswordNeverExpires = true`
- `lastLogonTimestamp` backdated 100 days
- `pwdLastSet` backdated 600 days

**Real-world context**: executive who travels constantly, uses a personal laptop for
most work, rarely touches the corporate AD-joined environment. IT enabled `PNE` "for
convenience" so password expiry doesn't lock them out at a critical moment. Nobody
revisits the decision.

**Threat model**: lower severity than a privileged account but still significant.
Executive accounts are prime targets for Business Email Compromise (BEC) and social
engineering. The 600-day-old password may exist in past credential dumps; the executive
likely reused some variant of it elsewhere. The infrequent logon means a hostile
session would not be quickly noticed.

**Detection**:
- `Get-InactiveUsers.ps1 -IncludeNewlyCreated` → mid-report (`AdminCount = null`)
- `Get-PasswordNeverExpires.ps1` → mid-report

**Cross-vector**: 2 reports — non-privileged but still worth flagging because the
combination raises the risk.

**Remediation**: remove `PNE`, enforce strong MFA on the account, document the expected
usage pattern so deviations are detectable.

---

## Scenario 6 — Provisioning Ghost (Never Logged In)

**Personas**: `cstein` (OU=IT), `jthomas` (OU=HR), `svc-print` (OU=Service Accounts)

**Configuration in the lab**:
- Enabled, no group memberships (or minimal)
- `lastLogonTimestamp` = null
- `pwdLastSet` = today (account created today, never used)

**Real-world context**: the joiner-mover-leaver pipeline created the account, but the
person never started (offer rescinded, new role chosen, project cancelled) or the
service was never deployed. The account stays enabled because nobody owns the cleanup.

**Threat model**: individually low risk. **Cumulatively**, large numbers of never-used
accounts are a symptom of a broken provisioning process and a measurable inflation of
the attack surface. Every ghost account is a potential foothold; the password is whatever
was set at provisioning (often a predictable template like `Welcome2026!`).

Service-account variants (`svc-print`) are slightly higher priority: a never-used
service account suggests either a misconfigured deployment (the service won't start) or
a service that was abandoned mid-rollout.

**Detection**:
- `Get-InactiveUsers.ps1 -IncludeNewlyCreated` → LastLogon = "Never". Without
  `-IncludeNewlyCreated`, all three are filtered out as too-young — see Scenario 7.

**Remediation**: review against HR/IT records. Onboard the person if they are still
expected, or disable the account. Strengthen the off-boarding pipeline to include an
automated "never-logged-in after N days" sweep.

---

## Scenario 7 — Too-Young Account (Negative Test)

**Persona**: `ldubois` (Lucas Dubois, OU=IT)

**Configuration in the lab**:
- Enabled, no group memberships
- `lastLogonTimestamp` = null
- `whenCreated` = today (cannot be backdated — `whenCreated` is schema-protected
  with `NO_USER_MODIFY`)

**Real-world context**: an account created yesterday for a person starting Monday. It
has not logged on because the person has not started yet. This is **not a finding** and
the script must not flag it.

**Threat model**: none yet. Premature flagging would erode the auditor's credibility
("the report has noise — we'll ignore the next one too").

**Detection**:
- `Get-InactiveUsers.ps1` (no `-IncludeNewlyCreated`) → **excluded** by the
  `whenCreated > cutoff` filter. The expected behaviour.
- `Get-InactiveUsers.ps1 -IncludeNewlyCreated` → surfaces as `LastLogon = Never`. This
  is correct in the lab context where every seeded user has `whenCreated = today` and
  the operator explicitly opts to include them; it would surface as a finding in a
  post-migration audit too.

This persona is the **negative test** that validates the too-young filter works as
designed. In a normal run (no switch), `ldubois` does not appear. With the switch, it
does. The contrast demonstrates the filter behaviour to a reviewer.

**Remediation**: none — by design.

---

## Scenario 8 — Excessive Operator Privilege on a Business Role

**Persona**: `aceo` (Alex CEO, OU=Management)

**Configuration in the lab**:
- Direct member of `Account Operators`
- Otherwise normal (active, password rotation enabled)

**Real-world context**: an executive demanded admin access for some self-service
operation, IT pushed back, IT was overruled, IT compromised by granting `Account
Operators`. Variant: an Identity Manager role assignment was misconfigured and granted
the operator role instead of a read-only equivalent.

**Threat model**: `Account Operators` is one of the
**[AdminSDHolder protected groups](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)** — within an hour of being added, the user's `adminCount`
is set to `1` and their ACL is propagated by SDProp. They can:
- Create, modify, and delete user/group/computer objects that are not themselves in the
  protected set.
- Modify membership of non-protected groups, which often includes operationally
  important ones (e.g., custom IT groups, GPO-scoping groups).

This is enough to pivot to a Domain Admin position in many environments by:
1. Creating a new user.
2. Adding that user to a non-protected group that has write access to the OU containing
   privileged users via a misconfigured delegation.
3. Resetting a DA password via that delegation.

**Detection**:
- `Get-PrivilegedUsers.ps1` → `aceo, Account Operators, Direct, AdminCount=1`. The
  `OU=Management` location is the auditor's contextual cue that this is a business role
  with unexpected admin privilege.

**Remediation**: revoke the membership. Implement a Privileged Identity Management
solution (or the equivalent) so admin role requests are auditable, time-bound, and
justified per-instance rather than standing.

---

## Scenario 9 — Shadow Privilege via Nested Custom Group

**Personas**: `GG-IT-Admins` (group) containing `jadams` and `mlefevre`, nested in
`Domain Admins`.

**Configuration in the lab**:
- `GG-IT-Admins` is a Global Security group in OU=IT.
- `GG-IT-Admins` is itself a member of `Domain Admins`.
- Users `jadams` and `mlefevre` are direct members of `GG-IT-Admins` (and also direct
  in DA for this lab — in production typically only the nesting exists).

**Real-world context**: IT created a "team" group for convenience: every IT hire is
added to `GG-IT-Admins` and inherits the standard IT permissions. Once upon a time
someone needed `DA` rights to do something quickly, nested `GG-IT-Admins` in `DA`
"temporarily," forgot to undo it. Two years later, every IT hire is implicitly DA from
day one.

**Threat model**: **shadow privilege escalation**. Adding a user to `GG-IT-Admins` looks
like a routine, low-stakes change in a ticket — and it bypasses any change control around
DA membership. The org's DA membership review process inspects DA directly and sees a
short list (the nested group); it does not inspect the contents of the nested group.

This is one of the most common findings in real audits because the team that owns the
nested group is rarely the same team that owns DA.

**Detection**:
- `Get-PrivilegedUsers.ps1` → for `jadams` and `mlefevre`, rows with
  `GroupName = Domain Admins, MembershipType = Nested`. The current dedup logic
  collapses to `Direct` when the same user is also a direct member (lab quirk —
  production would usually show pure Nested). The non-collapsed view: each chain is
  traceable via the `DistinguishedName` of the principal and the `member` attribute
  of intermediate groups.

**Remediation**: flatten the nesting. Either remove `GG-IT-Admins` from `Domain Admins`
and require direct DA membership with an approval workflow, or split the group into
"members who actually need DA" and "members who do not."

---

## Scenario 10 — Empty / Orphan Groups

**Personas**: `GG-Empty-Legacy` and `GG-Orphan-2018` (both in OU=IT, both with zero
members).

**Configuration in the lab**:
- Created with descriptive `Description` indicating their legacy / orphan nature.
- Zero members.

**Real-world context**: groups created for projects that ended, for team reorgs that
happened years ago, for vendor migrations completed long since. Nobody owns them,
nobody deletes them.

**Threat model**: mostly hygiene. **But** the risk surface is:
1. Empty groups frequently still hold ACLs on file shares, SharePoint sites, or are
   scoped on GPOs. Adding any user to the group implicitly grants those rights.
2. Misleading names create social engineering vectors. An attacker who can manipulate
   group membership (Account Operators, delegated group manager) chooses a
   harmless-looking orphan group whose name suggests a normal team — e.g.,
   `GG-Backup-Operators-Team`, the cousin of our `GG-Backup-Operators-Team` in
   Scenario 11.

**Detection**: the current toolkit does **not** include a dedicated empty-group
detector. `Get-PrivilegedUsers.ps1` will note empty privileged groups under `-Verbose`
but will not surface ordinary empty groups. This is a **known gap** to address in a
future iteration (Phase 2 candidate: `Get-OrphanGroups.ps1`).

**Remediation**: review the group's intended purpose and ownership. Delete if obsolete,
or assign an owner and document the purpose. Implement a quarterly orphan-group sweep
as a recurring control.

---

## Scenario 11 — Nested Privilege via Service-Team Group

**Personas**: `GG-Backup-Operators-Team` (group) containing `svc-sql`, nested in
`Backup Operators`.

**Configuration in the lab**:
- `GG-Backup-Operators-Team` is in OU=Service Accounts.
- `svc-sql` is direct member of both `Backup Operators` and `GG-Backup-Operators-Team`.

**Real-world context**: a team owns multiple backup-related services. Rather than
adding each service account directly to `Backup Operators`, they created a team group.
Same pattern as Scenario 9 but applied to service accounts. Same risk: any future
service account dropped into the team group inherits Backup Operators (and therefore
the NTDS.dit extraction path).

**Threat model**: identical to Scenario 2's underlying threat (`Backup Operators`
ability to extract `NTDS.dit`), but the nesting structure hides which principals
ultimately hold the privilege. A reviewer inspecting `Backup Operators` membership sees
one group; they have to walk into the group to see the actual accounts.

**Detection**:
- `Get-PrivilegedUsers.ps1` → `svc-sql, Backup Operators, Nested` (the dedup picks
  Direct if also direct — in this lab `svc-sql` is both Direct and Nested, demonstrating
  the dedup behaviour). The presence of the intermediate group is visible by inspecting
  `Backup Operators` membership directly.

**Remediation**: same as Scenario 9 — flatten where possible, or formalise the team
group as a managed object (owner, justification, review cadence).

---

## Scenario 12 — Non-Privileged User with PasswordNeverExpires

**Persona**: `rmills` (Robert Mills, OU=IT)

**Configuration in the lab**:
- Standard user, no admin role
- `PasswordNeverExpires = true`
- `pwdLastSet` backdated 730 days

**Real-world context**: a user complained about password reset prompts, escalated,
helpdesk enabled `PNE` "just for them." Variant: an application required a static
password and the user's account was repurposed to hold that password.

**Threat model**: a 2-year-old password is statistically likely to appear in some
credential dump or have been reused on a now-breached personal account. The risk is
proportional to the user's effective access — `rmills` is in IT, which usually means
non-trivial access to file shares, business systems, perhaps source repositories.

Standalone this is a moderate finding; the higher-priority cousin is when `PNE` is set
on accounts with `AdminCount = 1` (Scenarios 2, 3, 4).

**Detection**:
- `Get-PasswordNeverExpires.ps1` → mid-report (`AdminCount = null`, `PasswordAge = 730`)

**Remediation**: revoke `PNE`, force a password change at next logon, document the
business reason if `PNE` is genuinely required (rare).

---

## Scenario 13 — Disabled Accounts (Negative Test)

**Personas**: `jsmith`, `rpark`, `wlegacy` (all OU=Disabled Users)

**Configuration in the lab**:
- `Enabled = false`
- Variously inactive, with one (`wlegacy`) flagged as a former DA member

**Real-world context**: former employees, properly off-boarded. Kept disabled for audit
trail or for the retention period mandated by HR/legal.

**Threat model**: none for active exploitation (disabled accounts cannot authenticate).
The hygiene question is whether they should be deleted or moved to a dedicated
deletion-pending OU after the retention period — but that is a policy question, not a
detection-script question.

**Detection** (negative test — should NOT surface in default-mode reports):
- `Get-InactiveUsers.ps1` → excluded by the `Enabled = true` filter.
- `Get-PrivilegedUsers.ps1` → `wlegacy` is no longer in any privileged group (the lab
  simulates an off-boarding where group membership was removed before disabling), so
  does not appear.
- `Get-PasswordNeverExpires.ps1` → excluded by default; surfaces only with
  `-IncludeDisabled`.

The default behaviour is correct; the auditor's report does not waste lines on accounts
that cannot authenticate.

---

## Scenario 14 — Must-Change-At-Next-Logon (Configuration Edge Case)

**Persona**: `ptaylor` (Patricia Taylor, OU=IT)

**Configuration in the lab**:
- Enabled, `ChangePasswordAtLogon = true` (which sets `pwdLastSet = 0`)
- No other anomalies

**Real-world context**: helpdesk just reset the password and required the user to
change it at next logon. Or: a new hire whose account was created with the must-change
flag.

**Threat model**: not a finding by itself. **But** it is a hygiene case worth surfacing
because:
1. If combined with `PasswordNeverExpires = true`, it is a configuration contradiction
   (the must-change flag is satisfied at next logon, but `PNE` then prevents further
   rotation — a confusing state to a future reviewer).
2. A long-standing `pwdLastSet = 0` (months without anyone logging in to change it)
   suggests the password reset was never used → unused account.

**Detection**:
- `Get-PasswordNeverExpires.ps1` → for `ptaylor`, this script returns no row (`PNE` is
  not set). If `PNE` were also set, the row would appear with `PasswordAge = null`
  (sort priority below known ages) and `PasswordLastSet = null`.

In the lab, `ptaylor` is the documented expected-null case for the sort logic; the
`PasswordAge = null` branch of `Get-PasswordNeverExpires.ps1` is exercised by any user
who has been seeded with `ChangePasswordAtLogon` and `PasswordNeverExpires` together
(none in the current seed — left as a possible extension).

**Remediation**: no action unless `pwdLastSet = 0` persists for an extended period, in
which case treat as a never-used-after-reset finding.

---

## Cross-vector findings matrix

The table below shows which seeded principals surface in each of the three reports.
The two-or-three-cell rows are the highest-priority findings in any real audit.

| Persona            | Inactive | Privileged | PNE | Notes |
|--------------------|:--------:|:----------:|:---:|---|
| `svc-legacy`       | yes      | yes        | yes | Worst case — all 3 reports |
| `sysadmin-legacy`  | yes      | yes        | yes | Triple finding |
| `svc-backup`       | —        | yes        | yes | Kerberoasting target |
| `mlefevre`         | yes      | yes        | —   | Stale DA |
| `svc-sql`          | —        | yes        | yes | Backup Op + PNE |
| `ccfo`             | yes      | —          | yes | Stale exec |
| `alopez`           | yes      | —          | yes | Stale HR + PNE |
| `aceo`             | —        | yes        | —   | Excessive operator |
| `jadams`           | —        | yes        | —   | Active DA (baseline good) |
| `rmills`           | —        | —          | yes | Standalone PNE |
| `pkim`             | —        | —          | yes | Standalone PNE |
| `svc-monitor`      | —        | —          | yes | Service PNE |
| `cstein`           | yes\*    | —          | —   | Never logged in |
| `jthomas`          | yes\*    | —          | —   | Never logged in |
| `svc-print`        | yes\*    | —          | —   | Never logged in (service) |
| `ldubois`          | yes\*\*  | —          | —   | Too-young filter test |
| `jsmith`/`rpark`/`wlegacy` | — | —      | —   | Disabled — must NOT surface |

\* Requires `-IncludeNewlyCreated` (whenCreated=today on all seeded users; see
Scenario 7 for the reason).

\*\* Surfaces ONLY with `-IncludeNewlyCreated`; absence without the switch validates the
too-young filter (negative test).

---

## Validation walkthrough

Run from the repository root on the lab DC (or a host with RSAT against `lab.local`):

```powershell
# 1. Seed the lab (idempotent — safe to re-run)
.\lab\seed-test-users.ps1

# 2. Run the three detection scripts
.\scripts\powershell\Get-InactiveUsers.ps1        -IncludeNewlyCreated -OutputPath .\outputs\inactive.csv
.\scripts\powershell\Get-PrivilegedUsers.ps1      -OutputPath .\outputs\privileged.csv
.\scripts\powershell\Get-PasswordNeverExpires.ps1 -OutputPath .\outputs\pne.csv
```

### Expected counts (lab baseline)

| Report                          | Expected rows | Notes |
|---------------------------------|---------------|---|
| `inactive.csv` (with switch)    | ~10           | 7 backdated + 3 never-logged-in + ldubois |
| `inactive.csv` (without switch) | 0             | All seeded users excluded as too-young — validates the filter |
| `privileged.csv`                | ~10           | Direct + Nested across DA / Backup Op / Account Op |
| `pne.csv`                       | 9             | Excludes disabled, excludes managed service accounts (none seeded) |

### Validation checks to perform

1. **Top of `pne.csv`** should be `svc-legacy` (AdminCount=1, PasswordAge=1400 days).
2. **Top of `inactive.csv`** should be `svc-legacy` then `sysadmin-legacy` then
   `mlefevre` (AdminCount=1 sort priority, oldest LastLogon first within tier).
3. **`privileged.csv`** should contain rows for `jadams`, `mlefevre`, `svc-backup`,
   `svc-legacy` all tagged `Direct, Domain Admins`. `svc-sql` should appear
   `Direct, Backup Operators` and `Nested, Backup Operators` (the latter collapses
   to Direct under the script's dedup).
4. **None of the disabled users** (`jsmith`, `rpark`, `wlegacy`) should appear in any
   default-mode report.

### Cross-vector join

```powershell
$inactive   = Import-Csv .\outputs\inactive.csv
$privileged = Import-Csv .\outputs\privileged.csv
$pne        = Import-Csv .\outputs\pne.csv

# Principals appearing in all three reports — the highest-priority findings
$inactive |
    Where-Object { $privileged.SamAccountName -contains $_.SamAccountName } |
    Where-Object { $pne.SamAccountName        -contains $_.SamAccountName } |
    Select-Object SamAccountName, DisplayName, LastLogon, AdminCount
```

In the lab this query returns `svc-legacy` and `sysadmin-legacy`. In a real audit, the
output of this join is the executive-summary-page-one of the report.
