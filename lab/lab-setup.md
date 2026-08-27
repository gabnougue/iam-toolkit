# Lab Setup — Reproducible AD Environment

Step-by-step guide to build the lab environment used by the IAM Toolkit. At the end you
will have a single Windows Server domain controller running `lab.local`, populated with
the misconfigurations catalogued in [lab-scenarios.md](lab-scenarios.md), against which
the three detection scripts can be executed.

**Estimated total time**: 60–90 minutes (longer with Windows updates).

**Skill assumed**: ability to install Windows from an ISO. No prior Active Directory
experience required.

---

## What you will have at the end

- One Windows Server 2022 (or 2019) virtual machine, evaluation edition
- A single-DC forest, single domain: `lab.local`
- DNS hosted on the DC itself
- Root OU structure created (`IT`, `HR`, `Finance`, `Management`, `Service Accounts`,
  `Disabled Users`)
- ~31 seeded users with intentional IAM misconfigurations
- 5 custom groups, including 2 empty/orphan groups
- Cross-references to existing built-in groups (`Domain Admins`, `Backup Operators`,
  `Account Operators`)

---

## Safety note

This environment is intentionally vulnerable. **Do not connect the VM to a corporate
network or to any production Active Directory.** Use NAT or host-only networking only.
The seed script refuses to run against any domain other than `lab.local` unless you pass
`-Force`; that safety check exists precisely to prevent the lab personas from being
created in a real environment.

---

## Prerequisites

### Host machine

- 64-bit x86 or Apple Silicon (with x86 emulation)
- 8 GB host RAM minimum (16 GB comfortable)
- 80 GB free disk space
- Hardware virtualisation enabled (VT-x / AMD-V / Apple HVF)

### Hypervisor (choose one)

Any modern hypervisor works. The lab has been validated against:

| Hypervisor              | Notes |
|-------------------------|-------|
| VMware Workstation Pro  | Windows / Linux host, mature, paid |
| VMware Fusion           | macOS host, paid (free for personal use as of 2024) |
| Oracle VirtualBox       | Free, cross-platform, easiest for first-time users |
| Microsoft Hyper-V       | Built into Windows 10/11 Pro and Enterprise |
| UTM (Apple Silicon)     | Free, macOS-only, uses Apple Virtualization for ARM-native Windows |

If you have no preference, use **VirtualBox** on Windows/Linux or **UTM** on Apple
Silicon. The rest of this guide is hypervisor-agnostic — you create a VM, attach an
ISO, install Windows.

### Alternative — Azure VM (replaces Steps 1–4)

If you deploy the lab on Azure (or another public cloud), skip the ISO / VM-creation
steps and follow this section instead. Rejoin the guide at Step 5 once you can RDP into
Windows Server as the local admin.

**Recommended settings** (verified against Azure on 26 August 2026):

| Setting               | Value |
|-----------------------|-------|
| Image                 | *Windows Server 2022 Datacenter* from publisher **MicrosoftWindowsServer**. **Avoid** Azure Edition, Hotpatch, Server Core, and any *-smalldisk* variant. |
| VM size               | `Standard_D2als_v7` (2 vCPU, 4 GB RAM). The B-series is frequently `NotAvailableForSubscription` in France Central — do not rely on it. |
| Region                | Any that allows Windows Server. France Central works with the size above. |
| Local admin username  | Anything **except `Administrator`** — Azure forbids it. `labadmin` is a good pick. |
| Local admin password  | Anything satisfying the domain policy you will use later. Suggested: `LabAdmin!2026Demo`. |
| Public inbound ports  | RDP (3389) — restrict source IP to your workstation. |
| Virtual network       | New VNet, single subnet. Do NOT peer it to any production network. |
| Disk                  | Standard SSD, default 128 GB is fine. |

**Post-deploy configuration** (before jumping to Step 5):

1. **Do NOT fix the IP inside Windows.** On Azure, the NIC gets its IP from Azure
   DHCP. Setting a static IP inside Windows diverges from the platform view; the VM
   survives one reboot then loses RDP for good. Fix the IP in the portal instead:
   *Networking blade → Network interface → IP configurations → ipconfig1 → change
   Assignment from Dynamic to Static → Save.*
2. **DNS at the VNet level** (not inside Windows). For the DC to resolve `lab.local`
   after promotion, DNS must point at the DC itself:
   *Virtual network → DNS servers → Custom → add the VM's private IP → Save*, then
   **reboot the VM** so the DHCP lease is renewed. Do not use Windows'
   `Set-DnsClientServerAddress`.
3. **Local admin account and RID**. Because Azure forbids the name `Administrator`,
   the built-in admin is the account created at provisioning (in the example above,
   `labadmin`). Its RID is `-500` — same well-known Administrator SID suffix.
   Any detection script that filters on the account **name** would miss it. The
   toolkit filters on group membership and `adminCount`, so this is a non-issue for
   the shipped scripts; be aware if you extend them with name-based rules.

**Cost hygiene**:

- Stop the VM from the **Azure portal** (`Stop / Deallocate`), never from Windows.
  Shutting down inside Windows leaves the VM in the "Stopped" (still allocated)
  state and compute continues to bill.
- Once deallocated, only storage is charged (a few euros / month for the OS disk).

Rejoin the guide at **Step 5 — Install the Active Directory Domain Services role**.

---

## Step 1 — Download Windows Server ISO

1. Go to the Microsoft Evaluation Center: <https://www.microsoft.com/en-us/evalcenter/>.
2. Search for **Windows Server 2022** (or 2019 if you specifically need it).
3. Choose the ISO download (not VHD).
4. Register with a Microsoft account if prompted. The download is free, no product key
   required. The evaluation period is 180 days (renewable).
5. Save the ISO somewhere convenient. The file is ~5 GB and named something like
   `SERVER_EVAL_x64FRE_en-us.iso`.

---

## Step 2 — Create the virtual machine

Create a new VM with the following specifications. The values below are minimums for a
single-DC lab; double them if your host can spare the resources.

| Setting              | Value                                  |
|----------------------|----------------------------------------|
| Guest OS             | Windows Server 2022 (or 2019)          |
| vCPU                 | 2                                      |
| RAM                  | 4 GB (6 GB recommended)                |
| Disk                 | 60 GB, thin-provisioned                |
| Network adapter      | NAT *or* host-only — **never bridged** |
| Boot ISO             | the ISO from Step 1                    |
| Firmware             | UEFI                                   |
| Secure Boot          | Enabled (optional, off if it causes issues) |

Power on the VM and proceed with the Windows installer.

---

## Step 3 — Install Windows Server

When the installer launches:

1. **Language / region**: English (or your preference). Keyboard layout matters for the
   password you will set in Step 6 — pick one you can type reliably.
2. **Install now**.
3. **Select operating system**: choose **Windows Server 2022 Standard Evaluation (Desktop
   Experience)**. The Desktop Experience variant is much easier to navigate for first
   setup than Server Core.
4. **Accept the licence terms**.
5. **Custom: Install Windows only (advanced)**.
6. **Drive selection**: select the (single) unallocated disk, click **Next**.
7. Wait. Installation takes 5–15 minutes depending on your host.
8. The VM will reboot automatically. When it lands on the post-install screen, set the
   built-in `Administrator` password. **Write it down**. Suggested:
   `LabAdmin!2026Demo`.
9. Sign in with `Administrator` and the password you just set.

You should now see a Windows Server desktop with Server Manager auto-opened.

---

## Step 4 — Initial configuration

Perform these steps from the Windows desktop or via PowerShell as Administrator.

### 4a — Rename the host

Default name is something like `WIN-XXXXXXX`. Rename it to something sensible:

```powershell
Rename-Computer -NewName "DC01" -Restart
```

The VM reboots. Sign back in.

### 4b — Set a static IP

A domain controller must have a static IP and must point its own DNS at itself. Replace
`Ethernet0` with your actual adapter name (find it with `Get-NetAdapter`).

```powershell
# Inspect first
Get-NetAdapter
Get-NetIPAddress -AddressFamily IPv4

# Then set (adjust the addresses to your hypervisor's subnet)
New-NetIPAddress `
    -InterfaceAlias "Ethernet0" `
    -IPAddress      "192.168.56.10" `
    -PrefixLength   24 `
    -DefaultGateway "192.168.56.1"

# DNS must point to the DC itself (loopback is fine pre-promotion)
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses "127.0.0.1"
```

If you are on VirtualBox NAT, the gateway is usually `10.0.2.2` and the host gives the
VM `10.0.2.15`. On Hyper-V Default Switch, the subnet is dynamic — use NAT switch with a
fixed subnet for predictability.

If the static IP step is fiddly with your hypervisor, you can also use DHCP and rely on
the hypervisor's address pool, but a static IP is the documented best practice for a DC.

### 4c — (Optional) Apply Windows updates

```powershell
# Install the PSWindowsUpdate module to drive updates from PowerShell
Install-Module PSWindowsUpdate -Force
Import-Module PSWindowsUpdate
Get-WindowsUpdate -Install -AcceptAll -AutoReboot
```

This step is **optional for lab use**, takes 30–60 minutes, and is not required for the
detection scripts to function. Skip it if you want to get to seeding quickly.

---

## Step 5 — Install the Active Directory Domain Services role

From an elevated PowerShell prompt:

```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
```

You should see a success summary with `ExitCode = Success`, no reboot required.

The `-IncludeManagementTools` flag installs RSAT (the `ActiveDirectory` PowerShell
module the detection scripts depend on). Confirm:

```powershell
Get-Module -ListAvailable -Name ActiveDirectory
```

A module entry should be listed.

---

## Step 6 — Promote the server to a Domain Controller

This creates a new forest with a single domain `lab.local`. The DSRM password is the
recovery password if the DC's directory service ever fails to start — keep it,
**different from the local admin password**.

```powershell
Install-ADDSForest `
    -DomainName                    "lab.local" `
    -DomainNetbiosName             "LAB" `
    -InstallDNS `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "SafeMode!Lab2026" -AsPlainText -Force) `
    -DomainMode                    "WinThreshold" `
    -ForestMode                    "WinThreshold" `
    -NoRebootOnCompletion:$false `
    -Force
```

Expected behaviour:
- 5–10 minutes of work (schema setup, DNS install, replication initialisation).
- Several warnings about DNS delegation and best practices — these are normal for a
  standalone lab DC and can be ignored.
- The VM reboots automatically.

After the reboot, sign in as `LAB\Administrator` with the password from Step 3. The
domain `lab.local` is now live.

Verify:

```powershell
Get-ADDomain
Get-ADDomainController
```

Both commands should return the DC info, with `Forest = lab.local`,
`DNSRoot = lab.local`, `Name = DC01`.

---

## Step 7 — Create the root OU structure

The seed script will create its own sub-OUs (it creates `OU=IT`, `OU=HR`, etc.
directly under `DC=lab,DC=local`). The default `Users` and `Computers` containers are
left untouched.

You can either let the seed script create the OUs, or pre-create them now if you want
to apply specific delegations. To pre-create:

```powershell
$domainDN = (Get-ADDomain).DistinguishedName
foreach ($ou in 'IT', 'HR', 'Finance', 'Management', 'Service Accounts', 'Disabled Users') {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -SearchBase $domainDN -SearchScope OneLevel -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ou -Path $domainDN -ProtectedFromAccidentalDeletion $false
    }
}
```

The seed script is idempotent and will detect existing OUs.

---

## Step 8 — Take a snapshot

**Do this before seeding.** Snapshots are free and revert in seconds.

In your hypervisor:
- **VirtualBox**: Machine -> Take Snapshot. Name it `clean-dc-no-seed`.
- **Hyper-V**: right-click VM -> Checkpoint.
- **VMware**: VM menu -> Snapshot -> Take Snapshot.
- **UTM**: VM menu -> Save Snapshot.

This lets you iterate on the seed script or detection scripts without rebuilding the DC.

---

## Step 9 — Clone the IAM Toolkit and run the seed

From an elevated PowerShell prompt on the DC:

```powershell
# Install git if not already present
winget install --id Git.Git -e --source winget

# Clone the toolkit
cd C:\
git clone https://github.com/gabnougue/iam-toolkit.git
cd iam-toolkit

# Run the seed
.\lab\seed-test-users.ps1
```

Expected output: an upfront advisory that `lastLogonTimestamp` / `pwdLastSet` cannot
be backdated via LDAP (this is expected; see the seed's `.NOTES`), then a summary
block showing `UsersCreated = 31`, `OUsCreated = 6` (or `OUsExisting = 6` if you
pre-created them in Step 7), `GroupsCreated = 5`, `MembershipsAdded = 15`, and
zero warnings.

Re-run the script to verify idempotency — all counters should report `Existing` /
`Unchanged` on the second run.

---

## Step 10 — Force SDProp so adminCount propagates

The seed just added several users to protected groups (`Domain Admins`, `Backup
Operators`, `Account Operators`). Their `adminCount` attribute is set by the Security
Descriptor Propagator (SDProp) task, which runs on the PDC emulator every **60 minutes
of PDC uptime** — not calendar time. On a fresh lab whose DC has been up for less than
an hour (typical on a cloud VM that was just started), SDProp has not run yet, and
`Get-PrivilegedUsers.ps1` reports `AdminCount = $null` on every direct DA member.

Force SDProp immediately (Domain Admin required):

```powershell
$root = [ADSI]"LDAP://RootDSE"
$root.Put("runProtectAdminGroupsTask", 1)
$root.SetInfo()
```

Wait 10–30 seconds, then verify:

```powershell
Get-ADUser -Filter "MemberOf -like '*Domain Admins*'" -Properties adminCount |
    Select-Object SamAccountName, adminCount
```

Every direct DA member should now show `adminCount = 1`.

This same phenomenon occurs in production — right after a remediation that adds a user
to a protected group, right after a fresh compromise, or on a domain whose PDC has
recently rebooted. `Get-PrivilegedUsers.ps1` documents the caveat in its `.NOTES` and
its membership walk is authoritative regardless of `adminCount`, so a missed SDProp run
does not change the group membership listing — only the `AdminCount` column
prioritisation.

---

## Step 11 — Validate the lab

Run each detection script and confirm the row counts match the expectations in
[lab-scenarios.md](lab-scenarios.md#validation-walkthrough):

```powershell
mkdir C:\iam-toolkit\outputs -Force

.\scripts\powershell\Get-InactiveUsers.ps1        -IncludeNewlyCreated -OutputPath .\outputs\inactive.csv
.\scripts\powershell\Get-PrivilegedUsers.ps1      -OutputPath .\outputs\privileged.csv
.\scripts\powershell\Get-PasswordNeverExpires.ps1 -OutputPath .\outputs\pne.csv

# Sanity checks (measured against the 27 August lab run)
(Import-Csv .\outputs\inactive.csv).Count         # expect 28 — every enabled account. See NOTE below.
(Import-Csv .\outputs\privileged.csv).Count       # expect ~16
(Import-Csv .\outputs\pne.csv).Count              # expect 9
```

**NOTE on `inactive.csv = 28`.** Because `lastLogonTimestamp` cannot be backdated via
LDAP (it is owned by the SAM) and every seeded account has `whenCreated = today`, the
inactivity column matches the entire enabled surface in the lab. This is a symptom of
a non-discriminating criterion, not of a dormant estate — see the calibration note in
[lab-scenarios.md](lab-scenarios.md#a-criterion-that-matches-100-of-the-perimeter-is-not-a-criterion)
for the full explanation. In a real audit an inactivity column that returns 100% of
the perimeter tells you to switch to authentication logs, not to disable everyone.

Verify the cross-vector join (the top-of-report findings):

```powershell
$inactive   = Import-Csv .\outputs\inactive.csv
$privileged = Import-Csv .\outputs\privileged.csv
$pne        = Import-Csv .\outputs\pne.csv

$inactive |
    Where-Object { $privileged.SamAccountName -contains $_.SamAccountName } |
    Where-Object { $pne.SamAccountName        -contains $_.SamAccountName } |
    Select-Object SamAccountName, DisplayName, LastLogon, AdminCount
```

Expected output: **four rows**, `svc-backup`, `svc-legacy`, `svc-sql`,
`sysadmin-legacy`. Because the `Inactive` predicate matches the whole enabled surface,
this join reduces to `Privileged ∩ PNE`. If you see those four, the entire toolchain
is wired correctly.

---

## Troubleshooting

### `Get-ADDomain` returns "Unable to find a default server"

Your DNS settings probably do not point to the DC. Verify:

```powershell
Get-DnsClientServerAddress -InterfaceAlias "Ethernet0"
```

The first entry must be `127.0.0.1` (or the DC's IP). Re-apply Step 4b if needed.

### `Install-ADDSForest` rejects the DSRM password

The default complexity policy requires 7+ characters with three of four character
classes (upper/lower/digit/symbol). The example `SafeMode!Lab2026` meets it. If you
chose your own, increase its complexity.

### Seed script: "Refusing to seed: current domain 'X' is not 'lab.local'"

This is the safety check working as intended. Confirm `(Get-ADDomain).DNSRoot` returns
exactly `lab.local`. If it does and the check still fires, your shell is connected to a
different domain context — open a new elevated PowerShell on the DC itself.

### Seed script: single upfront warning about backdating

The current seed emits one advisory at the start explaining that `lastLogonTimestamp`
and `pwdLastSet` cannot be aged via LDAP (`lastLogonTimestamp` is SAM-owned;
`pwdLastSet` accepts only 0 and -1). This is expected and does not affect any of the
seed's successful operations — the affected accounts appear as never-authenticated in
`Get-InactiveUsers.ps1`, which is what the current lab scenarios assume. See the
seed's `.NOTES` and [lab-scenarios.md](lab-scenarios.md) for the calibrated narrative.

### `Get-PrivilegedUsers.ps1` returns `AdminCount = $null` on freshly added members

Expected until SDProp propagates — see **Step 10** above for the forcing procedure.
The membership rows themselves are correct; only the `AdminCount` column is empty.

### Detection scripts return zero rows for `inactive.csv` without `-IncludeNewlyCreated`

Expected behaviour. All seeded users have `whenCreated = today` because the
`whenCreated` AD attribute is schema-protected and cannot be backdated. The
`-IncludeNewlyCreated` switch bypasses the too-young filter for lab validation. See
[lab-scenarios.md, Scenario 7](lab-scenarios.md#scenario-7--too-young-account-negative-test)
for the full explanation.

### Time-related authentication failures (Kerberos clock skew)

Kerberos rejects requests with a clock skew greater than 5 minutes. If your VM's clock
drifts (common after host sleep/resume), fix it:

```powershell
w32tm /resync
```

---

## Resetting the lab

To start over, revert to the `clean-dc-no-seed` snapshot taken in Step 8 and re-run
Step 9. The seed script is idempotent so re-running it on a partially seeded state is
also safe.

To delete everything seeded but keep the DC, a cleanup script is **not** included in
this version of the toolkit. As a workaround, every seeded object has its `Description`
field starting with `[SEEDED-LAB]`, so the following one-liner removes them:

```powershell
# DESTRUCTIVE — review the matched objects with -WhatIf first
Get-ADUser  -Filter "Description -like '[SEEDED-LAB]*'" | Remove-ADUser  -Confirm:$false -WhatIf
Get-ADGroup -Filter "Description -like '[SEEDED-LAB]*'" | Remove-ADGroup -Confirm:$false -WhatIf
```

Remove the `-WhatIf` once you have confirmed the list. This will not delete the OUs
(create them empty is fine for re-seeding).

---

## What is intentionally NOT covered

The lab is the minimum environment needed to exercise the toolkit's three detection
scripts. The following are out of scope for Phase 1 and would be added if/when the
toolkit covers the corresponding detection:

- Additional domain controllers (would let you exercise `-AccurateMode` on
  `Get-InactiveUsers.ps1`)
- Domain trusts and Foreign Security Principals (would exercise the FSP handling in
  `Get-PrivilegedUsers.ps1`)
- Group Managed Service Accounts (requires `Add-KdsRootKey` and a second waiting
  period; would exercise the gMSA paths in `Get-InactiveUsers.ps1` and
  `Get-PasswordNeverExpires.ps1`)
- Active Directory Certificate Services (would exercise ADCS-related findings)
- Multiple sites and inter-site replication
- Fine-Grained Password Policies (PSOs)

These are candidates for a future lab expansion as the toolkit grows.
