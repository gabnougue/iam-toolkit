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

Expected output: a summary block showing `UsersCreated = 31`, `OUsCreated = 6` (or
`OUsExisting = 6` if you pre-created them in Step 7), `GroupsCreated = 5`,
`MembershipsAdded = ~12`, and `LastLogonBackdated = 7`.

Re-run the script to verify idempotency — all counters should report `Existing` /
`Unchanged` on the second run.

---

## Step 10 — Validate the lab

Run each detection script and confirm the row counts match the expectations in
[lab-scenarios.md](lab-scenarios.md#validation-walkthrough):

```powershell
mkdir C:\iam-toolkit\outputs -Force

.\scripts\powershell\Get-InactiveUsers.ps1        -IncludeNewlyCreated -OutputPath .\outputs\inactive.csv
.\scripts\powershell\Get-PrivilegedUsers.ps1      -OutputPath .\outputs\privileged.csv
.\scripts\powershell\Get-PasswordNeverExpires.ps1 -OutputPath .\outputs\pne.csv

# Sanity checks
(Import-Csv .\outputs\inactive.csv).Count         # expect ~10
(Import-Csv .\outputs\privileged.csv).Count       # expect ~10
(Import-Csv .\outputs\pne.csv).Count              # expect 9
```

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

Expected output: two rows, `svc-legacy` and `sysadmin-legacy`. If you see those two,
the entire toolchain is wired correctly.

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

### Seed script: backdating warnings on `lastLogonTimestamp`

The script writes `lastLogonTimestamp` directly via `Set-ADObject`. This requires
Domain Admin context. If you see warnings like `Access denied`, ensure you are running
as `LAB\Administrator` (which is `Domain Admin` by default in a fresh forest).

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
