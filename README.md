# IAM Toolkit

A practical toolkit to audit Identity and Access Management (IAM) risks in Active Directory environments.

It bundles three things:

- PowerShell scripts that detect common IAM misconfigurations in Active Directory
- A reproducible lab environment to simulate real-world scenarios end to end
- Clear documentation of the audit methodology and findings

The toolkit is built for IAM consultants, internal auditors, and sysadmins who need a quick, repeatable way to surface identity hygiene issues in an AD domain.

## What it detects

| Script | What it finds |
|---|---|
| `Get-InactiveUsers.ps1` | Enabled accounts with no recent logon activity |
| `Get-PrivilegedUsers.ps1` | Members (direct and nested) of sensitive AD groups |
| `Get-PasswordNeverExpires.ps1` | Accounts flagged with `PasswordNeverExpires` |

Each script outputs a CSV ready to be reviewed, filtered, or fed into a report.

## Repository layout

```
iam-toolkit/
├── scripts/
│   └── powershell/         # Audit scripts (PowerShell)
├── lab/                    # Reproducible AD lab + seeded test users
├── docs/                   # Audit methodology and findings
├── outputs/                # Sample CSV outputs (no real data, ever)
└── reports/                # Sample audit report
```

## Requirements

- Windows Server with the Active Directory PowerShell module (`RSAT-AD-PowerShell`)
- An account with read access to the directory
- PowerShell 5.1 or later

## Quick start

```powershell
# Find accounts inactive for more than 90 days
.\scripts\powershell\Get-InactiveUsers.ps1 -DaysInactive 90 -OutputPath .\outputs\inactive.csv

# List all members of sensitive groups, including nested
.\scripts\powershell\Get-PrivilegedUsers.ps1 -OutputPath .\outputs\privileged.csv

# Find enabled accounts with non-expiring passwords
.\scripts\powershell\Get-PasswordNeverExpires.ps1 -OutputPath .\outputs\pwd-never-expires.csv
```

Every script supports `-OutputPath` and ships with comment-based help (`Get-Help .\Get-InactiveUsers.ps1 -Full`).

## Lab environment

The `lab/` directory contains everything needed to spin up a Windows Server domain with intentionally flawed accounts, so the scripts can be run against a known-bad state.

- `lab/lab-setup.md` — VM specs, domain bootstrap, OU layout
- `lab/seed-test-users.ps1` — populates the domain with realistic IAM misconfigurations (idempotent)
- `lab/lab-scenarios.md` — the misconfiguration scenarios the lab simulates

## Documentation

- `docs/audit-methodology.md` — how to run a full audit pass and interpret results
- `docs/findings-examples.md` — example findings, severity, and remediation notes
- `reports/sample-audit-report.md` — a sample report produced from the lab

## Roadmap

- Phase 1 — Core PowerShell scripts, lab, and documentation
- Phase 2 — Python reporting wrapper, sample outputs, methodology guide
- Phase 3 — Polish, examples, and additional detection coverage

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes.
