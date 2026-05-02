# Contributing

Thanks for considering a contribution to IAM Toolkit. This document covers what kinds of changes are in scope, how the codebase is organized, and the conventions to follow when submitting a patch.

## Scope

The toolkit intentionally stays narrow: detect common IAM misconfigurations in Active Directory, ship a reproducible lab to validate them, and document the audit methodology.

In scope:

- Bug fixes and reliability improvements to the existing scripts
- Better documentation, examples, and lab scenarios
- New AD-focused detections that fill a clear gap (open an issue first)
- Improvements to the lab environment and seeded test data

Out of scope (for now):

- Web UI, dashboards, or SaaS features
- Entra ID / Azure AD, ADFS, or federation coverage
- Vendor-specific IGA integrations

If you are unsure whether an idea fits, open an issue describing the use case before writing code.

## Reporting issues

When reporting a bug, please include:

- Script name and version (commit SHA if possible)
- PowerShell version (`$PSVersionTable.PSVersion`)
- Domain/forest functional level, if relevant
- Exact command you ran and the full error message
- What you expected to happen

Do not include real account names, SIDs, or any data extracted from a production directory. Reproduce the issue against the lab in `lab/` whenever possible.

## Pull requests

1. Open an issue first for anything beyond a small fix, so we can agree on the approach.
2. Keep pull requests focused — one logical change per PR.
3. Update or add documentation alongside code changes.
4. Make sure scripts run cleanly against the lab (`lab/seed-test-users.ps1`) before submitting.

## Code conventions

### PowerShell

- Use `Verb-Noun` naming, with approved verbs (`Get-Verb`)
- Every script must include comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`)
- Use `[CmdletBinding()]` and a typed `param()` block
- No hardcoded domain names, thresholds, or group names — expose them as parameters
- Default output is CSV; every script must accept `-OutputPath`
- Wrap directory queries in `try/catch` and surface meaningful error messages — never fail silently
- Prefer the `ActiveDirectory` module over LDAP queries unless there is a clear reason

### Documentation

- All code, comments, and documentation in English
- Professional tone, no marketing fluff, no emojis in docs
- Reference scripts and files with relative paths

### Data hygiene

- Never commit real AD data (account names, SIDs, group memberships, exports)
- Sample outputs go in `outputs/sample-results/` and must come from the lab only
- Treat the lab as the source of truth for examples, screenshots, and report samples

## Lab changes

If your change touches `lab/seed-test-users.ps1` or the lab setup:

- The seed script must remain idempotent — running it twice should not duplicate users or error out
- Update `lab/lab-setup.md` and `lab/lab-scenarios.md` to reflect the new state
- Document any new misconfiguration scenario you introduce, including how the detection scripts should respond

## License

By contributing, you agree that your contributions will be licensed under the MIT License (see [LICENSE](LICENSE)).
