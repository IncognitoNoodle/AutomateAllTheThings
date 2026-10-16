# sql-decommission (CUPA)

Production-layout PowerShell playbook for RFC-driven SQL Server decommission (standalone + Always On).

## Quick start

```powershell
cd scripts\powershell\cupa\sql-decommission

# Plan every host in config\hosts.csv
.\invoke-sql-decommission.ps1 -RFCNumber '45012' -PlanOnly

# Execute
.\invoke-sql-decommission.ps1 -RFCNumber '45012'

# Alternate host list
.\invoke-sql-decommission.ps1 -RFCNumber '45012' -HostList '\\share\Decom\Wave1.xlsx'
```

## Layout

```
sql-decommission/
├── invoke-sql-decommission.ps1     # entry point only
├── README.md
├── config/
│   ├── defaults.ps1                # environment defaults
│   └── hosts.csv                   # ServerName,ExpectedIP
├── module/
│   ├── sql-decom.psd1              # module manifest
│   ├── sql-decom.psm1              # loader
│   ├── public/                     # exported commands (one concern per file)
│   └── private/                    # internal helpers (not exported)
├── docs/
│   ├── architecture.md             # why this layout
│   └── process.md                  # operational runbook
└── tests/
    └── sql-decom.tests.ps1         # Pester stubs
```

## Naming

| Layer | Convention | Example |
|-------|------------|---------|
| Folders / files | `lowercase-with-dashes` | `invoke-decom-preflight.ps1` |
| Exported functions | Approved Verb + PascalCase | `Invoke-DecomPreflight` |
| Module | `lowercase-with-dashes` | `sql-decom.psm1` |

## Docs

- [Architecture](docs/architecture.md) — Common vs module/public/private
- [Process](docs/process.md) — operational pipeline, IP checks, two-phase AG/standalone

## Org template

Clone new playbooks from [`templates/powershell-project/`](../../../templates/powershell-project/).
