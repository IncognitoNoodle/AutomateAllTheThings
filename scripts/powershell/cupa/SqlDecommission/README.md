# SqlDecommission (CUPA)

RFC-driven SQL Server decommission playbook (standalone + Always On).

## Quick start

```powershell
cd scripts\powershell\cupa\SqlDecommission

.\Invoke-SqlDecommission.ps1 -RFCNumber '45012' -PlanOnly
.\Invoke-SqlDecommission.ps1 -RFCNumber '45012'
.\Invoke-SqlDecommission.ps1 -RFCNumber '45012' -HostList '\\share\Decom\Wave1.xlsx'
```

## Layout

```
SqlDecommission/
├── Invoke-SqlDecommission.ps1      # entry (Verb-Noun)
├── README.md
├── config/
│   ├── defaults.ps1
│   └── hosts.csv
├── module/
│   ├── SqlDecom.psd1
│   ├── SqlDecom.psm1
│   ├── Public/                     # exported commands; file = function
│   └── Private/                    # internal helpers
├── docs/
│   ├── architecture.md
│   └── process.md
└── tests/
    └── SqlDecom.Tests.ps1
```

## Naming convention (PowerShell standard)

| Kind | Convention | Example |
|------|------------|---------|
| Entry / public script | `Verb-Noun.ps1` | `Invoke-SqlDecommission.ps1` |
| Public function file | Matches function | `Invoke-DecomPreflight.ps1` |
| Function | Approved Verb + PascalCase | `Invoke-DecomPreflight` |
| Parameter | PascalCase | `-SqlInstance`, `-HostList` |
| Module | PascalCase product | `SqlDecom.psd1` |
| Folders | `Public` / `Private` / `config` / `docs` / `tests` | |

## Docs

- [Architecture](docs/architecture.md)
- [Process](docs/process.md)

Org template: [`templates/PowerShellProject/`](../../../../templates/PowerShellProject/)
