# PowerShell project template (org standard)

Master skeleton for modular, production-grade PowerShell playbooks/modules.

Copy this folder to start a new project, then rename `sample-*` artifacts.

## Standard hierarchy

```
<project-name>/
├── README.md
├── invoke-<project-name>.ps1       # thin entry only
├── config/
│   └── defaults.ps1                # env defaults (no secrets in git)
├── module/
│   ├── <project-name>.psd1
│   ├── <project-name>.psm1
│   ├── public/                     # exported commands
│   │   └── invoke-sample-action.ps1
│   └── private/                    # internal helpers
│       └── format-sample-message.ps1
├── docs/
│   └── architecture.md
├── tests/
│   └── <project-name>.tests.ps1
└── scripts/                        # optional one-off ops scripts
```

## Naming rules

| Kind | Rule | Example |
|------|------|---------|
| Folders / files | lowercase + dashes | `invoke-backup-job.ps1` |
| Module files | lowercase + dashes | `sql-maintenance-module.psm1` |
| Functions | Approved Verb + PascalCase | `Invoke-BackupJob` |
| Parameters | PascalCase | `-SqlInstance`, `-HostList` |
| Script variables (module) | `$script:Project*` prefix | `$script:DecomLogDir` |

> File name ≈ function purpose: `get-sql-database.ps1` contains `function Get-SqlDatabase`.

## What belongs where

| Put here | Examples |
|----------|----------|
| `config/` | paths, timeouts, exclude lists, host inventories |
| `module/public/` | commands operators/CI may call |
| `module/private/` | backup helpers, parsers, internal validators |
| `docs/` | runbooks, architecture |
| `tests/` | Pester |
| Repo `modules/shared-*` | logging, credentials, cross-playbook SQL helpers |

**Do not** put an entire playbook under `Common/`. Reserve common/shared for multi-project reuse.

## Production checklist

- [ ] `[CmdletBinding()]` + parameter validation on public commands
- [ ] `-WhatIf` / `-Confirm` via `SupportsShouldProcess` for mutating commands
- [ ] Transcript or structured log path under `config` defaults
- [ ] Secrets via Credential Manager / SecretManagement / CI secret store — never committed
- [ ] Non-zero exit codes from the entry script
- [ ] Pester smoke tests for exported surface
- [ ] CI: PSScriptAnalyzer + Pester on Windows agents

## Reference implementation

See [`scripts/powershell/cupa/sql-decommission/`](../../scripts/powershell/cupa/sql-decommission/).
