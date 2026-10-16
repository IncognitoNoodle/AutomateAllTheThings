# PowerShellProject template (org standard)

Master skeleton for modular, production-grade PowerShell playbooks.

Copy this folder, rename `Sample*` artifacts, and follow the naming table below.

## Hierarchy

```
<ProjectName>/
├── README.md
├── Invoke-<ProjectName>.ps1        # thin entry (Verb-Noun)
├── config/
│   └── defaults.ps1
├── module/
│   ├── <ModuleName>.psd1
│   ├── <ModuleName>.psm1
│   ├── Public/                     # file name = function name
│   │   └── Invoke-SampleAction.ps1
│   └── Private/
│       └── Format-SampleMessage.ps1
├── docs/
│   └── architecture.md
└── tests/
    └── <ModuleName>.Tests.ps1
```

## Naming convention (best PowerShell practice)

| Kind | Rule | Example |
|------|------|---------|
| Entry script | `Verb-Noun.ps1` | `Invoke-SampleProject.ps1` |
| Public script | Matches function | `Invoke-SampleAction.ps1` |
| Function | Approved Verb + PascalCase | `Invoke-SampleAction` |
| Parameter | PascalCase | `-SqlInstance` |
| Module | PascalCase | `SampleModule.psd1` |
| Folders | `Public` / `Private` / `config` / `docs` / `tests` | |
| Pester | `<Module>.Tests.ps1` | `SampleModule.Tests.ps1` |

Avoid kebab-case or camelCase for exported PowerShell commands and their script files.

## What belongs where

| Location | Contents |
|----------|----------|
| `config/` | Paths, timeouts, inventories — no secrets |
| `module/Public/` | Commands operators/CI may call |
| `module/Private/` | Helpers not part of the public API |
| Repo `modules/Shared*` | Cross-playbook libraries |

**Do not** put an entire playbook under `Common/`.

## Production checklist

- [ ] `[CmdletBinding()]` + validation on public commands
- [ ] `SupportsShouldProcess` for mutating commands
- [ ] Transcript / structured logs via config defaults
- [ ] Secrets via SecretManagement / CI — never committed
- [ ] Non-zero exit codes from the entry script
- [ ] Pester + PSScriptAnalyzer in CI

## Reference implementation

[`scripts/powershell/cupa/SqlDecommission/`](../../scripts/powershell/cupa/SqlDecommission/)
