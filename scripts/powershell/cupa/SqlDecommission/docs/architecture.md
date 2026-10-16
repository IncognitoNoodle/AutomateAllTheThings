# Architecture

## Why not a single `Common/` dump?

`Common/` should hold **cross-project** shared libraries only. A playbook’s resolve/preflight/AG/backup code is feature logic and belongs in a module with an explicit public API.

## Layout

```
SqlDecommission/
  Invoke-SqlDecommission.ps1   # thin entry
  config/                      # defaults + host inventory
  module/
    SqlDecom.psd1 / .psm1
    Public/                    # exported Verb-Noun commands
    Private/                   # internals
  docs/
  tests/
```

## Naming (best PowerShell practice)

| Layer | Rule |
|-------|------|
| Functions | Approved Verb + PascalCase Noun (`Invoke-DecomPreflight`) |
| Public files | **Same name as the function** (`Invoke-DecomPreflight.ps1`) |
| Parameters | PascalCase (`-HostList`) |
| Module | PascalCase (`SqlDecom`) |
| Folders | `Public`, `Private`, `config`, `docs`, `tests` |

Do **not** use camelCase or kebab-case for exported PowerShell commands/files.

## Dependency flow

```
Invoke-SqlDecommission.ps1
        │ Import-Module SqlDecom
        v
   SqlDecom.psm1
        │ . config/defaults.ps1
        │ . Private/*.ps1
        │ . Public/*.ps1
        v
   Public commands call Private helpers
```

## Shared code across playbooks

Put reusable libraries at repo level, e.g. `modules/SharedLogging/`, not inside one playbook’s Common folder.
