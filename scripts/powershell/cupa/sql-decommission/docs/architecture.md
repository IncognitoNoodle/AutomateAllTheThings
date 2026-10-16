# Architecture: why not a single `Common/` dump?

## Short answer

Putting **all** project code under `Common/` is **not** a production-grade practice.

`Common/` (or `shared/`) should hold **cross-project** utilities only — logging, credential helpers, SQL connection wrappers reused by many playbooks. A single decommission playbook’s resolve/preflight/AG/backup logic is **feature code**, not “common.”

## What was wrong with the previous layout

```
cupa/
  decommission-sql-server.ps1   # (was PascalCase entry)
  Common/                       # ← everything lived here
    Config.ps1
    Decom.Common.ps1
    Decom.Resolve.ps1
    ...
```

Problems:

1. **Semantic lie** — “Common” implied shared org libraries; it was really the whole app.
2. **No public/private boundary** — helpers and orchestration mixed; hard to know what callers may use.
3. **No module contract** — dot-sourcing leaked `$script:` state into the entry script accidentally.
4. **Weak onboarding** — new engineers cannot tell config vs entry vs reusable API vs internals.

## Target layout (applied)

```
sql-decommission/
  invoke-*.ps1          entry (thin)
  config/               environment + host list
  module/
    *.psd1 / *.psm1     versioned module surface
    public/             exported commands
    private/            internals
  docs/                 human docs
  tests/                Pester
```

This matches common enterprise PowerShell practice (similar to .NET: `src/`, public API vs internals) and PowerShell Gallery module norms (`Public/` / `Private/` + `.psd1`).

## Industry patterns we follow

| Concern | Placement |
|---------|-----------|
| Entry / orchestration | Root `invoke-*.ps1` (or `scripts/`) |
| Defaults / env | `config/` |
| Exported automation API | `module/public/` |
| Helpers | `module/private/` |
| Cross-playbook shared libs | Repo-level `modules/shared-*` (not inside one playbook’s Common) |
| Docs | `docs/` |
| Tests | `tests/` |

## Naming standard (this org)

- **Files & folders:** `lowercase-with-dashes` → `get-sql-database.ps1`, `sql-decom.psm1`
- **Functions:** PowerShell approved verbs + PascalCase → `Get-SqlDatabase`, `Invoke-DecomPreflight`
  - Reason: discoverability (`Get-Command -Noun Decom*`), PSScriptAnalyzer, Gallery norms
- **Variables:** `$script:Decom*` inside the module only; entry script uses return objects / exported setters

## Dependency flow

```
invoke-sql-decommission.ps1
        │ Import-Module
        v
   sql-decom.psm1
        │ loads config/defaults.ps1
        │ dotsources private/* then public/*
        v
   public commands call private helpers
```

No circular deps: private never imports public; entry never dotsources private files.

## When a `common/` folder *is* appropriate

At **repo** or **shared-module** level only, e.g.:

```
modules/
  shared-logging/
  shared-sql-connection/
  shared-credentials/
playbooks/
  sql-decommission/     # imports shared-* as needed
  sql-service-account/
```

Not as a junk drawer inside one playbook.
