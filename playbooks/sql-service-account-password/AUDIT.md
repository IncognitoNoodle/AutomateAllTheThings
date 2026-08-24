# Playbook audit (2026-08-24)

Audit of `playbooks/sql-service-account-password` after converting Common to dot-sourced `.ps1` and optimizing stages.

## Structural decisions

| Topic | Verdict |
|-------|---------|
| `.psm1` vs `.ps1` | **`.ps1`** — ops runbook, not a published module. Stages: `. (Join-Path $PSScriptRoot 'Common\SqlServiceAccount.Common.ps1')` |
| One vs many scripts | **5 stage scripts** + shared Common + Config. Process is not monolithic; Common is shared library only. |
| Apply vs restart | **Separated** (03 vs 04) — main production recovery lesson. |

## Issues found and fixed

| # | Severity | Script | Issue | Fix |
|---|----------|--------|-------|-----|
| 1 | High | Common | Used `.psm1` + `Export-ModuleMember` for a folder runbook | Converted to `.ps1`, removed export |
| 2 | High | 04 | Pre-restart AD poll every **60s** (lockout risk) | Default poll **300s** (matches production) |
| 3 | High | 02/03 | Sentinel timeout `= 0` with `ValidateRange(30,…)` would **throw on parse** | Real defaults 300 / 3600 / 300 |
| 4 | Medium | 04 | `-FailbackOnly` only read discovery; fragile after failover | Also reads `04-restart-latest.json`; new `-OriginalPrimary` |
| 5 | Medium | All | OutputFolder duplicated / hard to configure | Single editable `Common\Config.ps1` |
| 6 | Medium | 01/05 | Duplicated finding list logic | `Add-SsaFinding` / `Show-SsaFindings` |
| 7 | Medium | 04 | Large inline AG restart block | `Invoke-SsaGracefulAgRestart` in Common |
| 8 | Low | 02/03/04 | No durable checkpoint between stages | `Save-SsaStageState` → `02-ad-latest.json`, `03-apply-latest.json`, `04-restart-latest.json`, `05-validate-latest.json` |
| 9 | Low | 01 | Critical findings only warned | `-FailOnCritical` for gated pipelines |
| 10 | Low | 03/04 | AD unlock needs RSAT but stages didn't soft-load AD | `Import-SsaDependencies -PreferActiveDirectory` |
| 11 | Low | 04 | Types to restart rediscovered every time | Prefers `TypesTouched` from `03-apply-latest.json` |
| 12 | Info | 02 | Node list resolution duplicated | `Resolve-SsaNodeList` (ComputerName → discovery → topology) |

## Per-script audit summary

### `Common/Config.ps1`
- Single place for OutputFolder + service types + default AD poll timings.
- Edit this before first run in a new environment.

### `Common/SqlServiceAccount.Common.ps1`
- Dot-sourced helpers only (no module manifest).
- Retains production-hardened WinRM/DNS/AG/AD wait logic.
- New: findings helpers, node resolve, stage state, AG failover/restart wrappers.

### `01-Discover-ServiceAccounts.ps1`
- Read-only; AG-aware; SPN via `setspn -L` with AD fallback.
- Findings cover service state, AD lock/expiry, missing MSSQLSvc SPNs, AG replica count.
- Writes `discovery-latest.json`.

### `02-Reset-AdPassword.ps1`
- Reset / unlock / never-expire (default on) / mgmt + node AD wait.
- `-WaitOnly` for SecOps-owned resets; `-RequireNodes` to refuse mgmt-only waits.
- Writes `02-ad-latest.json`.

### `03-Apply-ServicePassword.ps1`
- `Update-DbaServiceAccount -NoRestart` on all nodes first (lockout-safe).
- Re-validates AD after apply; refuses stage 04 guidance on failure.
- Writes `03-apply-latest.json` including `TypesTouched`.

### `04-Restart-Services.ps1`
- Standalone restart or AG graceful path; failback **off** by default.
- AD gate before restart uses slow poll.
- Checkpoints primary movement for later `-FailbackOnly`.

### `05-Validate-Health.ps1`
- Services + AD + SPN + AG DB sync/health.
- Exit 1 on any Critical finding; writes `05-validate-latest.json`.

## Residual risks (accepted)

- Live SQL/AD/WinRM not executable in this cloud agent Linux environment — scripts are static-audited only.
- `setspn.exe` / RSAT / dbatools must exist on the Windows jump box.
- Aggressive third-party tools outside this playbook can still lock accounts; keep poll intervals ≥ 5 minutes on nodes.
- Async AG commit replicas report `Synchronizing` (treated as OK).

## Recommended run order (unchanged)

`01 → 02 → 03 → 04 → 05` — resume from last successful stage after failure.
