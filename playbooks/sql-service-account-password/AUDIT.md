# Playbook audit

Living audit of `playbooks/sql-service-account-password`. Updated 2026-10-05 after production failures (IComparable on validate, SQL Agent restart, password apply).

## Structural decisions

| Topic | Verdict |
|-------|---------|
| `.psm1` vs `.ps1` | **`.ps1`** - ops runbook, not a published module |
| One vs many scripts | **5 stage scripts** + shared Common + Config |
| Apply vs restart | **Separated** (03 vs 04) - main production recovery lesson |

## Issues found and fixed (2026-08-24)

| # | Severity | Script | Issue | Fix |
|---|----------|--------|-------|-----|
| 1 | High | Common | Used `.psm1` + `Export-ModuleMember` for a folder runbook | Converted to `.ps1` |
| 2 | High | 04 | Pre-restart AD poll every **60s** (lockout risk) | Default poll **300s** |
| 3 | High | 02/03 | Sentinel timeout `= 0` with `ValidateRange` would throw on parse | Real defaults 300 / 3600 / 300 |
| 4 | Medium | 04 | `-FailbackOnly` only read discovery | Also reads `04-restart-latest.json`; `-OriginalPrimary` |
| 5 | Medium | All | OutputFolder hard to configure | `Common\Config.ps1` |
| 6 | Medium | 01/05 | Duplicated finding list logic | `Add-SsaFinding` / `Show-SsaFindings` |
| 7 | Medium | 04 | Large inline AG restart block | `Invoke-SsaGracefulAgRestart` |
| 8 | Low | 02/03/04 | No durable checkpoint | `*-latest.json` stage state |
| 9 | Low | 01 | Critical findings only warned | `-FailOnCritical` |
| 10 | Low | 03/04 | AD unlock needs RSAT | `Import-SsaDependencies -PreferActiveDirectory` |
| 11 | Low | 04 | Types rediscovered every time | Prefers `TypesTouched` from `03-apply-latest.json` |

## Issues found and fixed (2026-10-05)

| # | Severity | Script | Issue | Fix |
|---|----------|--------|-------|-----|
| 12 | **Critical** | Common / 01 / 05 | `Show-SsaFindings` piped `Format-Table` into the success stream. `$critCount = Show-SsaFindings` then `$critCount -gt 0` threw **`NotIcomparable` / `FormatStartData`** (exactly the validate error). | `Format-Table \| Out-Host`; return `[int]` count only. Stages cast `[int](Show-SsaFindings ...)`. |
| 13 | **High** | Common | `Restart-DbaService -Type Engine,Agent` together: Agent hits **dependent service** / StartPending while Engine is down; treated as auth failure -> useless AD unlock retries; Agent left stopped. | Restart **one type at a time** in order **Engine -> Agent -> SSRS -> SSIS**; wait Running after each; dependency failures retry without AD unlock. |
| 14 | **High** | Common / 03 | Bulk `Update-DbaServiceAccount` on Engine+Agent could return **empty/partial** results; no WinRM name fallback - password looked "applied" or failed opaquely; Agent often still on old password. | Update **per service** (Engine first); WinRM target retry like restart; synthesize Failed rows; stage 03 requires one success per service. |
| 15 | Medium | 01 / 05 | `Sort-Object ... ServiceType` on dbatools enum objects can also trip non-IComparable compares under `$ErrorActionPreference Stop`. | Project `[string]` ServiceType/State before sort/format. |
| 16 | Medium | All | Em dashes / arrows in `.ps1` strings showed as mojibake on Windows PowerShell (UTF-8 misread as Windows-1252). | Replaced with ASCII `-` / `->` / `...` across playbook scripts and docs. |
| 17 | **High** | 01 / Common | Discover treated Stopped Engine/Agent and expired passwords as Critical and required live SQL - blocked return-to-service when VMs powered on with expired accounts. | Stopped services = Info; expired/locked = Warning -> stage 02. `-ComputerName` / SQL-unreachable offline topology via WinRM. Stage 04 skips AG failover while Offline. |

### Root cause of the validate crash

```text
Cannot compare "Microsoft.PowerShell.Commands.Internal.Format.FormatStartData"
because it is not IComparable.
FullyQualifiedErrorId : NotIcomparable,05-Validate-Health.ps1
```

When stage 05 found Critical issues (e.g. Agent not Running), `Show-SsaFindings` emitted Format-* objects **and** the integer count into `$critCount`. Comparing that array with `-gt 0` compared `FormatStartData` -> terminating error, masking the real findings.

### SQL Agent restart

Agent depends on Engine. Restarting both in one `Restart-DbaService` call often returns Agent Failed / not Running. Old logic matched `dependent service` as auth failure and ran AD unlock + 5-minute waits instead of waiting for Engine. Fix: ordered single-type restarts + readiness wait + dependency vs auth split.

### Password did not apply

Stage 03 now fails closed if any service on a node is missing from Update results, logs per-service Status, and retries WinRM computer names the same way restart does.

## Residual risks (accepted)

- Live SQL/AD/WinRM not executable in this Linux cloud agent - static audit + logic review only.
- `setspn.exe` / RSAT / dbatools required on the Windows jump box.
- Keep node AD poll intervals >= 5 minutes to avoid lockouts.
- Async AG replicas report `Synchronizing` (treated as OK).

## Recommended run order

`01 -> 02 -> 03 -> 04 -> 05` - resume from last successful stage after failure.

If Agent is still down after a bad run: re-run **03** (confirm apply), then **04** with `-Account`/`-SecurePassword`, then **05**.
