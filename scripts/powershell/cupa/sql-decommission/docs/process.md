# CUPA SQL Server decommission — process

> Entry point: [`../invoke-sql-decommission.ps1`](../invoke-sql-decommission.ps1)  
> Architecture: [`architecture.md`](architecture.md)

RFC-driven decommission for CUPA SQL estates: host identity check, AG configuration backup, verified full backups, rename databases with an `_Decom_RFC{n}` suffix, clean Availability Group membership, and (for standalone) mark inventory inactive.

Run the orchestrator only — `module/private` helpers are not meant to be called directly.

## Layout

| Path | Role |
|------|------|
| `invoke-sql-decommission.ps1` | Entry point / orchestrator |
| `config/defaults.ps1` | Environment defaults + DB exclude list |
| `config/hosts.csv` | Default host list (ServerName + ExpectedIP) |
| `module/sql-decom.psd1` / `.psm1` | Module manifest + loader |
| `module/public/` | Exported pipeline commands |
| `module/private/` | Internal helpers (backup, IP check, AG config, …) |
| `tests/` | Pester stubs |

## Pipeline overview

```
-HostList path  (.csv or .xlsx)
    ServerName + ExpectedIP rows
    |
    v
[Resolve]  SQL connect (ICMP is soft warning only)
    |---- multi-AG? require -AvailabilityGroup or -AllAvailabilityGroups
    |
    +-- standalone list ----------+
    +-- AG units (all replicas) --+
                                  |
                                  v
                           [Preflight]
                     hostname DNS vs ExpectedIP
                     SQL connect every planned node
                     AG sync snapshot
                     write DecomPlan_RFC{n}.json
                                  |
                     hard failure? ---- abort (exit 2)
                                  |
                     -PlanOnly? ------- stop after plan
                                  |
                                  v
              +-------------------+-------------------+
              |                                       |
              v                                       v
     Branch A: Standalone                      Branch B: AG
     Phase1 backup+verify all                  Phase0 AG config backup (gate)
     Phase2 rename only if all OK              Phase1 backup+verify ALL DBs
                                               Phase2 detach/orphan/rename
                                               (skipped if Phase1 incomplete)
              |                                       |
              +-------------------+-------------------+
                                  |
                                  v
                         [Inventory update]
                         (standalone successes)
                                  |
                                  v
                     [Summary JSON + exit code]
```

## Host list file (`-HostList`)

Pass a **CSV or Excel (.xlsx)** file. Every row is a host to decommission — there is no separate `-Targets` list.

```powershell
# Default bundled list
.\invoke-sql-decommission.ps1 -RFCNumber '45012' -PlanOnly

# Explicit CSV / Excel path (or bare filename under module/ + config/)
.\invoke-sql-decommission.ps1 -RFCNumber '45012' -HostList '.\config\hosts.csv'
.\invoke-sql-decommission.ps1 -RFCNumber '45012' -HostList '\\share\Decom\Wave1.xlsx'
.\invoke-sql-decommission.ps1 -RFCNumber '45012' -HostList 'DecomHosts.csv'
```

Required columns (aliases accepted):

| Logical field | Accepted column names |
|---------------|----------------------|
| Server name | `ServerName`, `Hostname`, `Server`, `Name` |
| Expected IP | `ExpectedIP`, `IPAddress`, `IpAddress`, `IP` |

Example CSV:

```csv
ServerName,ExpectedIP
sresmsq400,10.119.40.16
srsclsq405,10.119.40.12
```

Excel (`.xlsx`) needs the **ImportExcel** module (`Install-Module ImportExcel -Scope CurrentUser`). Otherwise save the sheet as CSV.

### IP validation

During preflight, for every planned host (file row or discovered AG replica):

1. Look up `ExpectedIP` from the host list.
2. Forward DNS — resolved IPv4 list must contain `ExpectedIP`.
3. Reverse DNS of `ExpectedIP` — best-effort hostname confirm.

| Status | Meaning | Default action |
|--------|---------|----------------|
| `Ok` | Forward + reverse agree | Continue |
| `OkForwardOnly` | Forward matches, reverse unclear | Warning, continue |
| `Mismatch` / `DnsFailed` | Wrong IP or DNS failure | **Hard fail** (abort) |
| `MissingInventory` | Host not in file (e.g. AG replica outside the list) | Warning (hard fail if `-RequireHostInventory`) |

Overrides: `-SkipIpValidation`, `-ForceIpMismatch`.

## AG configuration backup

Before any AG database mutation, Branch B writes `AgConfig\` under the AG archive folder:

| File | Purpose |
|------|---------|
| `AG_Config_{Ag}.json` | Structured replicas, listeners, databases, seeding/routing |
| `AG_Config_{Ag}.txt` | Human-readable snapshot |
| `AG_Rollback_{Ag}.sql` | Rebuild script + commented `ADD DATABASE` list |

If any artifact is missing/empty or JSON fails to parse, **Phase 2 does not run**.

## Two-phase mutation (flawless-run safety)

### Standalone
1. Backup + on-disk verify every eligible DB.
2. If any backup fails → **no renames** for that server.
3. Rename only verified `BackedUp` databases.

### Availability Group
1. Export AG configuration (gate).
2. Backup + verify **all** AG databases on the primary.
3. If Phase 1 is incomplete → **no detach/rename**.
4. Only then: remove from AG → drop secondary orphans → rename on primary.
5. AG object + listener stay intact.

## Configuration

Edit `config\defaults.ps1`:

```powershell
$script:DecomInstanceSuffix    = '\SQL01'
$script:DecomArchiveBasePath   = '\\ucles.internal\DBArchive'
$script:DecomInventoryInstance = 'DBAPRDAG01\SQL01'
$script:DecomLogDir            = 'C:\Temp\DecomLogs'
$script:DecomHostListPath      = Join-Path $PSScriptRoot 'DecomHosts.csv'
$script:DecomExcludeDatabases  = @('SSISDB','distribution','ReportServer','ReportServerTempDB')
```

## Parameters

| Parameter | Purpose |
|-----------|---------|
| `-RFCNumber` | Mandatory RFC token (safe charset) |
| `-HostList` | CSV/XLSX path or filename (default: `config\hosts.csv`) |
| `-AvailabilityGroup` | Select AG(s) when instance has more than one |
| `-AllAvailabilityGroups` | Process every AG on multi-AG instances |
| `-ExcludeDatabase` | Extra DB names to skip |
| `-PlanOnly` | Resolve + preflight + plan; no mutations |
| `-SkipIpValidation` | Skip DNS vs ExpectedIP checks |
| `-RequireHostInventory` | Fail if a discovered AG replica is missing from the file |
| `-ForceIpMismatch` | Continue despite IP mismatch |
| `-WhatIf` / `-Confirm` | SupportsShouldProcess on mutating steps |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Backup/rename/AG mutate failures |
| 2 | Preflight hard failures (IP mismatch, SQL down, etc.) |
| 3 | Some hosts unreachable/unresolved (no other hard fail) |

## Examples

```powershell
cd scripts\powershell\cupa

# Plan every host in the default CSV
.\invoke-sql-decommission.ps1 -RFCNumber '45012' -PlanOnly

# Execute after reviewing DecomPlan_*.json
.\invoke-sql-decommission.ps1 -RFCNumber '45012'

# Different wave file
.\invoke-sql-decommission.ps1 -RFCNumber '45012' -HostList '\\share\Decom\RFC45012.xlsx'

# Multi-AG instance
.\invoke-sql-decommission.ps1 -RFCNumber '45012' `
  -HostList 'DecomHosts.csv' -AvailabilityGroup 'AG_APP' -WhatIf
```

## Outputs

Under archive share (or `N$` fallback) plus `C:\Temp\DecomLogs\`:

| Artifact | Contents |
|----------|----------|
| `ServerInfo.txt` | Server/replica + database inventory |
| `AgConfig\*` | AG JSON/TXT/SQL configuration backup |
| `*.bak` | Verified full backups |
| `DecomPlan_RFC{n}_*.json` | Preflight plan + IP results |
| `DecomManifest_RFC{n}_*.json` | Per-DB state machine for the run |
| `DecomSummary_RFC{n}_*.json` | Final summary |
| `Decom_RFC{n}_*.log` | Transcript |

## Safety notes

- ICMP ping is informational only; SQL connectivity decides reachability.
- IP mismatch aborts the run by default.
- Phase 2 never starts if Phase 1 (or AG config export) is incomplete.
- Databases already named `*_Decom_RFC*` and Config excludes are skipped.
- AG and listener are **not** dropped by this playbook.
