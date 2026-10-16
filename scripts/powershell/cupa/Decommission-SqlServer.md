# CUPA SQL Server decommission

RFC-driven decommission for CUPA SQL estates: host identity check, AG configuration backup, verified full backups, rename databases with an `_Decom_RFC{n}` suffix, clean Availability Group membership, and (for standalone) mark inventory inactive.

Run the orchestrator only — modules under `Common\` are not meant to be invoked directly unless you are debugging a single branch.

## Layout

| Path | Role |
|------|------|
| `Decommission-SqlServer.ps1` | Entry point / orchestrator |
| `Common\Config.ps1` | Environment defaults + DB exclude list |
| `Common\DecomHosts.csv` | **Source of truth** — hosts to decommission + ExpectedIP |
| `Common\Decom.Common.ps1` | Session, backup/verify, rename, rich AG config export, manifest |
| `Common\Decom.Resolve.ps1` | Classify targets (SQL connect is the hard gate) |
| `Common\Decom.Preflight.ps1` | IP validation, SQL checks, plan JSON |
| `Common\Decom.Standalone.ps1` | **Branch A** — two-phase standalone pipeline |
| `Common\Decom.AvailabilityGroup.ps1` | **Branch B** — two-phase AG pipeline |
| `Common\Decom.Inventory.ps1` | Mark successfully processed standalone servers inactive |

## Pipeline overview

```
Targets[]
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

## Host CSV = target list + IP check

`Common\DecomHosts.csv` is the single source of truth:

```csv
ServerName,ExpectedIP
sresmsq400,10.119.40.16
srsclsq405,10.119.40.12
...
```

- **Default:** process every `ServerName` in the CSV (no `-Targets` needed).
- **Optional `-Targets`:** filter to a subset; each name must exist in the CSV or the run throws.
- **`-HostsFile`:** point at a different CSV (same columns) for another wave/RFC.

During preflight, for every planned host (CSV target or discovered AG replica):

1. Look up `ExpectedIP` from the CSV (case-insensitive; FQDN matches on short name).
2. Forward DNS (`GetHostEntry`) — resolved IPv4 list must contain `ExpectedIP`.
3. Reverse DNS of `ExpectedIP` — best-effort confirm hostname (warning if forward OK but reverse does not).

| Status | Meaning | Default action |
|--------|---------|----------------|
| `Ok` | Forward + reverse agree | Continue |
| `OkForwardOnly` | Forward matches, reverse unclear | Warning, continue |
| `Mismatch` / `DnsFailed` | Wrong IP or DNS failure | **Hard fail** (abort) |
| `MissingInventory` | Host not in CSV (e.g. AG replica discovered outside the list) | Warning (hard fail if `-RequireHostInventory`) |

Overrides:

- `-SkipIpValidation` — skip the DNS vs ExpectedIP check
- `-ForceIpMismatch` — continue despite mismatch (dangerous)
- `-HostsFile <path>` — alternate CSV (targets + IPs)

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

## Order of operations

1. **Initialize** — config, host inventory, dbatools, transcript/manifest paths.
2. **Resolve** — SQL connect; classify standalone vs AG; expand replicas; multi-AG guard.
3. **Preflight** — IP identity, SQL on all nodes, AG health snapshot, plan JSON.
4. **Branch A / B** — two-phase pipelines (skipped with `-PlanOnly`).
5. **Inventory** — `Active = 0` for fully successful standalone servers only.
6. **Summary** — console + `DecomSummary_RFC{n}.json`; non-zero exit on failures.

## Standalone vs AG branching

| | Standalone (Branch A) | Availability Group (Branch B) |
|--|----------------------|-------------------------------|
| Detection | No AG on instance | AG(s) on instance; replicas via dbatools |
| Work scope | That one host | Primary + every secondary node |
| Config backup | ServerInfo.txt | Rich AgConfig JSON/TXT/SQL (gated) |
| Backup source | The standalone instance | Primary only |
| Cleanup | Rename after all backups OK | Remove from AG → drop orphans → rename |
| AG object | N/A | Left intact (listener too) |
| Inventory | Marked inactive on full success | Not marked inactive |

## Configuration

Edit `Common\Config.ps1`:

```powershell
$script:DecomInstanceSuffix    = '\SQL01'
$script:DecomArchiveBasePath   = '\\ucles.internal\DBArchive'
$script:DecomInventoryInstance = 'DBAPRDAG01\SQL01'
$script:DecomLogDir            = 'C:\Temp\DecomLogs'
$script:DecomHostsFile         = Join-Path $PSScriptRoot 'DecomHosts.csv'
$script:DecomExcludeDatabases  = @('SSISDB','distribution','ReportServer','ReportServerTempDB')
```

## Parameters

| Parameter | Purpose |
|-----------|---------|
| `-RFCNumber` | Mandatory RFC token (safe charset) |
| `-Targets` | Optional filter of CSV hosts (omit = entire CSV) |
| `-AvailabilityGroup` | Select AG(s) when instance has more than one |
| `-AllAvailabilityGroups` | Process every AG on multi-AG instances |
| `-HostsFile` | Alternate CSV (targets + ExpectedIP) |
| `-ExcludeDatabase` | Extra DB names to skip |
| `-PlanOnly` | Resolve + preflight + plan; no mutations |
| `-SkipIpValidation` | Skip DNS vs ExpectedIP checks |
| `-RequireHostInventory` | Fail if a discovered AG replica is missing from CSV |
| `-ForceIpMismatch` | Continue despite IP mismatch |
| `-WhatIf` / `-Confirm` | SupportsShouldProcess on mutating steps |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Backup/rename/AG mutate failures |
| 2 | Preflight hard failures (IP mismatch, SQL down, etc.) |
| 3 | Some targets unreachable/unresolved (no other hard fail) |

## Examples

```powershell
cd scripts\powershell\cupa

# 1) Plan every host in DecomHosts.csv (IP check included)
.\Decommission-SqlServer.ps1 -RFCNumber '45012' -PlanOnly

# 2) Execute the full CSV list after reviewing DecomPlan_*.json
.\Decommission-SqlServer.ps1 -RFCNumber '45012'

# Optional: only a subset of CSV rows
.\Decommission-SqlServer.ps1 -RFCNumber '45012' -Targets 'sresmsq400','srsclsq405'

# Multi-AG instance (still CSV-driven; filter if needed)
.\Decommission-SqlServer.ps1 -RFCNumber '45012' `
  -Targets 'srsclsq405' -AvailabilityGroup 'AG_APP'

# Dry-run mutations for one CSV host
.\Decommission-SqlServer.ps1 -RFCNumber '45012' -Targets 'suinfsq018' -WhatIf
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
