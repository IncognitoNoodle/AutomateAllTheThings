# CUPA SQL Server decommission

RFC-driven decommission for CUPA SQL estates: full backup, rename databases with an `_Decom_RFC{n}` suffix, clean Availability Group membership, and (for standalone) mark inventory inactive.

Run the orchestrator only — modules under `Common\` are not meant to be invoked directly unless you are debugging a single branch.

## Layout

| Path | Role |
|------|------|
| `Decommission-SqlServer.ps1` | Entry point / orchestrator |
| `Common\Config.ps1` | Environment defaults (archive share, instance suffix, inventory) |
| `Common\Decom.Common.ps1` | Session init, backup/rename helpers, summary |
| `Common\Decom.Resolve.ps1` | Classify each target as standalone or AG |
| `Common\Decom.Standalone.ps1` | **Branch A** — standalone server pipeline |
| `Common\Decom.AvailabilityGroup.ps1` | **Branch B** — AG pipeline across discovered replica nodes |
| `Common\Decom.Inventory.ps1` | Mark successfully processed standalone servers inactive |

## Pipeline overview

```
Targets[]
    |
    v
[Resolve] ---- ping + Connect-DbaInstance ----+
    |                                        |
    | has AG?                                | no AG
    v                                        v
 Branch B: Availability Group          Branch A: Standalone
    |                                        |
    | discover primary + replicas            | per server
    | reachability gate on ALL replicas      | backup -> rename
    |                                        |
    | per AG database:                       |
    |   backup (primary)                     |
    |   Remove-DbaAgDatabase                 |
    |   drop orphan on each secondary        |
    |   rename on primary                    |
    |                                        |
    | AG + listener LEFT INTACT              |
    |                                        |
    +------------------+---------------------+
                       |
                       v
              [Inventory update]
              (standalone successes only)
                       |
                       v
                   [Summary]
```

## Order of operations

1. **Initialize** — load config, ensure `dbatools`, start transcript under `C:\Temp\DecomLogs`.
2. **Resolve** — for each unique target:
   - Skip if unreachable or SQL connect fails.
   - If the instance belongs to an AG → queue that AG (primary + all replica names).
   - Otherwise → queue as standalone.
   - Deduplicate overlapping inputs (listener + node both passed → one AG unit).
   - Skip any AG that has an offline replica (safety).
3. **Branch A — Standalone** — for each standalone host:
   - Create archive folder `{server}_RFC{n}` (share or `\\server\N$\...` fallback).
   - Write `ServerInfo.txt` (instance + database inventory).
   - For each user database (skip already-renamed `*_Decom_RFC*`):
     - Full backup to archive; on failure retry to local `N$` path.
     - Rename to `{name}_Decom_RFC{n}`.
4. **Branch B — Availability Group** — for each valid AG:
   - Expand work to **all discovered replica nodes** (primary + secondaries).
   - Export AG rollback package (`AG_Config_*.txt`, `AG_Rollback_*.sql`).
   - Snapshot every replica + every AG database into `ServerInfo.txt`.
   - Per AG database:
     - Backup on **primary**.
     - Remove database from AG; poll until membership clears.
     - Drop the orphaned RESTORING copy on **each secondary**.
     - Rename on **primary**.
   - Leave the AG object and listener in place.
5. **Inventory** — set `Active = 0` on `dba_inv` for standalone servers that fully succeeded. AG replica nodes are not auto-deactivated (AG still exists).
6. **Summary** — processed / failed / unreachable + transcript path.

## Standalone vs AG branching

| | Standalone (Branch A) | Availability Group (Branch B) |
|--|----------------------|-------------------------------|
| Detection | No AG found on instance | First AG on instance; replicas discovered via dbatools |
| Work scope | That one host | Primary + every secondary node |
| Backup source | The standalone instance | Primary only |
| Cleanup | Rename only | Remove from AG → drop secondary orphans → rename primary |
| AG object | N/A | Left intact (listener too) |
| Inventory | Marked inactive on full success | Not marked inactive |

## Configuration

Edit `Common\Config.ps1` once per environment:

```powershell
$script:DecomInstanceSuffix    = '\SQL01'
$script:DecomArchiveBasePath   = '\\ucles.internal\DBArchive'
$script:DecomLocalBackupRoot   = 'N:\'
$script:DecomInventoryInstance = 'DBAPRDAG01\SQL01'
$script:DecomLogDir            = 'C:\Temp\DecomLogs'
```

If the archive share is offline, backups fall back to `\\{host}\N$\...`.

## Requirements

- Windows jump box with network access to targets and (ideally) the archive share
- **dbatools** (auto-installed for CurrentUser if missing)
- Rights to backup, rename, remove AG databases, drop secondary orphans, and update `dba_inv`
- ICMP / `Test-Connection` reachability to hosts being decommissioned

## Examples

```powershell
cd scripts\powershell\cupa

# Dry run
.\Decommission-SqlServer.ps1 -RFCNumber '45012' -Targets 'SQLDEV01' -WhatIf

# Standalone only
.\Decommission-SqlServer.ps1 -RFCNumber '45012' -Targets 'SQLDEV01'

# Mixed: AG seed/node + a standalone box
.\Decommission-SqlServer.ps1 -RFCNumber '45012' -Targets 'AGNODE1','SQLBOX02'

# Already-qualified instance name (suffix not appended)
.\Decommission-SqlServer.ps1 -RFCNumber '45012' -Targets 'SQLDEV01\SQL01'
```

## Outputs

Per target folder under the archive share (or `N$` fallback):

| Artifact | Contents |
|----------|----------|
| `ServerInfo.txt` | Server / replica metadata and database inventory at run start |
| `*.bak` (via Backup-DbaDatabase) | Full compressed/checksum/verified backups |
| `AG_Config_{AgName}.txt` | Replica + listener snapshot (AG branch only) |
| `AG_Rollback_{AgName}.sql` | Rebuild script for the AG (AG branch only) |

Transcript: `C:\Temp\DecomLogs\Decom_RFC{n}_{timestamp}.log`

## Safety notes

- Supports `-WhatIf` / `-Confirm` via `SupportsShouldProcess` on mutating steps.
- Databases already named `*_Decom_RFC*` are skipped.
- An AG with any unreachable replica is skipped entirely.
- Rename failures and backup failures are tracked per server/AG and listed in the summary for manual follow-up.
- AG and listener are **not** dropped by this playbook — only databases are removed from the group.
