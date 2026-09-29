# Azure SQL Database (PaaS) Health Check — Senior Cloud DBA Playbook

Operational health check for **Azure SQL Database** and **elastic pools** (single DB / elastic pool / Hyperscale). This is **not** for SQL Server on Azure VM (IaaS) and only partially applies to Managed Instance.

**Companion script:** `scripts/database/mssql/cloud/03_azure_sql_database_health_check.sql`

---

## Scope and mental model

Azure SQL Database is PaaS: Microsoft owns OS, storage fabric, and patching. Your job is **service SLO + workload + config + recoverability + security**, not disk/SQL Agent/OS.

| You own | Microsoft owns |
|---------|----------------|
| DTU/vCore SKU, max size, elastic pool mix | Host OS, storage, patching |
| Query Store / indexes / stats / app SQL | Physical backups (PITR) |
| Firewall / Private Link / Entra auth | Control plane / fabric HA |
| Geo-replication / failover groups / LTR | Zone-redundant infrastructure (when enabled) |
| Auditing, Defender, RLS, secrets | Certificate rotation for TDE service-managed keys |

**Two complementary approaches (use both):**

1. **Control-plane + Azure Monitor** — Resource Health, metrics, alerts, backups, networking, Defender. Best for fleet scale and paging.
2. **Data-plane T-SQL** — `sys.dm_db_resource_stats`, waits, Query Store, blocking, storage. Best for root cause inside one database.

Do not rely on on-prem scripts that use SQL Agent, `xp_readerrorlog`, or instance-level DMVs that do not exist in Azure SQL Database.

---

## Cadence

| Cadence | Focus |
|---------|--------|
| **Continuous** | Azure Monitor alert rules (CPU, workers, storage, failed connections, geo-lag) |
| **Daily (15–30 min)** | Sections 1–6 below for prod / business-critical DBs |
| **Weekly** | Automatic Tuning / index recommendations, Query Store regressions, elastic pool density |
| **Monthly** | Capacity/SKU right-size, LTR restore drill, security posture, geo-failover dry-run |
| **Quarterly** | RPO/RTO tabletop, private endpoint / firewall review, encryption key (CMK) rotation check |

---

## Daily health check (ordered)

### 1. Service & Resource Health (control plane)

**Goal:** Separate Azure platform incidents from your workload.

- [ ] Azure Service Health — subscription / region incidents for SQL
- [ ] Resource Health on each server/database — Available / Degraded / Unavailable
- [ ] Recent Azure Activity Log — unexpected SKU changes, firewall rule edits, delete/lock removals

```bash
# Resource Health (Azure CLI)
az resource health show \
  --resource-id "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Sql/servers/<server>/databases/<db>"

# Recent control-plane changes
az monitor activity-log list \
  --resource-group <rg> \
  --offset 24h \
  --query "[?contains(resourceId, 'Microsoft.Sql')].{time:eventTimestamp, op:operationName.value, status:status.value, caller:caller}" \
  -o table
```

**Escalate if:** Resource Health ≠ Available, or unexplained `Write` ops on SQL resources overnight.

---

### 2. Connectivity & authentication

- [ ] Can connect with preferred auth (Entra ID preferred; SQL auth only if required)
- [ ] Public access vs Private Endpoint matches design; deny-public if Private Link is intended
- [ ] Firewall: only expected IPs / VNets; Azure services rule intentional
- [ ] Entra admin set on logical server; apps use managed identity where possible

```bash
az sql server show -g <rg> -n <server> --query "{publicNetworkAccess:publicNetworkAccess, minimalTlsVersion:minimalTlsVersion}"
az sql server firewall-rule list -g <rg> -s <server> -o table
az sql server vnet-rule list -g <rg> -s <server> -o table
az network private-endpoint-connection list -g <rg> --name <server> --type Microsoft.Sql/servers -o table
```

**Escalate if:** Spike in failed connections metric, TLS &lt; 1.2, public exposure on a private-only design.

---

### 3. Capacity & resource governance (data plane + metrics)

**Primary DMV (last hour, ~15s samples):** `sys.dm_db_resource_stats`  
**Portal / Monitor metrics:** `cpu_percent`, `physical_data_read_percent`, `log_write_percent`, `workers_percent`, `sessions_percent`, `storage_percent`, `connection_successful` / `connection_failed`, `deadlock`

Checklist:

- [ ] Avg and max **CPU / data IO / log write** &lt; sustained alert thresholds (typical warn 80%, critical 95% for 15–30+ min)
- [ ] **Workers %** and **sessions %** not climbing toward 100% (throttling / login failures)
- [ ] **Storage %** headroom for growth + index rebuilds (warn ~80–85%, plan scale before 90%+)
- [ ] Elastic pool: pool CPU/IO/eDTU not hot while one noisy DB starves others (`sys.elastic_pool_resource_stats` from `master` on the logical server)

```sql
-- Run in user database (see companion script for full pack)
SELECT TOP 12
    end_time,
    avg_cpu_percent,
    avg_data_io_percent,
    avg_log_write_percent,
    avg_memory_usage_percent,
    max_worker_percent,
    max_session_percent,
    avg_dtu_percent          -- NULL on vCore; useful on DTU
FROM sys.dm_db_resource_stats
ORDER BY end_time DESC;
```

```bash
az monitor metrics list \
  --resource "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Sql/servers/<server>/databases/<db>" \
  --metric cpu_percent storage_percent workers_percent \
  --interval PT5M --aggregation Average Maximum \
  --start-time $(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ)
```

**Actions when hot:**

| Symptom | First moves |
|---------|-------------|
| CPU high, IO low | Top Query Store CPU queries; missing indexes / plan regressions; scale vCore only after proof |
| Data IO high | Large scans, missing indexes, under-provisioned storage throughput; Hyperscale vs General Purpose trade-offs |
| Log write high | Large transactions, index rebuilds, bulk loads; batch size / minimal logging patterns |
| Workers/sessions high | Connection leaks, no pooling, blocking storms |
| Storage high | Purge/archive, shrink only with care, raise max size / tier |

---

### 4. Performance & concurrency

- [ ] Query Store ON (`READ_WRITE`); review **regressed queries** (last 24h / 7d)
- [ ] No long blocking chains; no deadlock storms
- [ ] Wait stats: dominate waits make sense (`SOS_SCHEDULER_YIELD`, `PAGEIOLATCH_*`, `WRITELOG`, `LCK_*`, `RESOURCE_GOVERNOR*` / Azure-specific)
- [ ] Automatic Tuning: review recommendations; prefer **Create/Drop Index** and **Force Plan** with monitoring in prod

```sql
-- Regressed queries (Query Store) — last 24 hours
SELECT TOP 20
    q.query_id,
    qt.query_sql_text,
    rs1.avg_duration / 1000.0 AS avg_duration_us_recent,
    rs2.avg_duration / 1000.0 AS avg_duration_us_baseline,
    (rs1.avg_duration - rs2.avg_duration) * 100.0 / NULLIF(rs2.avg_duration, 0) AS pct_worse
FROM sys.query_store_query_text qt
JOIN sys.query_store_query q ON qt.query_text_id = q.query_text_id
JOIN sys.query_store_plan p ON q.query_id = p.query_id
JOIN sys.query_store_runtime_stats rs1 ON p.plan_id = rs1.plan_id
JOIN sys.query_store_runtime_stats_interval rsi1 ON rs1.runtime_stats_interval_id = rsi1.runtime_stats_interval_id
JOIN sys.query_store_runtime_stats rs2 ON p.plan_id = rs2.plan_id
JOIN sys.query_store_runtime_stats_interval rsi2 ON rs2.runtime_stats_interval_id = rsi2.runtime_stats_interval_id
WHERE rsi1.start_time >= DATEADD(hour, -24, SYSUTCDATETIME())
  AND rsi2.start_time >= DATEADD(day, -8, SYSUTCDATETIME())
  AND rsi2.start_time < DATEADD(day, -1, SYSUTCDATETIME())
ORDER BY pct_worse DESC;
```

Also use Portal **Query Performance Insight** and companion script sections for blocking / top waits.

---

### 5. High availability & disaster recovery

| Feature | What to verify |
|---------|----------------|
| **Zone redundancy** | Enabled where SLA requires it (Premium/Business Critical / supporting tiers) |
| **Active geo-replication** | Secondaries ONLINE; replication lag acceptable vs RPO |
| **Failover groups** | Listener reachable; read/write & read-only endpoints correct; grace period understood |
| **PITR** | Retention meets RPO (1–35 days by tier); note earliest restore point |
| **LTR** | Policies present for weekly/monthly/yearly if compliance requires; test restore to a throwaway DB |
| **Hyperscale** | Secondary replicas / named replicas healthy; backup cadence differs — do not assume MI/IaaS patterns |

```bash
az sql db op list -g <rg> --server <server> --database <db> -o table
az sql db replica list-by-database -g <rg> --server <server> --name <db> -o table
az sql failover-group show -g <rg> --server <server> -n <fog>
az sql db ltr-policy show -g <rg> --server <server> --database <db>
az sql db show -g <rg> --server <server> --name <db> \
  --query "{earliestRestore:earliestRestoreDate, zoneRedundant:zoneRedundant, sku:sku, maxSize:maxSizeBytes}"
```

**Monthly:** restore a non-prod copy from PITR or LTR and validate app smoke tests. Untested restore = assumed failure.

---

### 6. Security & compliance posture

- [ ] **TDE** enabled (on by default); if CMK, Key Vault key enabled / not expired / soft-delete + purge protection
- [ ] **Auditing** to Log Analytics / storage / Event Hub; retention meets policy
- [ ] **Microsoft Defender for SQL** enabled; review open security findings
- [ ] **Minimal TLS 1.2+**; Entra-only auth where policy requires
- [ ] No broad `db_owner` for apps; contained users / roles least privilege
- [ ] Sensitive data: classification / vulnerability assessment findings triaged

```bash
az sql db tde show -g <rg> --server <server> --database <db>
az sql db audit-policy show -g <rg> --server <server> --database <db>
az security pricing show --name SqlServers   # Defender plan (subscription context)
```

---

### 7. Configuration drift (quick)

```sql
SELECT
    DB_NAME() AS database_name,
    DATABASEPROPERTYEX(DB_NAME(), 'Status') AS status,
    DATABASEPROPERTYEX(DB_NAME(), 'Updateability') AS updateability,
    DATABASEPROPERTYEX(DB_NAME(), 'UserAccess') AS user_access,
    compatibility_level,
    collation_name,
    is_auto_create_stats_on,
    is_auto_update_stats_on,
    is_query_store_on,
    snapshot_isolation_state_desc,
    is_read_committed_snapshot_on
FROM sys.databases
WHERE database_id = DB_ID();
```

- [ ] Status ONLINE; intended read-scale / secondary role
- [ ] Compatibility level matches app certification
- [ ] Query Store / auto-stats not disabled by accident

---

## Elastic pool–specific checks

- [ ] Pool utilization (eDTU/vCore) vs per-DB min/max — avoid one DB consuming the pool
- [ ] Per-DB `storage_percent` and CPU within pool
- [ ] Right-size: many cold DBs → pool; one hot DB → dedicated

```sql
-- Connect to master on the logical server
SELECT TOP 24 *
FROM sys.elastic_pool_resource_stats
ORDER BY end_time DESC;
```

---

## Alerting baseline (Azure Monitor)

Minimum production alert set (tune to baselines):

| Metric / signal | Suggest start |
|-----------------|---------------|
| `cpu_percent` | Avg &gt; 80% for 30 min |
| `workers_percent` / `sessions_percent` | &gt; 80% for 15 min |
| `storage_percent` | &gt; 85% |
| `connection_failed` | Spike vs baseline |
| `deadlock` | &gt; 0 sustained / unusual rate |
| Geo-replication lag | Beyond RPO |
| Resource Health Unavailable | Immediate |
| Defender / audit pipeline failures | Immediate |

Wire action groups to on-call; avoid portal-only “someone might look.”

---

## Automation options

**Option A — Azure Monitor + Workbooks (fleet-first)**  
Metric alerts + Resource Health + Log Analytics workbook for DTU/vCore, storage, geo-lag. Lowest operational toil for many databases.

**Option B — Scheduled T-SQL + Azure Automation / Function (deep dive)**  
Run `03_azure_sql_database_health_check.sql` via Automation runbook or Azure Function on a schedule; store results in a DBA utility DB or Log Analytics custom logs. Better for Query Store / blocking detail.

Prefer **A for paging**, **B for diagnosis**. Combine: alert fires → runbook opens → execute companion script + Query Store.

---

## What *not* to waste time on (PaaS)

- SQL Agent job failures (not available on Azure SQL Database)
- Checking OS disks / PLE the IaaS way as a primary signal
- Manual full/diff/log backup jobs (platform does PITR; use LTR + restore tests instead)
- Instance-level `sp_configure` / TempDB file layout (limited / not applicable)

For those patterns use **Managed Instance** or **SQL on VM** playbooks instead.

---

## Severity guide

| Finding | Severity | Typical response |
|---------|----------|------------------|
| Resource Health Unavailable / region outage | Sev1 | Failover group failover if secondary healthy; status page; app degrade mode |
| Workers/sessions at ceiling; apps failing login | Sev1 | Kill blockers / scale up / fix connection leak |
| Storage &gt; 95% | Sev1–2 | Raise max size / free space / scale tier |
| Sustained CPU/IO &gt; 95% | Sev2 | Query Store top consumers; temporary scale; tune |
| Geo-lag beyond RPO | Sev2 | Check secondary health; network; failover readiness |
| Auditing/Defender off in prod | Sev2–3 | Re-enable; compliance ticket |
| Auto-tuning recommendation pending review | Sev4 | Weekly triage |

---

## Deliverable after each daily pass

Record (ticket, wiki, or DBA log):

1. Databases checked + SKU/pool  
2. Any metric above threshold (value + duration)  
3. Top 1–3 Query Store offenders if performance was hot  
4. Backup/restore point / geo status OK or not  
5. Security findings opened/closed  
6. Follow-ups with owners  

---

## Related repo assets

- `scripts/database/mssql/cloud/03_azure_sql_database_health_check.sql` — data-plane pack  
- `scripts/database/mssql/cloud/01_azure_sql_database_automatic_tuning.sql` — auto-tuning  
- `resources/database/daily_dba_checklist.md` — general daily checklist  
- `resources/database/runbooks/` — incident runbooks (adapt storage/log scenarios to PaaS limits)

## References

- [Azure SQL Database monitoring](https://learn.microsoft.com/azure/azure-sql/database/monitoring-sql-database-azure-monitor)  
- [DMVs in Azure SQL Database](https://learn.microsoft.com/azure/azure-sql/database/monitoring-with-dmvs)  
- [sys.dm_db_resource_stats](https://learn.microsoft.com/sql/relational-databases/system-dynamic-management-views/sys-dm-db-resource-stats-azure-sql-database)  
- [Query Store](https://learn.microsoft.com/sql/relational-databases/performance/monitoring-performance-by-using-the-query-store)  
- [Business continuity](https://learn.microsoft.com/azure/azure-sql/database/business-continuity-high-availability-disaster-recover-hadr-overview)  
- [Security best practices](https://learn.microsoft.com/azure/azure-sql/database/security-best-practice)

---

**Last Updated:** 2026-08-18  
**Maintained By:** Cloud DBA / Platform Engineering
