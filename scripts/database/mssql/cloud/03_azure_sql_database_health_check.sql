/*
================================================================================
SCRIPT: Azure SQL Database (PaaS) — Daily Health Check
================================================================================
PURPOSE:
    Data-plane health pack for Azure SQL Database: resource governance,
    storage, waits, blocking, Query Store signal, and config drift.
    Designed for EngineEdition = 5 (Azure SQL Database), not IaaS/MI-only DMVs.

BUSINESS APPLICATION:
    Run daily (or on alert) as a senior Cloud DBA triage pack. Complements
    Azure Monitor metrics/alerts and the playbook:
    resources/database/azure_sql_database_paas_healthcheck.md

CLOUD CONSIDERATIONS:
    - Azure SQL Database: primary target (this script)
    - Elastic pool: also query sys.elastic_pool_resource_stats from master
    - Managed Instance / on-prem: use monitoring/01_daily_health_check.sql

PREREQUISITES:
    - Azure SQL Database (single DB or elastic pool member)
    - Permissions: VIEW DATABASE STATE (most sections); CONNECT to master
      for elastic pool stats
    - Query Store enabled for regression section (recommended)

USAGE:
    1. Connect to the user database (not master) unless noted
    2. Review CONFIGURATION SECTION thresholds
    3. Execute entire script; review WARNING lines and result grids

REFERENCES:
    - https://learn.microsoft.com/sql/relational-databases/system-dynamic-management-views/sys-dm-db-resource-stats-azure-sql-database
    - https://learn.microsoft.com/azure/azure-sql/database/monitoring-with-dmvs
================================================================================
*/

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ============================================================================
-- CONFIGURATION SECTION
-- ============================================================================
DECLARE @CpuWarnPct            DECIMAL(5,2) = 80.0;
DECLARE @CpuCritPct            DECIMAL(5,2) = 95.0;
DECLARE @IoWarnPct             DECIMAL(5,2) = 80.0;
DECLARE @WorkerWarnPct         DECIMAL(5,2) = 80.0;
DECLARE @SessionWarnPct        DECIMAL(5,2) = 80.0;
DECLARE @StorageWarnPct        DECIMAL(5,2) = 85.0;
DECLARE @BlockingSecondsWarn   INT = 30;
DECLARE @TopN                  INT = 15;

-- ============================================================================
-- PLATFORM GUARD
-- ============================================================================
DECLARE @EngineEdition INT = CAST(SERVERPROPERTY('EngineEdition') AS INT);
-- 5 = Azure SQL Database, 8 = Azure SQL Managed Instance, etc.

PRINT '================================================================================';
PRINT 'AZURE SQL DATABASE (PaaS) HEALTH CHECK';
PRINT '================================================================================';
PRINT 'Server:         ' + CAST(@@SERVERNAME AS NVARCHAR(128));
PRINT 'Database:       ' + DB_NAME();
PRINT 'UTC Now:        ' + CONVERT(VARCHAR(23), SYSUTCDATETIME(), 126);
PRINT 'EngineEdition:  ' + CAST(@EngineEdition AS VARCHAR(10))
    + CASE @EngineEdition
        WHEN 5 THEN ' (Azure SQL Database)'
        WHEN 8 THEN ' (Azure SQL Managed Instance — prefer MI health script)'
        ELSE ' (Not Azure SQL Database — results may be incomplete)'
      END;
PRINT '================================================================================';
PRINT '';

IF @EngineEdition <> 5
BEGIN
    PRINT '*** NOTICE: This pack is optimized for Azure SQL Database (EngineEdition 5). ***';
    PRINT 'Continue only if you intentionally want overlapping DMV sections.';
    PRINT '';
END

-- ============================================================================
-- 1. DATABASE STATUS & CONFIG DRIFT
-- ============================================================================
PRINT '================================================================================';
PRINT '1. DATABASE STATUS & CONFIGURATION';
PRINT '================================================================================';

SELECT
    DB_NAME() AS database_name,
    CAST(DATABASEPROPERTYEX(DB_NAME(), 'Status') AS NVARCHAR(60)) AS status,
    CAST(DATABASEPROPERTYEX(DB_NAME(), 'Updateability') AS NVARCHAR(60)) AS updateability,
    CAST(DATABASEPROPERTYEX(DB_NAME(), 'UserAccess') AS NVARCHAR(60)) AS user_access,
    d.compatibility_level,
    d.collation_name,
    d.is_auto_create_stats_on,
    d.is_auto_update_stats_on,
    d.is_query_store_on,
    d.is_read_committed_snapshot_on,
    d.snapshot_isolation_state_desc,
    d.recovery_model_desc
FROM sys.databases AS d
WHERE d.database_id = DB_ID();

IF CAST(DATABASEPROPERTYEX(DB_NAME(), 'Status') AS NVARCHAR(60)) <> N'ONLINE'
    PRINT '*** CRITICAL: Database status is not ONLINE ***';

IF EXISTS (
    SELECT 1 FROM sys.databases
    WHERE database_id = DB_ID() AND is_query_store_on = 0
)
    PRINT '*** WARNING: Query Store is OFF — enable for regression analysis ***';

PRINT '';

-- ============================================================================
-- 2. RESOURCE GOVERNANCE (last ~1 hour)
-- ============================================================================
PRINT '================================================================================';
PRINT '2. RESOURCE GOVERNANCE (sys.dm_db_resource_stats)';
PRINT '================================================================================';

IF OBJECT_ID(N'sys.dm_db_resource_stats') IS NULL
BEGIN
    PRINT 'sys.dm_db_resource_stats not available in this engine.';
END
ELSE
BEGIN
    ;WITH recent AS (
        SELECT
            end_time,
            avg_cpu_percent,
            avg_data_io_percent,
            avg_log_write_percent,
            avg_memory_usage_percent,
            max_worker_percent,
            max_session_percent,
            avg_dtu_percent
        FROM sys.dm_db_resource_stats
    )
    SELECT TOP (12)
        end_time,
        avg_cpu_percent,
        avg_data_io_percent,
        avg_log_write_percent,
        avg_memory_usage_percent,
        max_worker_percent,
        max_session_percent,
        avg_dtu_percent
    FROM recent
    ORDER BY end_time DESC;

    DECLARE
        @MaxCpu DECIMAL(5,2),
        @AvgCpu DECIMAL(5,2),
        @MaxDataIo DECIMAL(5,2),
        @MaxLogIo DECIMAL(5,2),
        @MaxWorker DECIMAL(5,2),
        @MaxSession DECIMAL(5,2);

    SELECT
        @MaxCpu = MAX(avg_cpu_percent),
        @AvgCpu = AVG(avg_cpu_percent),
        @MaxDataIo = MAX(avg_data_io_percent),
        @MaxLogIo = MAX(avg_log_write_percent),
        @MaxWorker = MAX(max_worker_percent),
        @MaxSession = MAX(max_session_percent)
    FROM sys.dm_db_resource_stats;

    PRINT 'Last-hour summary (approx):';
    PRINT '  Avg CPU %:      ' + CAST(ISNULL(@AvgCpu, 0) AS VARCHAR(12));
    PRINT '  Max CPU %:      ' + CAST(ISNULL(@MaxCpu, 0) AS VARCHAR(12));
    PRINT '  Max Data IO %:  ' + CAST(ISNULL(@MaxDataIo, 0) AS VARCHAR(12));
    PRINT '  Max Log Write %:' + CAST(ISNULL(@MaxLogIo, 0) AS VARCHAR(12));
    PRINT '  Max Worker %:   ' + CAST(ISNULL(@MaxWorker, 0) AS VARCHAR(12));
    PRINT '  Max Session %:  ' + CAST(ISNULL(@MaxSession, 0) AS VARCHAR(12));

    IF ISNULL(@MaxCpu, 0) >= @CpuCritPct
        PRINT '*** CRITICAL: CPU saturated — triage Query Store / consider scale ***';
    ELSE IF ISNULL(@MaxCpu, 0) >= @CpuWarnPct
        PRINT '*** WARNING: High CPU — review top consumers before scaling ***';

    IF ISNULL(@MaxDataIo, 0) >= @IoWarnPct OR ISNULL(@MaxLogIo, 0) >= @IoWarnPct
        PRINT '*** WARNING: High data or log IO % — check scans, bulk loads, log-heavy txns ***';

    IF ISNULL(@MaxWorker, 0) >= @WorkerWarnPct
        PRINT '*** WARNING: High worker utilization — blocking or parallelism pressure ***';

    IF ISNULL(@MaxSession, 0) >= @SessionWarnPct
        PRINT '*** WARNING: High session utilization — connection pooling / leaks ***';
END

PRINT '';

-- ============================================================================
-- 3. STORAGE HEADROOM
-- ============================================================================
PRINT '================================================================================';
PRINT '3. STORAGE HEADROOM';
PRINT '================================================================================';

SELECT
    DB_NAME() AS database_name,
    CAST(DATABASEPROPERTYEX(DB_NAME(), 'MaxSizeInBytes') AS BIGINT) / 1024 / 1024 AS max_size_mb,
    SUM(CAST(FILEPROPERTY(name, 'SpaceUsed') AS BIGINT) * 8 / 1024) AS space_used_mb,
    SUM(CAST(size AS BIGINT) * 8 / 1024) AS reserved_mb,
    CAST(
        SUM(CAST(FILEPROPERTY(name, 'SpaceUsed') AS BIGINT) * 8 / 1024) * 100.0
        / NULLIF(CAST(DATABASEPROPERTYEX(DB_NAME(), 'MaxSizeInBytes') AS BIGINT) / 1024 / 1024, 0)
        AS DECIMAL(5,2)
    ) AS pct_of_max_size
FROM sys.database_files
WHERE type_desc IN (N'ROWS', N'LOG');

SELECT
    name AS file_name,
    type_desc,
    CAST(size AS BIGINT) * 8 / 1024 AS size_mb,
    CAST(FILEPROPERTY(name, 'SpaceUsed') AS BIGINT) * 8 / 1024 AS used_mb,
    CAST(
        (CAST(FILEPROPERTY(name, 'SpaceUsed') AS BIGINT) * 100.0)
        / NULLIF(CAST(size AS BIGINT), 0) AS DECIMAL(5,2)
    ) AS pct_file_used
FROM sys.database_files
ORDER BY type_desc, name;

DECLARE @PctOfMax DECIMAL(5,2);
SELECT @PctOfMax = CAST(
    SUM(CAST(FILEPROPERTY(name, 'SpaceUsed') AS BIGINT) * 8 / 1024) * 100.0
    / NULLIF(CAST(DATABASEPROPERTYEX(DB_NAME(), 'MaxSizeInBytes') AS BIGINT) / 1024 / 1024, 0)
    AS DECIMAL(5,2)
)
FROM sys.database_files
WHERE type_desc = N'ROWS';

IF ISNULL(@PctOfMax, 0) >= @StorageWarnPct
    PRINT '*** WARNING: Approaching max database size — raise max size / archive / scale ***';
ELSE
    PRINT 'Storage headroom looks acceptable vs MaxSizeInBytes.';

PRINT '';

-- ============================================================================
-- 4. TOP WAITS (database-scoped)
-- ============================================================================
PRINT '================================================================================';
PRINT '4. TOP WAIT STATS (sys.dm_db_wait_stats)';
PRINT '================================================================================';

IF OBJECT_ID(N'sys.dm_db_wait_stats') IS NULL
BEGIN
    PRINT 'sys.dm_db_wait_stats not available.';
END
ELSE
BEGIN
    SELECT TOP (@TopN)
        wait_type,
        waiting_tasks_count,
        wait_time_ms,
        signal_wait_time_ms,
        CAST(wait_time_ms * 100.0 / NULLIF(SUM(wait_time_ms) OVER (), 0) AS DECIMAL(5,2)) AS pct_of_total_wait
    FROM sys.dm_db_wait_stats
    WHERE wait_type NOT IN (
        N'BROKER_EVENTHANDLER', N'BROKER_RECEIVE_WAITFOR', N'BROKER_TASK_STOP',
        N'BROKER_TO_FLUSH', N'BROKER_TRANSMITTER', N'CHECKPOINT_QUEUE',
        N'CHKPT', N'CLR_AUTO_EVENT', N'CLR_MANUAL_EVENT', N'CLR_SEMAPHORE',
        N'DBMIRROR_DBM_EVENT', N'DBMIRROR_EVENTS_QUEUE', N'DBMIRROR_WORKER_QUEUE',
        N'DBMIRRORING_CMD', N'DIRTY_PAGE_POLL', N'DISPATCHER_QUEUE_SEMAPHORE',
        N'EXECSYNC', N'FSAGENT', N'FT_IFTS_SCHEDULER_IDLE_WAIT', N'FT_IFTSHC_MUTEX',
        N'HADR_CLUSAPI_CALL', N'HADR_FILESTREAM_IOMGR_IOCOMPLETION', N'HADR_LOGCAPTURE_WAIT',
        N'HADR_NOTIFICATION_DEQUEUE', N'HADR_TIMER_TASK', N'HADR_WORK_QUEUE',
        N'KSOURCE_WAKEUP', N'LAZYWRITER_SLEEP', N'LOGMGR_QUEUE', N'MEMORY_ALLOCATION_EXT',
        N'ONDEMAND_TASK_QUEUE', N'PARALLEL_REDO_DRAIN_WORKER', N'PARALLEL_REDO_LOG_CACHE',
        N'PARALLEL_REDO_TRAN_LIST', N'PARALLEL_REDO_WORKER_SYNC', N'PARALLEL_REDO_WORKER_WAIT_WORK',
        N'PREEMPTIVE_XE_GETTARGETSTATE', N'PWAIT_ALL_COMPONENTS_INITIALIZED',
        N'PWAIT_DIRECTLOGCONSUMER_GETNEXT', N'QDS_PERSIST_TASK_MAIN_LOOP_SLEEP',
        N'QDS_ASYNC_QUEUE', N'QDS_CLEANUP_STALE_QUERIES_TASK_MAIN_LOOP_SLEEP',
        N'QDS_SHUTDOWN_QUEUE', N'REDO_THREAD_PENDING_WORK', N'REQUEST_FOR_DEADLOCK_SEARCH',
        N'RESOURCE_QUEUE', N'SERVER_IDLE_CHECK', N'SLEEP_BPOOL_FLUSH', N'SLEEP_DBSTARTUP',
        N'SLEEP_DCOMSTARTUP', N'SLEEP_MASTERDBREADY', N'SLEEP_MASTERMDREADY',
        N'SLEEP_MASTERUPGRADED', N'SLEEP_MSDBSTARTUP', N'SLEEP_SYSTEMTASK', N'SLEEP_TASK',
        N'SLEEP_TEMPDBSTARTUP', N'SNI_HTTP_ACCEPT', N'SP_SERVER_DIAGNOSTICS_SLEEP',
        N'SQLTRACE_BUFFER_FLUSH', N'SQLTRACE_INCREMENTAL_FLUSH_SLEEP', N'SQLTRACE_WAIT_ENTRIES',
        N'WAIT_FOR_RESULTS', N'WAITFOR', N'WAITFOR_TASKSHUTDOWN', N'WAIT_XTP_RECOVERY',
        N'WAIT_XTP_HOST_WAIT', N'WAIT_XTP_OFFLINE_CKPT_NEW_LOG', N'WAIT_XTP_CKPT_CLOSE',
        N'XE_DISPATCHER_JOIN', N'XE_DISPATCHER_WAIT', N'XE_TIMER_EVENT'
    )
    ORDER BY wait_time_ms DESC;
END

PRINT '';

-- ============================================================================
-- 5. BLOCKING & LONG REQUESTS
-- ============================================================================
PRINT '================================================================================';
PRINT '5. BLOCKING & LONG-RUNNING REQUESTS';
PRINT '================================================================================';

SELECT
    r.session_id,
    r.blocking_session_id,
    r.status,
    r.command,
    r.wait_type,
    r.wait_time,
    r.cpu_time,
    r.total_elapsed_time,
    r.logical_reads,
    DB_NAME(r.database_id) AS database_name,
    s.login_name,
    s.host_name,
    s.program_name,
    SUBSTRING(
        t.text,
        (r.statement_start_offset / 2) + 1,
        (
            CASE r.statement_end_offset
                WHEN -1 THEN DATALENGTH(t.text)
                ELSE r.statement_end_offset
            END - r.statement_start_offset
        ) / 2 + 1
    ) AS statement_text
FROM sys.dm_exec_requests AS r
JOIN sys.dm_exec_sessions AS s ON r.session_id = s.session_id
CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) AS t
WHERE r.session_id <> @@SPID
  AND (
        r.blocking_session_id <> 0
        OR r.total_elapsed_time >= (@BlockingSecondsWarn * 1000)
      )
ORDER BY r.blocking_session_id DESC, r.total_elapsed_time DESC;

IF EXISTS (
    SELECT 1
    FROM sys.dm_exec_requests
    WHERE blocking_session_id <> 0
      AND session_id <> @@SPID
)
    PRINT '*** WARNING: Active blocking detected — capture lead blocker before killing ***';
ELSE
    PRINT 'No active blocking chains detected at sample time.';

PRINT '';

-- ============================================================================
-- 6. TOP QUERY STORE CONSUMERS (CPU / duration) — last 24h
-- ============================================================================
PRINT '================================================================================';
PRINT '6. QUERY STORE — TOP CONSUMERS (last 24 hours)';
PRINT '================================================================================';

IF NOT EXISTS (
    SELECT 1 FROM sys.databases WHERE database_id = DB_ID() AND is_query_store_on = 1
)
BEGIN
    PRINT 'Query Store is disabled — skipping.';
END
ELSE
BEGIN
    ;WITH qs AS (
        SELECT
            q.query_id,
            qt.query_sql_text,
            SUM(rs.count_executions) AS executions,
            SUM(rs.avg_cpu_time * rs.count_executions) / NULLIF(SUM(rs.count_executions), 0) AS avg_cpu_us,
            SUM(rs.avg_duration * rs.count_executions) / NULLIF(SUM(rs.count_executions), 0) AS avg_duration_us,
            SUM(rs.avg_logical_io_reads * rs.count_executions) / NULLIF(SUM(rs.count_executions), 0) AS avg_logical_reads
        FROM sys.query_store_query AS q
        JOIN sys.query_store_query_text AS qt ON q.query_text_id = qt.query_text_id
        JOIN sys.query_store_plan AS p ON q.query_id = p.query_id
        JOIN sys.query_store_runtime_stats AS rs ON p.plan_id = rs.plan_id
        JOIN sys.query_store_runtime_stats_interval AS rsi
            ON rs.runtime_stats_interval_id = rsi.runtime_stats_interval_id
        WHERE rsi.start_time >= DATEADD(hour, -24, SYSUTCDATETIME())
        GROUP BY q.query_id, qt.query_sql_text
    )
    SELECT TOP (@TopN)
        query_id,
        LEFT(query_sql_text, 200) AS query_sql_text_preview,
        executions,
        CAST(avg_cpu_us AS DECIMAL(18,2)) AS avg_cpu_us,
        CAST(avg_duration_us AS DECIMAL(18,2)) AS avg_duration_us,
        CAST(avg_logical_reads AS DECIMAL(18,2)) AS avg_logical_reads
    FROM qs
    ORDER BY avg_cpu_us * executions DESC;
END

PRINT '';

-- ============================================================================
-- 7. AUTOMATIC TUNING SNAPSHOT (if available)
-- ============================================================================
PRINT '================================================================================';
PRINT '7. AUTOMATIC TUNING OPTIONS';
PRINT '================================================================================';

IF OBJECT_ID(N'sys.database_automatic_tuning_options') IS NOT NULL
BEGIN
    SELECT name, desired_state_desc, actual_state_desc, reason_desc
    FROM sys.database_automatic_tuning_options;
END
ELSE
    PRINT 'Automatic tuning DMV not available.';

IF OBJECT_ID(N'sys.dm_db_tuning_recommendations') IS NOT NULL
BEGIN
    SELECT
        type,
        reason,
        state,
        valid_since,
        score,
        LEFT(CAST(details AS NVARCHAR(MAX)), 400) AS details_preview
    FROM sys.dm_db_tuning_recommendations
    ORDER BY score DESC;
END

PRINT '';

-- ============================================================================
-- 8. CONNECTION / SESSION SNAPSHOT
-- ============================================================================
PRINT '================================================================================';
PRINT '8. SESSION SNAPSHOT';
PRINT '================================================================================';

SELECT
    status,
    COUNT(*) AS session_count
FROM sys.dm_exec_sessions
WHERE is_user_process = 1
GROUP BY status
ORDER BY session_count DESC;

SELECT TOP (@TopN)
    s.session_id,
    s.login_name,
    s.host_name,
    s.program_name,
    s.status,
    s.cpu_time,
    s.memory_usage,
    s.total_elapsed_time,
    s.last_request_start_time
FROM sys.dm_exec_sessions AS s
WHERE s.is_user_process = 1
ORDER BY s.cpu_time DESC;

PRINT '';
PRINT '================================================================================';
PRINT 'HEALTH CHECK COMPLETE';
PRINT 'Next: correlate with Azure Monitor metrics, Resource Health, geo-replication,';
PRINT 'PITR/LTR, and security posture per playbook.';
PRINT 'Playbook: resources/database/azure_sql_database_paas_healthcheck.md';
PRINT '================================================================================';
GO
