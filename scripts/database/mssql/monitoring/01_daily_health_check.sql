/*
================================================================================
SCRIPT: Daily Health Check - Comprehensive SQL Server Health Monitoring
================================================================================
PURPOSE:
    Performs comprehensive daily health checks including CPU, memory, I/O,
    blocking sessions, failed jobs, database status, and error log analysis.
    Based on methodology from Brent Ozar's First Responder Kit.

BUSINESS APPLICATION:
    Used in automated SQL Agent jobs to proactively detect issues before
    users are affected. Essential for SLA monitoring, capacity planning, and
    incident prevention. Works for on-premises, Azure SQL Managed Instance,
    and provides insights for Azure SQL Database via extended events.

CLOUD CONSIDERATIONS:
    - Azure SQL Database: Use Azure Monitor, Query Performance Insights
    - Azure SQL Managed Instance: Similar to on-premises, SQL Agent available
    - Azure VM SQL Server: Full monitoring capabilities

PREREQUISITES:
    - SQL Server 2019+ or Azure SQL Managed Instance
    - Permissions: VIEW SERVER STATE, VIEW DATABASE STATE
    - SQL Agent for scheduling (or Azure Automation for cloud)

PARAMETERS:
    @CheckCPU          - Check CPU utilization (1 = YES, default: 1)
    @CheckMemory       - Check memory pressure (1 = YES, default: 1)
    @CheckIO           - Check I/O performance (1 = YES, default: 1)
    @CheckBlocking     - Check for blocking sessions (1 = YES, default: 1)
    @CheckFailedJobs   - Check for failed SQL Agent jobs (1 = YES, default: 1)
    @CheckErrorLog     - Check recent error log entries (1 = YES, default: 1)
    @CheckDatabaseStatus - Check database status (1 = YES, default: 1)
    @AlertThresholdCPU - CPU threshold % for alert (default: 80)

RELATED TOOLS:
    - Brent Ozar's sp_Blitz: Overall health check
      https://www.brentozar.com/first-aid/sp-blitz/
    - Ola Hallengren's Maintenance Solution: Automated health checks
      https://ola.hallengren.com/sql-server-maintenance-solution.html

USAGE EXAMPLE:
    EXEC dbo.usp_DailyHealthCheck
        @CheckCPU = 1,
        @CheckMemory = 1,
        @CheckBlocking = 1,
        @AlertThresholdCPU = 85;

EXPECTED OUTPUT:
    Comprehensive health report with warnings and recommendations.
    Identifies immediate issues requiring attention.
    Provides actionable insights for optimization.

REFERENCES:
    - Microsoft Docs: Dynamic Management Views
      https://docs.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/system-dynamic-management-views
    - Azure Monitor: https://docs.microsoft.com/en-us/azure/azure-monitor/overview
================================================================================
*/

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ============================================================================
-- CONFIGURATION SECTION
-- ============================================================================
DECLARE @CheckCPU            BIT = 1;
DECLARE @CheckMemory         BIT = 1;
DECLARE @CheckIO             BIT = 1;
DECLARE @CheckBlocking       BIT = 1;
DECLARE @CheckFailedJobs     BIT = 1;
DECLARE @CheckErrorLog       BIT = 1;
DECLARE @CheckDatabaseStatus BIT = 1;
DECLARE @AlertThresholdCPU   DECIMAL(5,2) = 80.0;

-- ============================================================================
-- HEALTH CHECK EXECUTION
-- ============================================================================
PRINT '================================================================================';
PRINT 'DAILY HEALTH CHECK REPORT';
PRINT '================================================================================';
PRINT 'Server:              ' + @@SERVERNAME;
PRINT 'SQL Server Version:  ' + CAST(@@VERSION AS VARCHAR(100));
PRINT 'Check Date:          ' + CONVERT(VARCHAR(23), GETDATE(), 120);
PRINT '================================================================================';
PRINT '';

-- ============================================================================
-- 1. CPU UTILIZATION CHECK
-- ============================================================================
IF @CheckCPU = 1
BEGIN
    PRINT '================================================================================';
    PRINT '1. CPU UTILIZATION';
    PRINT '================================================================================';
    
    DECLARE @CPUUtilization DECIMAL(5,2);
    
    SELECT @CPUUtilization = 
        100 - (
            SELECT AVG(100 - r.sql_handle) 
            FROM sys.dm_os_ring_buffers r
            WHERE ring_buffer_type = N'RING_BUFFER_SCHEDULER_MONITOR'
            AND record_id IN (
                SELECT TOP 1 record_id 
                FROM sys.dm_os_ring_buffers 
                WHERE ring_buffer_type = N'RING_BUFFER_SCHEDULER_MONITOR'
                ORDER BY record_id DESC
            )
        );
    
    -- Alternative method using sys.dm_os_performance_counters
    SELECT 
        @CPUUtilization = CAST(value AS DECIMAL(5,2))
    FROM sys.dm_os_performance_counters
    WHERE counter_name = 'CPU usage %'
    AND instance_name = '_Total';
    
    IF @CPUUtilization IS NULL
    BEGIN
        -- Use wait stats as alternative indicator
        SELECT 
            @CPUUtilization = 
            CASE 
                WHEN SUM(signal_wait_time_ms) * 100.0 / NULLIF(SUM(wait_time_ms), 0) > @AlertThresholdCPU
                THEN SUM(signal_wait_time_ms) * 100.0 / NULLIF(SUM(wait_time_ms), 0)
                ELSE 0
            END
        FROM sys.dm_os_wait_stats
        WHERE wait_type NOT IN (
            'CLR_SEMAPHORE', 'LAZYWRITER_SLEEP', 'RESOURCE_QUEUE',
            'SLEEP_TASK', 'SLEEP_SYSTEMTASK', 'SQLTRACE_BUFFER_FLUSH',
            'WAITFOR', 'LOGMGR_QUEUE', 'CHECKPOINT_QUEUE',
            'REQUEST_FOR_DEADLOCK_SEARCH', 'XE_TIMER_EVENT', 'BROKER_TO_FLUSH',
            'BROKER_TASK_STOP', 'CLR_MANUAL_EVENT', 'CLR_AUTO_EVENT',
            'DISPATCHER_QUEUE_SEMAPHORE', 'FT_IFTS_SCHEDULER_IDLE_WAIT',
            'XE_DISPATCHER_WAIT', 'XE_DISPATCHER_JOIN', 'SQLTRACE_INCREMENTAL_FLUSH_SLEEP'
        );
    END
    
    PRINT 'Current CPU Utilization: ' + CAST(ISNULL(@CPUUtilization, 0) AS VARCHAR(10)) + '%';
    
    IF ISNULL(@CPUUtilization, 0) > @AlertThresholdCPU
    BEGIN
        PRINT '*** WARNING: High CPU utilization detected! ***';
        PRINT 'Recommendation: Review top CPU-consuming queries using sp_BlitzCache';
        PRINT '                EXEC dbo.sp_BlitzCache @Top = 10, @SortOrder = ''cpu'';';
    END
    ELSE
    BEGIN
        PRINT 'CPU utilization is within normal range.';
    END
    
    -- Top CPU consuming queries
    PRINT '';
    PRINT 'Top 5 CPU-Consuming Queries (Last Hour):';
    SELECT TOP 5
        DB_NAME(qt.dbid) AS DatabaseName,
        SUBSTRING(qt.text, 1, 100) AS QueryText,
        CAST(qs.total_worker_time / 1000.0 AS DECIMAL(18,2)) AS TotalCPUTime_ms,
        qs.execution_count,
        CAST((qs.total_worker_time / 1000.0) / NULLIF(qs.execution_count, 0) AS DECIMAL(18,2)) AS AvgCPUTime_ms
    FROM sys.dm_exec_query_stats qs
    CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) qt
    WHERE qt.dbid IS NOT NULL
    AND qs.last_execution_time >= DATEADD(HOUR, -1, GETDATE())
    ORDER BY qs.total_worker_time DESC;
    
    PRINT '';
END

-- ============================================================================
-- 2. MEMORY PRESSURE CHECK
-- ============================================================================
IF @CheckMemory = 1
BEGIN
    PRINT '================================================================================';
    PRINT '2. MEMORY UTILIZATION';
    PRINT '================================================================================';
    
    DECLARE @TotalMemoryMB BIGINT;
    DECLARE @AvailableMemoryMB BIGINT;
    DECLARE @SQLMemoryMB BIGINT;
    
    SELECT 
        @TotalMemoryMB = total_physical_memory_kb / 1024,
        @AvailableMemoryMB = available_physical_memory_kb / 1024
    FROM sys.dm_os_sys_memory;
    
    SELECT @SQLMemoryMB = (committed_kb / 1024)
    FROM sys.dm_os_sys_info;
    
    SELECT @SQLMemoryMB = 
        CAST(value AS BIGINT) / 1024
    FROM sys.dm_os_performance_counters
    WHERE counter_name = 'Total Server Memory (KB)';
    
    DECLARE @MemoryUtilization DECIMAL(5,2) = 
        (@SQLMemoryMB * 100.0 / NULLIF(@TotalMemoryMB, 0));
    
    PRINT 'Total Physical Memory:  ' + CAST(@TotalMemoryMB AS VARCHAR(20)) + ' MB';
    PRINT 'SQL Server Memory:      ' + CAST(@SQLMemoryMB AS VARCHAR(20)) + ' MB';
    PRINT 'Available Memory:       ' + CAST(@AvailableMemoryMB AS VARCHAR(20)) + ' MB';
    PRINT 'SQL Memory Utilization: ' + CAST(@MemoryUtilization AS VARCHAR(10)) + '%';
    
    IF @AvailableMemoryMB < (@TotalMemoryMB * 0.1) -- Less than 10% available
    BEGIN
        PRINT '*** WARNING: Low available memory detected! ***';
        PRINT 'Recommendation: Review memory grants and consider increasing max server memory';
    END
    ELSE
    BEGIN
        PRINT 'Memory status is healthy.';
    END
    
    -- Page Life Expectancy check
    DECLARE @PLE BIGINT;
    SELECT @PLE = cntr_value
    FROM sys.dm_os_performance_counters
    WHERE counter_name = 'Page life expectancy'
    AND instance_name = 'SQLServer:Buffer Manager';
    
    PRINT '';
    PRINT 'Page Life Expectancy:   ' + CAST(@PLE AS VARCHAR(20)) + ' seconds';
    
    IF @PLE < 300
    BEGIN
        PRINT '*** WARNING: Low Page Life Expectancy indicates memory pressure! ***';
        PRINT 'Recommendation: Review buffer pool usage and consider adding memory';
    END
    
    PRINT '';
END

-- ============================================================================
-- 3. I/O PERFORMANCE CHECK
-- ============================================================================
IF @CheckIO = 1
BEGIN
    PRINT '================================================================================';
    PRINT '3. I/O PERFORMANCE';
    PRINT '================================================================================';
    
    SELECT 
        DB_NAME(vfs.database_id) AS DatabaseName,
        mf.physical_name AS FileName,
        CAST(SUM(vfs.num_of_reads) AS BIGINT) AS TotalReads,
        CAST(SUM(vfs.num_of_writes) AS BIGINT) AS TotalWrites,
        CAST(SUM(vfs.io_stall_read_ms) AS BIGINT) AS TotalReadLatency_ms,
        CAST(SUM(vfs.io_stall_write_ms) AS BIGINT) AS TotalWriteLatency_ms,
        CAST(AVG(vfs.io_stall_read_ms) / NULLIF(AVG(vfs.num_of_reads), 0) AS DECIMAL(18,2)) AS AvgReadLatency_ms,
        CAST(AVG(vfs.io_stall_write_ms) / NULLIF(AVG(vfs.num_of_writes), 0) AS DECIMAL(18,2)) AS AvgWriteLatency_ms
    FROM sys.dm_io_virtual_file_stats(NULL, NULL) vfs
    INNER JOIN sys.master_files mf ON vfs.database_id = mf.database_id 
        AND vfs.file_id = mf.file_id
    GROUP BY vfs.database_id, mf.physical_name
    HAVING AVG(vfs.io_stall_read_ms) / NULLIF(AVG(vfs.num_of_reads), 0) > 20 -- > 20ms latency
        OR AVG(vfs.io_stall_write_ms) / NULLIF(AVG(vfs.num_of_writes), 0) > 20
    ORDER BY AvgReadLatency_ms DESC;
    
    IF @@ROWCOUNT > 0
    BEGIN
        PRINT '*** WARNING: High I/O latency detected on above files! ***';
        PRINT 'Recommendation: Review storage performance, consider SSD or faster storage';
    END
    ELSE
    BEGIN
        PRINT 'I/O performance is within acceptable range.';
    END
    
    PRINT '';
END

-- ============================================================================
-- 4. BLOCKING SESSIONS CHECK
-- ============================================================================
IF @CheckBlocking = 1
BEGIN
    PRINT '================================================================================';
    PRINT '4. BLOCKING SESSIONS';
    PRINT '================================================================================';
    
    SELECT 
        s1.session_id AS BlockingSessionID,
        s1.login_name AS BlockingLogin,
        DB_NAME(s1.database_id) AS BlockingDatabase,
        s1.program_name AS BlockingProgram,
        s2.session_id AS BlockedSessionID,
        s2.login_name AS BlockedLogin,
        DB_NAME(s2.database_id) AS BlockedDatabase,
        s2.program_name AS BlockedProgram,
        CAST(wait_duration_ms / 1000.0 AS DECIMAL(18,2)) AS WaitDuration_Seconds,
        w.wait_type AS WaitType,
        SUBSTRING(st.text, 1, 100) AS BlockedQuery
    FROM sys.dm_exec_connections s1
    INNER JOIN sys.dm_exec_requests s2 ON s1.session_id = s2.blocking_session_id
    INNER JOIN sys.dm_os_waiting_tasks w ON s2.session_id = w.session_id
    CROSS APPLY sys.dm_exec_sql_text(s2.sql_handle) st
    WHERE s2.blocking_session_id <> 0;
    
    IF @@ROWCOUNT > 0
    BEGIN
        PRINT '*** WARNING: Blocking sessions detected! ***';
        PRINT 'Recommendation: Review blocking queries and transaction isolation levels';
        PRINT '                Use sp_BlitzLock for deadlock analysis:';
        PRINT '                EXEC dbo.sp_BlitzLock @SinceStartup = 1;';
    END
    ELSE
    BEGIN
        PRINT 'No blocking sessions detected.';
    END
    
    PRINT '';
END

-- ============================================================================
-- 5. FAILED SQL AGENT JOBS CHECK
-- ============================================================================
IF @CheckFailedJobs = 1
BEGIN
    PRINT '================================================================================';
    PRINT '5. SQL AGENT JOBS - FAILED IN LAST 24 HOURS';
    PRINT '================================================================================';
    
    SELECT 
        j.name AS JobName,
        h.step_id,
        h.step_name,
        h.run_date,
        h.run_time,
        h.run_duration,
        h.sql_message_id,
        h.message AS ErrorMessage,
        CASE h.run_status
            WHEN 0 THEN 'Failed'
            WHEN 1 THEN 'Succeeded'
            WHEN 2 THEN 'Retry'
            WHEN 3 THEN 'Canceled'
            ELSE 'Unknown'
        END AS Status
    FROM msdb.dbo.sysjobs j
    INNER JOIN msdb.dbo.sysjobhistory h ON j.job_id = h.job_id
    WHERE h.run_status = 0 -- Failed
    AND CAST(CAST(h.run_date AS VARCHAR(8)) + ' ' + 
        STUFF(STUFF(RIGHT('000000' + CAST(h.run_time AS VARCHAR(6)), 6), 3, 0, ':'), 6, 0, ':') 
        AS DATETIME) >= DATEADD(DAY, -1, GETDATE())
    ORDER BY h.run_date DESC, h.run_time DESC;
    
    IF @@ROWCOUNT > 0
    BEGIN
        PRINT '*** WARNING: Failed jobs detected! Review and resolve immediately. ***';
    END
    ELSE
    BEGIN
        PRINT 'No failed jobs in the last 24 hours.';
    END
    
    PRINT '';
END

-- ============================================================================
-- 6. ERROR LOG CHECK
-- ============================================================================
IF @CheckErrorLog = 1
BEGIN
    PRINT '================================================================================';
    PRINT '6. ERROR LOG - RECENT ERRORS (LAST 24 HOURS)';
    PRINT '================================================================================';
    
    -- Create temp table for error log
    CREATE TABLE #ErrorLog (
        LogDate DATETIME,
        ProcessInfo VARCHAR(50),
        ErrorText NVARCHAR(MAX)
    );
    
    INSERT INTO #ErrorLog
    EXEC xp_readerrorlog 0, 1, NULL, NULL, NULL, NULL, N'DESC';
    
    SELECT TOP 20
        LogDate,
        ProcessInfo,
        LEFT(ErrorText, 200) AS ErrorText
    FROM #ErrorLog
    WHERE LogDate >= DATEADD(DAY, -1, GETDATE())
    AND ErrorText LIKE '%error%'
    ORDER BY LogDate DESC;
    
    IF @@ROWCOUNT > 0
    BEGIN
        PRINT '*** Recent errors found in error log. Review for critical issues. ***';
    END
    ELSE
    BEGIN
        PRINT 'No recent errors in error log.';
    END
    
    DROP TABLE #ErrorLog;
    PRINT '';
END

-- ============================================================================
-- 7. DATABASE STATUS CHECK
-- ============================================================================
IF @CheckDatabaseStatus = 1
BEGIN
    PRINT '================================================================================';
    PRINT '7. DATABASE STATUS';
    PRINT '================================================================================';
    
    SELECT 
        name AS DatabaseName,
        state_desc AS State,
        recovery_model_desc AS RecoveryModel,
        CAST(compatibility_level AS VARCHAR(10)) AS CompatibilityLevel,
        user_access_desc AS UserAccess,
        is_read_only AS IsReadOnly,
        CASE 
            WHEN is_auto_close_on = 1 THEN 'ON'
            ELSE 'OFF'
        END AS AutoClose,
        CASE 
            WHEN is_auto_shrink_on = 1 THEN 'ON - WARNING'
            ELSE 'OFF'
        END AS AutoShrink
    FROM sys.databases
    WHERE state_desc <> 'ONLINE'
    OR is_auto_shrink_on = 1
    OR is_read_only = 1
    ORDER BY state_desc, name;
    
    IF @@ROWCOUNT > 0
    BEGIN
        PRINT '*** WARNING: Issues detected with above databases! ***';
        PRINT 'Recommendation: Review database states and configuration';
    END
    ELSE
    BEGIN
        PRINT 'All databases are online and properly configured.';
    END
    
    PRINT '';
END

-- ============================================================================
-- SUMMARY
-- ============================================================================
PRINT '================================================================================';
PRINT 'HEALTH CHECK SUMMARY';
PRINT '================================================================================';
PRINT 'For comprehensive analysis, use Brent Ozar''s First Responder Kit:';
PRINT '  - sp_Blitz: Overall health check';
PRINT '  - sp_BlitzCache: Query performance';
PRINT '  - sp_BlitzIndex: Index analysis';
PRINT '  Download: https://www.brentozar.com/first-aid/';
PRINT '';
PRINT 'For Azure SQL Database, use Azure Monitor and Query Performance Insights';
PRINT 'For Azure SQL Managed Instance, use Azure Monitor + SQL Agent';
PRINT '================================================================================';
GO

