/*
================================================================================
SCRIPT: Always On Availability Groups - Health Monitoring
================================================================================
PURPOSE:
    Monitors Always On Availability Groups health, synchronization status,
    failover readiness, and performance metrics. Provides actionable alerts
    for HA/DR scenarios.

BUSINESS APPLICATION:
    Critical for maintaining high availability and disaster recovery capabilities.
    Ensures databases remain available during planned and unplanned outages.
    Used for SLA compliance and business continuity planning.

CLOUD CONSIDERATIONS:
    - Azure SQL Managed Instance: Always On AGs available (Enterprise tier)
    - Azure SQL Database: Built-in HA via geo-replication (different model)
    - Azure VM SQL Server: Full Always On support, same as on-premises

PREREQUISITES:
    - SQL Server 2019+ with Always On Availability Groups configured
    - Permissions: VIEW SERVER STATE, VIEW ANY DEFINITION
    - Availability Groups must be configured and running

PARAMETERS:
    @AvailabilityGroupName - Specific AG to monitor (NULL = all AGs)
    @CheckSyncStatus       - Check synchronization status (1 = YES, default: 1)
    @CheckFailoverReadiness - Check failover readiness (1 = YES, default: 1)
    @CheckPerformance      - Check performance metrics (1 = YES, default: 1)

RELATED TOOLS:
    - Ola Hallengren: DatabaseBackup supports AG-aware backups
      https://ola.hallengren.com/sql-server-backup.html
    - Azure Portal: Built-in monitoring for Managed Instance AGs

USAGE EXAMPLE:
    EXEC dbo.usp_AlwaysOnHealthMonitoring
        @AvailabilityGroupName = NULL,
        @CheckSyncStatus = 1,
        @CheckFailoverReadiness = 1;

EXPECTED OUTPUT:
    AG health status with synchronization metrics.
    Failover readiness assessment.
    Performance and latency metrics.

REFERENCES:
    - Microsoft Docs: Always On Availability Groups
      https://docs.microsoft.com/en-us/sql/database-engine/availability-groups/windows/always-on-availability-groups-sql-server
    - Azure SQL Managed Instance: https://docs.microsoft.com/en-us/azure/azure-sql/managed-instance/business-critical-service-tier-overview
================================================================================
*/

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ============================================================================
-- CONFIGURATION SECTION
-- ============================================================================
DECLARE @AvailabilityGroupName   SYSNAME = NULL;       -- NULL = all AGs
DECLARE @CheckSyncStatus          BIT = 1;
DECLARE @CheckFailoverReadiness   BIT = 1;
DECLARE @CheckPerformance         BIT = 1;

-- ============================================================================
-- CHECK IF ALWAYS ON IS AVAILABLE
-- ============================================================================
IF SERVERPROPERTY('IsHadrEnabled') = 0
BEGIN
    PRINT '================================================================================';
    PRINT 'ALWAYS ON AVAILABILITY GROUPS NOT AVAILABLE';
    PRINT '================================================================================';
    PRINT '';
    PRINT 'Always On Availability Groups are not enabled on this server.';
    PRINT '';
    PRINT 'To enable Always On:';
    PRINT '  1. SQL Server Configuration Manager > Enable Always On';
    PRINT '  2. Restart SQL Server service';
    PRINT '  3. Configure Windows Failover Clustering (WFC)';
    PRINT '  4. Create Availability Groups via SSMS or T-SQL';
    PRINT '';
    PRINT 'For Azure SQL Managed Instance:';
    PRINT '  - Always On is built-in (Business Critical tier)';
    PRINT '  - Configure via Azure Portal or ARM templates';
    PRINT '';
    PRINT 'For Azure SQL Database:';
    PRINT '  - Use Active Geo-Replication instead';
    PRINT '  - Link: https://docs.microsoft.com/en-us/azure/azure-sql/database/active-geo-replication-overview';
    PRINT '';
    PRINT '================================================================================';
    RETURN;
END

-- ============================================================================
-- AVAILABILITY GROUP HEALTH CHECK
-- ============================================================================
PRINT '================================================================================';
PRINT 'ALWAYS ON AVAILABILITY GROUPS - HEALTH MONITORING';
PRINT '================================================================================';
PRINT 'Server:           ' + @@SERVERNAME;
PRINT 'Check Date:       ' + CONVERT(VARCHAR(23), GETDATE(), 120);
PRINT '================================================================================';
PRINT '';

-- ============================================================================
-- 1. AVAILABILITY GROUP STATUS
-- ============================================================================
PRINT '================================================================================';
PRINT '1. AVAILABILITY GROUP STATUS';
PRINT '================================================================================';

SELECT 
    ag.name AS AvailabilityGroupName,
    ag.failure_condition_level AS FailureConditionLevel,
    ag.health_check_timeout_ms AS HealthCheckTimeout_ms,
    ag.is_distributed AS IsDistributed,
    CASE 
        WHEN ars.synchronization_state = 0 THEN 'NOT INITIALIZED'
        WHEN ars.synchronization_state = 1 THEN 'INITIALIZED'
        WHEN ars.synchronization_state = 2 THEN 'SYNCHRONIZING'
        WHEN ars.synchronization_state = 3 THEN 'SYNCHRONIZED'
        WHEN ars.synchronization_state = 4 THEN 'REVERTING'
        WHEN ars.synchronization_state = 5 THEN 'INITIALIZING'
    END AS SyncState,
    CASE 
        WHEN ars.synchronization_health = 0 THEN 'NOT HEALTHY'
        WHEN ars.synchronization_health = 1 THEN 'PARTIALLY HEALTHY'
        WHEN ars.synchronization_health = 2 THEN 'HEALTHY'
    END AS SyncHealth,
    CASE 
        WHEN ars.operational_state = 0 THEN 'PENDING_FAILOVER'
        WHEN ars.operational_state = 1 THEN 'PENDING'
        WHEN ars.operational_state = 2 THEN 'ONLINE'
        WHEN ars.operational_state = 3 THEN 'OFFLINE'
        WHEN ars.operational_state = 4 THEN 'FAILED'
        WHEN ars.operational_state = 5 THEN 'FAILED_NOQUORUM'
    END AS OperationalState
FROM sys.availability_groups ag
LEFT JOIN sys.dm_hadr_availability_group_states ars ON ag.group_id = ars.group_id
WHERE (@AvailabilityGroupName IS NULL OR ag.name = @AvailabilityGroupName)
ORDER BY ag.name;

-- ============================================================================
-- 2. REPLICA STATUS
-- ============================================================================
IF @CheckSyncStatus = 1
BEGIN
    PRINT '';
    PRINT '================================================================================';
    PRINT '2. AVAILABILITY REPLICA STATUS';
    PRINT '================================================================================';
    
    SELECT 
        ag.name AS AvailabilityGroupName,
        ar.replica_server_name AS ReplicaServer,
        ar.availability_mode_desc AS AvailabilityMode,
        ar.failover_mode_desc AS FailoverMode,
        ar.primary_role_allow_connections_desc AS PrimaryConnections,
        ar.secondary_role_allow_connections_desc AS SecondaryConnections,
        CASE 
            WHEN rs.is_local = 1 THEN 'LOCAL'
            ELSE 'REMOTE'
        END AS ReplicaLocation,
        CASE 
            WHEN rs.role_desc = 'PRIMARY' THEN 'PRIMARY'
            WHEN rs.role_desc = 'SECONDARY' THEN 'SECONDARY'
            WHEN rs.role_desc = 'RESOLVING' THEN 'RESOLVING'
        END AS CurrentRole,
        CASE 
            WHEN rs.synchronization_state = 0 THEN 'NOT INITIALIZED'
            WHEN rs.synchronization_state = 1 THEN 'INITIALIZED'
            WHEN rs.synchronization_state = 2 THEN 'SYNCHRONIZING'
            WHEN rs.synchronization_state = 3 THEN 'SYNCHRONIZED'
            WHEN rs.synchronization_state = 4 THEN 'REVERTING'
            WHEN rs.synchronization_state = 5 THEN 'INITIALIZING'
        END AS SyncState,
        CASE 
            WHEN rs.synchronization_health = 0 THEN 'NOT HEALTHY'
            WHEN rs.synchronization_health = 1 THEN 'PARTIALLY HEALTHY'
            WHEN rs.synchronization_health = 2 THEN 'HEALTHY'
        END AS SyncHealth,
        rs.last_connect_error_number AS LastErrorNumber,
        rs.last_connect_error_description AS LastErrorDescription,
        rs.last_connect_error_timestamp AS LastErrorTime
    FROM sys.availability_groups ag
    INNER JOIN sys.availability_replicas ar ON ag.group_id = ar.group_id
    INNER JOIN sys.dm_hadr_availability_replica_states rs ON ar.replica_id = rs.replica_id
    WHERE (@AvailabilityGroupName IS NULL OR ag.name = @AvailabilityGroupName)
    ORDER BY ag.name, rs.role_desc, ar.replica_server_name;
    
    -- Check for unhealthy replicas
    IF EXISTS (
        SELECT 1 FROM sys.dm_hadr_availability_replica_states rs
        INNER JOIN sys.availability_groups ag ON rs.group_id = ag.group_id
        WHERE (@AvailabilityGroupName IS NULL OR ag.name = @AvailabilityGroupName)
        AND rs.synchronization_health <> 2
    )
    BEGIN
        PRINT '';
        PRINT '*** WARNING: Unhealthy replicas detected! Review above status. ***';
    END
END

-- ============================================================================
-- 3. DATABASE SYNCHRONIZATION STATUS
-- ============================================================================
IF @CheckSyncStatus = 1
BEGIN
    PRINT '';
    PRINT '================================================================================';
    PRINT '3. DATABASE SYNCHRONIZATION STATUS';
    PRINT '================================================================================';
    
    SELECT 
        ag.name AS AvailabilityGroupName,
        db.database_name AS DatabaseName,
        ar.replica_server_name AS ReplicaServer,
        CASE 
            WHEN drs.synchronization_state = 0 THEN 'NOT INITIALIZED'
            WHEN drs.synchronization_state = 1 THEN 'INITIALIZED'
            WHEN drs.synchronization_state = 2 THEN 'SYNCHRONIZING'
            WHEN drs.synchronization_state = 3 THEN 'SYNCHRONIZED'
            WHEN drs.synchronization_state = 4 THEN 'REVERTING'
            WHEN drs.synchronization_state = 5 THEN 'INITIALIZING'
        END AS SyncState,
        CASE 
            WHEN drs.synchronization_health = 0 THEN 'NOT HEALTHY'
            WHEN drs.synchronization_health = 1 THEN 'PARTIALLY HEALTHY'
            WHEN drs.synchronization_health = 2 THEN 'HEALTHY'
        END AS SyncHealth,
        drs.redo_queue_size AS RedoQueueSize_KB,
        drs.redo_rate AS RedoRate_KB_per_sec,
        drs.log_send_queue_size AS LogSendQueueSize_KB,
        drs.log_send_rate AS LogSendRate_KB_per_sec,
        CAST(drs.redo_queue_size / NULLIF(drs.redo_rate, 0) AS DECIMAL(18,2)) AS EstimatedRedoTime_Seconds,
        CAST(drs.log_send_queue_size / NULLIF(drs.log_send_rate, 0) AS DECIMAL(18,2)) AS EstimatedSendTime_Seconds
    FROM sys.dm_hadr_database_replica_states drs
    INNER JOIN sys.availability_replicas ar ON drs.replica_id = ar.replica_id
    INNER JOIN sys.availability_groups ag ON ar.group_id = ag.group_id
    INNER JOIN sys.availability_databases_cluster db ON drs.database_id = db.database_id
    WHERE (@AvailabilityGroupName IS NULL OR ag.name = @AvailabilityGroupName)
    ORDER BY ag.name, db.database_name, ar.replica_server_name;
    
    -- Alert on high queue sizes
    IF EXISTS (
        SELECT 1 FROM sys.dm_hadr_database_replica_states drs
        INNER JOIN sys.availability_groups ag ON drs.group_id = ag.group_id
        WHERE (@AvailabilityGroupName IS NULL OR ag.name = @AvailabilityGroupName)
        AND (drs.redo_queue_size > 10485760 OR drs.log_send_queue_size > 10485760) -- > 10 MB
    )
    BEGIN
        PRINT '';
        PRINT '*** WARNING: High queue sizes detected! Check network latency and replica performance. ***';
    END
END

-- ============================================================================
-- 4. FAILOVER READINESS
-- ============================================================================
IF @CheckFailoverReadiness = 1
BEGIN
    PRINT '';
    PRINT '================================================================================';
    PRINT '4. FAILOVER READINESS ASSESSMENT';
    PRINT '================================================================================';
    
    SELECT 
        ag.name AS AvailabilityGroupName,
        ar.replica_server_name AS ReplicaServer,
        CASE 
            WHEN rs.role_desc = 'PRIMARY' THEN 'PRIMARY'
            ELSE 'SECONDARY'
        END AS CurrentRole,
        ar.failover_mode_desc AS FailoverMode,
        CASE 
            WHEN rs.synchronization_state = 3 AND ar.failover_mode_desc = 'AUTOMATIC' 
                THEN 'READY FOR AUTOMATIC FAILOVER'
            WHEN rs.synchronization_state = 3 AND ar.failover_mode_desc = 'MANUAL'
                THEN 'READY FOR MANUAL FAILOVER'
            WHEN rs.synchronization_state <> 3
                THEN 'NOT READY - SYNCHRONIZATION IN PROGRESS'
            ELSE 'UNKNOWN'
        END AS FailoverReadiness,
        rs.synchronization_state_desc AS SyncState,
        CASE 
            WHEN rs.last_connect_error_number IS NOT NULL THEN 'CONNECTION ERRORS DETECTED'
            ELSE 'NO CONNECTION ERRORS'
        END AS ConnectionStatus
    FROM sys.availability_groups ag
    INNER JOIN sys.availability_replicas ar ON ag.group_id = ar.group_id
    INNER JOIN sys.dm_hadr_availability_replica_states rs ON ar.replica_id = rs.replica_id
    WHERE (@AvailabilityGroupName IS NULL OR ag.name = @AvailabilityGroupName)
    ORDER BY ag.name, rs.role_desc, ar.replica_server_name;
END

-- ============================================================================
-- 5. PERFORMANCE METRICS (if requested)
-- ============================================================================
IF @CheckPerformance = 1
BEGIN
    PRINT '';
    PRINT '================================================================================';
    PRINT '5. REPLICATION PERFORMANCE METRICS';
    PRINT '================================================================================';
    
    SELECT 
        ag.name AS AvailabilityGroupName,
        db.database_name AS DatabaseName,
        ar.replica_server_name AS ReplicaServer,
        CAST(AVG(drs.redo_rate) AS DECIMAL(18,2)) AS AvgRedoRate_KB_per_sec,
        CAST(AVG(drs.log_send_rate) AS DECIMAL(18,2)) AS AvgLogSendRate_KB_per_sec,
        CAST(MAX(drs.redo_queue_size) AS BIGINT) AS MaxRedoQueueSize_KB,
        CAST(MAX(drs.log_send_queue_size) AS BIGINT) AS MaxLogSendQueueSize_KB,
        COUNT(*) AS SampleCount
    FROM sys.dm_hadr_database_replica_states drs
    INNER JOIN sys.availability_replicas ar ON drs.replica_id = ar.replica_id
    INNER JOIN sys.availability_groups ag ON ar.group_id = ag.group_id
    INNER JOIN sys.availability_databases_cluster db ON drs.database_id = db.database_id
    WHERE (@AvailabilityGroupName IS NULL OR ag.name = @AvailabilityGroupName)
    GROUP BY ag.name, db.database_name, ar.replica_server_name
    ORDER BY ag.name, db.database_name;
END

-- ============================================================================
-- SUMMARY AND RECOMMENDATIONS
-- ============================================================================
PRINT '';
PRINT '================================================================================';
PRINT 'MONITORING RECOMMENDATIONS';
PRINT '================================================================================';
PRINT '';
PRINT '1. AUTOMATED MONITORING:';
PRINT '   - Set up SQL Agent alerts for synchronization health changes';
PRINT '   - Use Azure Monitor for Managed Instance (if applicable)';
PRINT '   - Configure email notifications for AG state changes';
PRINT '';
PRINT '2. REGULAR HEALTH CHECKS:';
PRINT '   - Run this script daily or via SQL Agent job';
PRINT '   - Review synchronization lag metrics';
PRINT '   - Validate failover readiness regularly';
PRINT '';
PRINT '3. BACKUP STRATEGY:';
PRINT '   - Use Ola Hallengren''s DatabaseBackup with AG awareness';
PRINT '   - Backup from secondary replicas to reduce primary load';
PRINT '   - Configure backup preferences in AG';
PRINT '';
PRINT '4. CLOUD-SPECIFIC:';
PRINT '   - Azure SQL Managed Instance: Built-in monitoring via Portal';
PRINT '   - Azure SQL Database: Use Active Geo-Replication monitoring';
PRINT '   - Azure VM SQL Server: Same as on-premises';
PRINT '';
PRINT '================================================================================';
GO

