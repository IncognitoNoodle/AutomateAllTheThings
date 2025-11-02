# Transaction Log Full - Incident Response Runbook

## Severity
**CRITICAL** - Transaction log full prevents all write operations and can cause application downtime.

## Symptoms
- Error: "The transaction log for database 'X' is full due to 'LOG_BACKUP'"
- Error: "Could not allocate space for object in database 'X'. The 'PRIMARY' filegroup is full"
- All INSERT, UPDATE, DELETE operations failing
- Database becomes read-only or inaccessible
- High transaction log utilization (near 100%)

## Immediate Actions

### 1. Assess the Situation
```sql
-- Check transaction log size and usage
SELECT 
    DB_NAME(database_id) AS DatabaseName,
    name AS LogicalFileName,
    physical_name AS PhysicalPath,
    size * 8.0 / 1024 AS Size_MB,
    CAST(FILEPROPERTY(name, 'SpaceUsed') * 8.0 / 1024 AS DECIMAL(10,2)) AS Used_MB,
    CAST((size - FILEPROPERTY(name, 'SpaceUsed')) * 8.0 / 1024 AS DECIMAL(10,2)) AS Free_MB,
    CAST((FILEPROPERTY(name, 'SpaceUsed') * 100.0 / size) AS DECIMAL(5,2)) AS PercentUsed,
    max_size,
    CASE 
        WHEN max_size = -1 THEN 'UNLIMITED'
        ELSE CAST(max_size * 8.0 / 1024 AS VARCHAR) + ' MB'
    END AS MaxSize,
    growth,
    CASE 
        WHEN is_percent_growth = 1 THEN CAST(growth AS VARCHAR) + '%'
        ELSE CAST(growth * 8.0 / 1024 AS VARCHAR) + ' MB'
    END AS GrowthSetting
FROM sys.master_files
WHERE type_desc = 'LOG'
AND DB_NAME(database_id) = 'YourDatabase'; -- Replace with actual database

-- Check recovery model and log backup status
SELECT 
    name AS DatabaseName,
    recovery_model_desc AS RecoveryModel,
    log_reuse_wait_desc AS LogReuseWait,
    CASE 
        WHEN is_log_shipping_primary = 1 THEN 'YES'
        ELSE 'NO'
    END AS IsLogShipped,
    CASE 
        WHEN is_published = 1 THEN 'YES'
        ELSE 'NO'
    END AS IsReplicated
FROM sys.databases
WHERE name = 'YourDatabase';

-- Check last log backup
SELECT 
    bs.database_name,
    MAX(bs.backup_finish_date) AS LastLogBackup,
    DATEDIFF(MINUTE, MAX(bs.backup_finish_date), GETDATE()) AS MinutesSinceLastBackup
FROM msdb.dbo.backupset bs
WHERE bs.type = 'L'
AND bs.database_name = 'YourDatabase'
GROUP BY bs.database_name;
```

### 2. Immediate Relief - Backup Transaction Log

**For FULL or BULK_LOGGED Recovery Model:**

```sql
-- BACKUP LOG to free space (if log backups are configured)
BACKUP LOG [YourDatabase]
TO DISK = 'D:\SQLBackups\YourDatabase_Log_' + 
          CONVERT(VARCHAR(23), GETDATE(), 112) + '.trn'
WITH COMPRESSION, INIT;

-- Verify log space freed
DBCC SQLPERF(LOGSPACE);
```

**If backup fails due to space:**

### 3. Emergency Actions (Use with Caution)

#### Option A: Increase Log File Size (If Disk Space Available)
```sql
-- Grow log file immediately
ALTER DATABASE [YourDatabase]
MODIFY FILE (
    NAME = 'YourDatabase_Log', -- Replace with actual log file name
    SIZE = 10GB, -- Adjust based on available space
    FILEGROWTH = 1GB
);

-- Check if space was freed
DBCC SQLPERF(LOGSPACE);
```

#### Option B: Switch to SIMPLE Recovery (LAST RESORT - Data Loss Risk)
**WARNING**: This breaks the log backup chain and prevents point-in-time recovery!

```sql
-- Only use if absolutely necessary and acceptable to lose recovery point
ALTER DATABASE [YourDatabase] SET RECOVERY SIMPLE;

-- This will truncate the log immediately
CHECKPOINT;

-- Switch back to FULL recovery
ALTER DATABASE [YourDatabase] SET RECOVERY FULL;

-- Take immediate full backup to re-establish backup chain
BACKUP DATABASE [YourDatabase]
TO DISK = 'D:\SQLBackups\YourDatabase_Full_AfterSimpleRecovery.bak'
WITH INIT, COMPRESSION;
```

#### Option C: Kill Long-Running Transactions (If Safe)
```sql
-- Find long-running transactions
SELECT 
    s.session_id,
    s.login_name,
    s.program_name,
    DB_NAME(s.database_id) AS DatabaseName,
    t.transaction_id,
    t.transaction_begin_time,
    DATEDIFF(MINUTE, t.transaction_begin_time, GETDATE()) AS TransactionDuration_Minutes,
    st.text AS QueryText
FROM sys.dm_tran_active_transactions t
INNER JOIN sys.dm_tran_session_transactions st2 ON t.transaction_id = st2.transaction_id
INNER JOIN sys.dm_exec_sessions s ON st2.session_id = s.session_id
LEFT JOIN sys.dm_exec_requests r ON s.session_id = r.session_id
CROSS APPLY sys.dm_exec_sql_text(ISNULL(r.sql_handle, s.most_recent_sql_handle)) st
WHERE s.database_id = DB_ID('YourDatabase')
ORDER BY t.transaction_begin_time;

-- If safe to kill:
-- KILL <session_id>; -- Replace with actual session ID
```

## Root Cause Analysis

### Common Causes
1. **Missing Transaction Log Backups**
   - Log backups not configured
   - Log backup job failed
   - Log backup destination full

2. **Long-Running Transactions**
   - Uncommitted transactions holding log space
   - Replication or log shipping delays
   - Open transactions from application bugs

3. **Large Data Operations**
   - Bulk INSERT operations
   - Large UPDATE/DELETE statements
   - Index rebuilds in FULL recovery

4. **Replication/Log Shipping Issues**
   - Transactional replication not reading log
   - Log shipping secondary not applying logs
   - Mirroring partner unavailable

5. **Log File Growth Issues**
   - Log file at max size limit
   - Insufficient disk space for growth
   - Very small growth increment causing many growths

### Investigation Queries
```sql
-- Check what's preventing log truncation
SELECT 
    name,
    log_reuse_wait_desc
FROM sys.databases
WHERE name = 'YourDatabase';

-- Common values:
-- NOTHING - Can truncate
-- CHECKPOINT - Waiting for checkpoint
-- LOG_BACKUP - Waiting for log backup (most common)
-- ACTIVE_BACKUP_OR_RESTORE - Backup/restore in progress
-- ACTIVE_TRANSACTION - Long-running transaction
-- DATABASE_MIRRORING - Mirroring in progress
-- REPLICATION - Replication not reading
-- DATABASE_SNAPSHOT_CREATION - Snapshot being created
-- LOG_SCAN - Log scan in progress
-- AVAILABILITY_REPLICA - Always On replication
-- OTHER_TRANSIENT - Temporary condition

-- Find active transactions preventing truncation
SELECT 
    transaction_id,
    name AS TransactionName,
    transaction_begin_time,
    transaction_type,
    transaction_state,
    transaction_status,
    transaction_status2
FROM sys.dm_tran_active_transactions
ORDER BY transaction_begin_time;
```

## Permanent Fixes

### 1. Establish Regular Log Backups
```sql
-- Set up SQL Agent job for transaction log backups
-- For critical databases: Every 15 minutes
-- For standard databases: Every hour
-- Use Ola Hallengren's DatabaseBackup for production

-- Example: Ola's solution
EXEC master.dbo.DatabaseBackup
    @Databases = 'YourDatabase',
    @BackupType = 'LOG',
    @Verify = 'Y',
    @CleanupTime = 168; -- Keep 7 days
```

### 2. Optimize Log File Configuration
```sql
-- Pre-size log file to avoid frequent growth
-- Set appropriate initial size based on database activity
ALTER DATABASE [YourDatabase]
MODIFY FILE (
    NAME = 'YourDatabase_Log',
    SIZE = 5GB, -- Adjust based on workload
    MAXSIZE = 50GB, -- Or UNLIMITED
    FILEGROWTH = 512MB -- Not too small, not too large
);
```

### 3. Monitor Proactively
```sql
-- Set up SQL Agent Alert for log space
-- Performance Condition Alert:
-- Object: SQLServer:Databases
-- Counter: Percent Log Used
-- Instance: YourDatabase
-- Alert when: Rises above 80%

-- Or use daily health check script
-- scripts/database/mssql/monitoring/01_daily_health_check.sql
```

### 4. Review Recovery Model
```sql
-- For databases that don't need point-in-time recovery
-- Consider SIMPLE recovery model (with approval)
-- This prevents log growth issues but loses point-in-time recovery

-- Review with business stakeholders before changing
```

## Prevention

### Best Practices
1. **Regular Log Backups**
   - Configure automated log backups
   - Verify backup job success
   - Monitor backup destination space

2. **Appropriate Recovery Model**
   - FULL: Production databases requiring point-in-time recovery
   - SIMPLE: Development/test databases, read-heavy databases
   - BULK_LOGGED: Temporary during bulk operations (switch back to FULL)

3. **Monitor Transaction Duration**
   - Set up alerts for long-running transactions
   - Review application code for transaction management
   - Use appropriate transaction isolation levels

4. **Proper Log File Sizing**
   - Pre-size based on workload analysis
   - Monitor growth trends
   - Adjust during capacity planning

### Daily Checks
- Include log space usage in daily health checks
- Verify log backup job success
- Review transaction log growth trends

## Cloud-Specific Notes

### Azure SQL Database
- Automatic backups include transaction logs
- PITR available for 7-35 days
- Long-term retention available
- Less likely to encounter log full issues
- Monitor via Azure Portal > Backups

### Azure SQL Managed Instance
- Similar to on-premises
- Configure log backups via SQL Agent
- Use Ola Hallengren's solution recommended
- Monitor via Azure Monitor

### Azure VM SQL Server
- Same as on-premises
- Ensure backup to Azure Blob Storage
- Monitor storage account capacity

## Related Scripts

- `scripts/database/mssql/backup_restore/01_automated_backup_full_differential_log.sql` - Backup automation
- `scripts/database/mssql/monitoring/01_daily_health_check.sql` - Daily monitoring
- `scripts/database/mssql/backup_restore/03_disaster_recovery_restore.sql` - Recovery procedures

## Escalation

If unable to resolve:
1. Document all steps attempted
2. Collect diagnostic data:
   - Log file size and usage
   - Last successful log backup
   - Active transaction details
   - Recovery model and log_reuse_wait_desc
3. Escalate to senior DBA
4. Consider Microsoft Support for cloud resources
5. If critical business impact, consider emergency failover (if Always On available)

## Post-Incident

1. **Root Cause Analysis**
   - Why did log backups stop?
   - Why did log file grow unexpectedly?
   - What transactions caused the issue?

2. **Preventive Measures**
   - Fix backup job if it failed
   - Optimize problematic queries/transactions
   - Update monitoring and alerts
   - Review log file sizing

3. **Documentation**
   - Update runbook with lessons learned
   - Document resolution steps
   - Update capacity planning

---

**Last Updated**: [Date]  
**Reviewed By**: [Team Name]

