# TempDB Full - Incident Response Runbook

## Severity
**HIGH** - TempDB full can cause application failures, blocking, and database unavailability.

## Symptoms
- Error messages: "Could not allocate space for object in database 'tempdb'"
- Queries failing with tempdb-related errors
- Blocking sessions waiting on tempdb resources
- High tempdb space utilization (near 100%)
- Application errors related to temporary objects

## Immediate Actions

### 1. Assess the Situation
```sql
-- Check tempdb space usage
SELECT 
    name AS FileName,
    type_desc AS FileType,
    physical_name AS PhysicalPath,
    size * 8.0 / 1024 AS Size_MB,
    CAST(FILEPROPERTY(name, 'SpaceUsed') * 8.0 / 1024 AS DECIMAL(10,2)) AS Used_MB,
    CAST((size - FILEPROPERTY(name, 'SpaceUsed')) * 8.0 / 1024 AS DECIMAL(10,2)) AS Free_MB,
    CAST((FILEPROPERTY(name, 'SpaceUsed') * 100.0 / size) AS DECIMAL(5,2)) AS PercentUsed
FROM sys.master_files
WHERE database_id = 2; -- tempdb

-- Check what's using tempdb
SELECT 
    session_id,
    database_id,
    user_objects_alloc_page_count * 8.0 / 1024 AS UserObjects_MB,
    internal_objects_alloc_page_count * 8.0 / 1024 AS InternalObjects_MB,
    user_objects_dealloc_page_count * 8.0 / 1024 AS UserObjectsDealloc_MB,
    internal_objects_dealloc_page_count * 8.0 / 1024 AS InternalObjectsDealloc_MB
FROM sys.dm_db_session_space_usage
WHERE database_id = 2
ORDER BY (user_objects_alloc_page_count + internal_objects_alloc_page_count) DESC;

-- Find active sessions using tempdb
SELECT 
    s.session_id,
    s.login_name,
    s.program_name,
    s.status,
    DB_NAME(s.database_id) AS DatabaseName,
    t.text AS QueryText,
    r.wait_type,
    r.wait_time,
    r.blocking_session_id
FROM sys.dm_exec_sessions s
INNER JOIN sys.dm_exec_requests r ON s.session_id = r.session_id
CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t
WHERE s.database_id = 2
AND r.status = 'running'
ORDER BY r.wait_time DESC;
```

### 2. Quick Fix - Clear TempDB (If Safe)
**WARNING**: This will kill active queries using tempdb. Only do this if you understand the impact.

```sql
-- Option 1: Kill specific problematic sessions (recommended)
-- First, identify the sessions from step 1, then:
KILL <session_id>; -- Replace with actual session ID

-- Option 2: Restart SQL Server service (most reliable)
-- This clears all tempdb data
-- Schedule during maintenance window if possible
```

### 3. Immediate Space Relief
```sql
-- Check if auto-grow is enabled
SELECT 
    name,
    growth,
    is_percent_growth,
    CASE 
        WHEN is_percent_growth = 1 THEN CAST(growth AS VARCHAR) + '%'
        ELSE CAST(growth * 8.0 / 1024 AS VARCHAR) + ' MB'
    END AS GrowthSetting,
    max_size,
    CASE 
        WHEN max_size = -1 THEN 'UNLIMITED'
        ELSE CAST(max_size * 8.0 / 1024 AS VARCHAR) + ' MB'
    END AS MaxSize
FROM sys.master_files
WHERE database_id = 2;

-- Manually grow tempdb files if needed (requires disk space)
ALTER DATABASE tempdb MODIFY FILE (
    NAME = 'tempdev',
    SIZE = 10GB, -- Adjust based on your needs
    FILEGROWTH = 1GB
);
```

## Root Cause Analysis

### Common Causes
1. **Large Sort Operations**
   - Queries with large ORDER BY, GROUP BY, or DISTINCT
   - Missing indexes causing table scans

2. **Hash Joins**
   - Large hash joins spilling to tempdb
   - Inadequate memory grants

3. **Index Maintenance**
   - Index rebuild operations using tempdb
   - Large index creation/rebuild jobs

4. **Temp Tables and Table Variables**
   - Excessive use of temporary objects
   - Large temp tables not cleaned up

5. **DBCC Operations**
   - DBCC CHECKDB on large databases
   - Other DBCC maintenance operations

### Investigation Queries
```sql
-- Find queries using temp tables
SELECT 
    st.text AS QueryText,
    qs.execution_count,
    qs.total_worker_time / 1000.0 AS TotalCPUTime_ms,
    qs.total_logical_reads,
    qs.last_execution_time
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
WHERE st.text LIKE '%#%' OR st.text LIKE '%@%table%'
ORDER BY qs.total_worker_time DESC;

-- Check for missing indexes that might cause sorts
EXEC dbo.sp_BlitzIndex @DatabaseName = 'YourDatabase'; -- Brent Ozar's tool
```

## Permanent Fixes

### 1. Optimize TempDB Configuration
```sql
-- Best Practice: Multiple tempdb data files
-- One file per CPU core, up to 8 files
-- See: scripts/database/mssql/administration/03_configure_instance_settings.sql

-- Set tempdb files to equal size
-- Set appropriate growth settings (not too small, not too large)
```

### 2. Optimize Problematic Queries
- Add missing indexes
- Rewrite queries to reduce sorting
- Increase memory grants for hash joins
- Consider query hints if appropriate

### 3. Schedule Maintenance Windows
- Run index maintenance during off-peak hours
- Schedule DBCC CHECKDB during maintenance windows
- Consider using Ola Hallengren's maintenance solution with proper scheduling

### 4. Monitor Proactively
```sql
-- Set up alert for tempdb space usage
-- SQL Agent Alert: Performance condition
-- Counter: SQLServer:Databases - Data File(s) Size (KB) - tempdb
-- Alert when: Rises above threshold (e.g., 80% of allocated space)
```

## Prevention

### Daily Checks
- Include tempdb space usage in daily health checks
- Monitor tempdb growth trends
- Review query performance regularly

### Best Practices
1. **TempDB File Configuration**
   - Multiple data files (1 per CPU core, max 8)
   - Equal file sizes
   - Appropriate growth settings
   - Pre-size files to avoid frequent growth

2. **Query Optimization**
   - Identify and fix queries causing excessive tempdb usage
   - Use Query Store to track problematic queries
   - Regular index maintenance

3. **Monitoring**
   - Set up proactive alerts
   - Track tempdb usage trends
   - Review during capacity planning

## Cloud-Specific Notes

### Azure SQL Database
- TempDB is managed automatically
- Less likely to encounter tempdb full issues
- Monitor via Query Performance Insights

### Azure SQL Managed Instance
- Similar to on-premises SQL Server
- Same troubleshooting steps apply
- Monitor via Azure Monitor

### Azure VM SQL Server
- Same as on-premises
- Consider tempdb placement on fast storage (SSD Premium)

## Related Scripts

- `scripts/database/mssql/monitoring/01_daily_health_check.sql` - Daily monitoring
- `scripts/database/mssql/performance/02_top_performing_queries_dmv.sql` - Find problematic queries
- `scripts/database/mssql/administration/03_configure_instance_settings.sql` - TempDB configuration

## Escalation

If the issue cannot be resolved:
1. Document all attempted steps
2. Collect diagnostic information:
   - TempDB file sizes and usage
   - Problematic session IDs
   - Error messages
   - Application impact
3. Escalate to senior DBA or database team lead
4. Consider engaging Microsoft Support for cloud resources

## Post-Incident

1. **Document**
   - Root cause
   - Resolution steps taken
   - Time to resolution
   - Business impact

2. **Implement Preventive Measures**
   - Update monitoring alerts
   - Optimize identified queries
   - Review tempdb configuration
   - Update runbooks with lessons learned

3. **Review**
   - Conduct post-mortem if significant impact
   - Update capacity planning
   - Review related runbooks

---

**Last Updated**: [Date]  
**Reviewed By**: [Team Name]

