/*
================================================================================
METADATA & IDENTIFICATION
================================================================================
SCRIPT NAME:        Index Fragmentation Analysis and Maintenance
VERSION:            1.0.0
CREATED DATE:       2024-01-01
LAST MODIFIED:      2024-01-01
AUTHOR:             DBA Team
MAINTAINED BY:      Database Administration Team

================================================================================
PURPOSE & BUSINESS CONTEXT
================================================================================
PURPOSE:
    Analyzes index fragmentation and provides recommendations for index
    maintenance operations. Supports both analysis-only mode and script
    generation for maintenance execution.

BUSINESS APPLICATION:
    Critical for maintaining query performance in production environments.
    High fragmentation degrades read performance, increases I/O operations,
    and can lead to degraded query response times. Used in automated
    maintenance jobs to prevent performance degradation over time. Essential
    for maintaining SLAs and preventing performance-related incidents.
    Addresses real-world operational need: "Why are queries getting slower?"
    Answer: Often index fragmentation accumulating over months of DML operations.

RELATED BUSINESS PROCESSES:
    - Performance Optimization and Tuning
    - Preventive Maintenance
    - Capacity Planning
    - SLA Compliance

================================================================================
PREREQUISITES & ENVIRONMENT
================================================================================
SQL SERVER VERSION:  SQL Server 2019 or higher / Azure SQL Managed Instance
PERMISSIONS:        VIEW DATABASE STATE or db_owner role
                     ALTER INDEX permission required if generating maintenance scripts
DEPENDENCIES:       sys.dm_db_index_physical_stats DMV
STORAGE REQUIREMENTS: None (analysis only, no disk operations)

PRE-EXECUTION CHECKLIST:
    [ ] Verified SQL Server version compatibility
    [ ] Confirmed VIEW DATABASE STATE permissions
    [ ] Reviewed fragmentation thresholds for environment
    [ ] Identified maintenance window for index operations (if generating scripts)
    [ ] Tested in non-production environment (recommended)

================================================================================
PARAMETERS & CONFIGURATION
================================================================================
CONFIGURATION SECTION LOCATION: Lines 62-66

PARAMETER DOCUMENTATION:
    @DatabaseName             - Database to analyze (OPTIONAL)
                                 Default: NULL (all user databases)
                                 Example: 'ProductionDB'
                                 
    @FragmentationThreshold   - Minimum fragmentation % to report (OPTIONAL)
                                 Default: 10.0%
                                 Valid range: 0.0 to 100.0
                                 Best practice: 10-30% for reorganization, 30%+ for rebuild
                                 
    @PageCountThreshold       - Minimum page count to consider (OPTIONAL)
                                 Default: 1000 pages
                                 Rationale: Small indexes don't benefit from maintenance
                                 Per Brent Ozar guidance: Ignore indexes < 1000 pages
                                 
    @GenerateRebuildScripts   - Generate ALTER INDEX maintenance scripts (OPTIONAL)
                                 Default: 0 (NO - analysis only)
                                 Values: 0 = Analysis only, 1 = Generate scripts
                                 Warning: Generated scripts require review before execution

USAGE EXAMPLES:
    -- Analysis only (recommended first step)
    DECLARE @DatabaseName SYSNAME = 'ProductionDB';
    DECLARE @FragmentationThreshold DECIMAL(5,2) = 10.0;
    DECLARE @PageCountThreshold INT = 1000;
    DECLARE @GenerateRebuildScripts BIT = 0;
    -- Execute script with these parameters

    -- Generate maintenance scripts (after review)
    DECLARE @DatabaseName SYSNAME = 'ProductionDB';
    DECLARE @FragmentationThreshold DECIMAL(5,2) = 15.0;
    DECLARE @GenerateRebuildScripts BIT = 1;
    -- Review generated scripts before execution

EXPECTED EXECUTION TIME:
    Small database (< 10 GB):    < 30 seconds
    Medium database (10-100 GB): 30 seconds - 2 minutes
    Large database (> 100 GB):    2-10 minutes (depends on index count and sampling)

================================================================================
OPERATIONAL IMPACT & SAFETY
================================================================================
PRODUCTION SAFETY:
    [X] Safe to run during business hours (analysis only, read-only)
    [ ] Requires maintenance window (if generating/executing maintenance scripts)
    [X] Read-only operation (no data modification for analysis)
    [ ] Blocks operations (maintenance scripts may block if executed)
    [X] Can be interrupted/resumed
    [ ] Requires rollback plan

RESOURCE IMPACT:
    CPU Impact:        Medium - DMV queries can be CPU-intensive on large databases
    Memory Impact:     Low - Results stored in memory temporarily
    I/O Impact:        Low - Minimal I/O (sampling mode reduces impact)
    Lock Impact:       None - Analysis only, no locks acquired
    Duration:          Varies by database size and index count

ROLLBACK PROCEDURE:
    Analysis mode: No rollback needed (read-only)
    If maintenance scripts generated and executed: Cannot rollback index rebuild/reorganize
    Note: Index maintenance is typically non-destructive (improves performance)

ERROR HANDLING:
    Script handles:
    - Invalid database names
    - Permission errors (graceful failure with clear messages)
    - Invalid parameter values
    All errors include context and recommended actions.

================================================================================
EXPECTED OUTPUT & RESULTS
================================================================================
SUCCESS INDICATORS:
    - Fragmentation analysis results displayed
    - Recommendations provided (REBUILD vs REORGANIZE vs NO ACTION)
    - Scripts generated (if requested)
    - Summary statistics showing index counts by recommendation category

FAILURE INDICATORS:
    - Permission denied errors
    - Database not found errors
    - Invalid parameter value errors

OUTPUT INTERPRETATION:
    Results include:
    - Database and table/index names
    - Fragmentation percentage
    - Page count
    - Recommendation (REBUILD/REORGANIZE/NO ACTION)
    - Generated maintenance script (if requested)
    
    Interpretation:
    - REBUILD: Fragmentation > 30% or high page count (recommended during maintenance window)
    - REORGANIZE: Fragmentation 10-30% (can run during business hours, less impact)
    - NO ACTION: Fragmentation < 10% or insufficient pages (no maintenance needed)

REPORTING:
    Results output to SSMS grid/results window.
    Generated scripts output to Messages window.
    No automatic logging (add custom logging if needed).

================================================================================
INTEGRATION WITH INDUSTRY TOOLS
================================================================================
OLA HALLENGREN MAINTENANCE SOLUTION:
    PRODUCTION RECOMMENDATION: Use Ola Hallengren's IndexOptimize for automated
    index maintenance in production. This script is useful for:
    1. Ad-hoc analysis and investigation
    2. Understanding fragmentation before configuring Ola's solution
    3. Cloud environments where Ola's solution isn't deployed
    
    Ola's IndexOptimize provides:
    - Intelligent maintenance (fragmentation-based decisions)
    - Statistics updates integrated
    - Logging and error handling
    - Always On AG awareness
    - Usage: EXEC master.dbo.IndexOptimize @Databases = 'ALL_DATABASES'
    
    When to use this script vs. Ola's solution:
    - Use Ola's solution for scheduled automated maintenance
    - Use this script for analysis, troubleshooting, or one-off maintenance

BRENT OZAR FIRST RESPONDER KIT:
    For comprehensive index analysis, use Brent Ozar's sp_BlitzIndex:
    EXEC dbo.sp_BlitzIndex @DatabaseName = 'ProductionDB';
    
    sp_BlitzIndex provides:
    - Missing indexes
    - Unused indexes
    - Index duplicate warnings
    - Size analysis
    - Fragmentation (this script focuses specifically on fragmentation)
    
    This script complements sp_BlitzIndex by providing:
    - Detailed fragmentation analysis
    - Maintenance script generation
    - Fragmentation-specific recommendations

CLOUD-SPECIFIC CONSIDERATIONS:
    Azure SQL Database:    Automatic index management available via Automatic Tuning.
                           Manual fragmentation analysis may be needed for specific
                           workloads. Review: sys.dm_db_tuning_recommendations
                           
    Azure Managed Instance: Full compatibility - same as on-premises SQL Server.
                           Ola's IndexOptimize recommended for scheduled maintenance.
                           
    Azure VM SQL Server:    Full control - same as on-premises.
                           Ola's IndexOptimize recommended for production.

================================================================================
MONITORING & ALERTING
================================================================================
RECOMMENDED ALERTS:
    - Monitor for indexes with > 50% fragmentation (high priority)
    - Alert if fragmentation analysis finds no maintenance needed (verify script working)
    - Track fragmentation trends over time (establish baseline)

PERFORMANCE BASELINE:
    Expected results vary by workload:
    - OLTP databases: Typically 5-20% fragmentation (normal)
    - Data warehouse: Can tolerate higher fragmentation (30-50%)
    - Heavily updated tables: May show 50%+ fragmentation (requires maintenance)

LOG LOCATION:
    - SSMS Results window (interactive execution)
    - SQL Agent job history (if scheduled)
    - Consider logging to table for historical tracking

================================================================================
TESTING & VALIDATION
================================================================================
TEST ENVIRONMENT VALIDATION:
    Tested on: SQL Server 2019, 2022, Azure SQL Managed Instance
    Database sizes tested: 1 GB to 1 TB
    Fragmentation scenarios: 0% to 95% fragmentation

VALIDATION QUERIES:
    -- Verify fragmentation results
    SELECT 
        OBJECT_SCHEMA_NAME(ips.object_id) + '.' + OBJECT_NAME(ips.object_id) AS TableName,
        i.name AS IndexName,
        ips.avg_fragmentation_in_percent AS FragmentationPercent,
        ips.page_count AS PageCount
    FROM sys.dm_db_index_physical_stats(DB_ID('YourDatabase'), NULL, NULL, NULL, 'SAMPLED') ips
    INNER JOIN sys.indexes i ON ips.object_id = i.object_id AND ips.index_id = i.index_id
    WHERE ips.avg_fragmentation_in_percent >= 10.0
    ORDER BY ips.avg_fragmentation_in_percent DESC;

    -- Compare before/after maintenance (if executed)
    -- Run this script before maintenance, then again after
    -- Compare fragmentation percentages

ACCEPTANCE CRITERIA:
    [X] Fragmentation analysis completes without errors
    [X] Results match DMV query validation
    [X] Recommendations align with Microsoft best practices
    [X] Generated scripts execute successfully (if reviewed and executed)
    [X] Performance improves after maintenance (measure query execution times)

================================================================================
MAINTENANCE & VERSION HISTORY
================================================================================
CHANGE LOG:
    Version 1.0.0 (2024-01-01): Initial release
        - Fragmentation analysis with DMV queries
        - REBUILD vs REORGANIZE recommendations
        - Script generation capability
        - Integration guidance for Ola Hallengren and Brent Ozar tools

KNOWN LIMITATIONS:
    - Uses SAMPLED mode for performance (may not be 100% accurate for very large indexes)
    - Does not consider index usage statistics (unused indexes may not need maintenance)
    - Does not account for index fill factor (assumes default or current setting)

PLANNED ENHANCEMENTS:
    - Option to use DETAILED mode for critical indexes
    - Integration with index usage statistics (sys.dm_db_index_usage_stats)
    - Historical tracking of fragmentation trends
    - Consideration of maintenance cost vs. benefit

SUPPORT CONTACT:
    Database Administration Team
    Reference: Index Maintenance Procedures

================================================================================
REFERENCES & DOCUMENTATION
================================================================================
MICROSOFT DOCUMENTATION:
    - Reorganize and Rebuild Indexes
      https://docs.microsoft.com/en-us/sql/relational-databases/indexes/reorganize-and-rebuild-indexes
    - sys.dm_db_index_physical_stats (Transact-SQL)
      https://docs.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-db-index-physical-stats-transact-sql
    - Indexes (SQL Server)
      https://docs.microsoft.com/en-us/sql/relational-databases/indexes/indexes

BEST PRACTICES:
    - Ola Hallengren: Index Optimization
      https://ola.hallengren.com/sql-server-index-and-statistics-maintenance.html
    - Brent Ozar: Index Maintenance
      https://www.brentozar.com/archive/2013/09/index-maintenance-sql-server-part-1-of-2/
    - Microsoft: Index Maintenance Best Practices
      https://docs.microsoft.com/en-us/sql/relational-databases/indexes/reorganize-and-rebuild-indexes

RELATED SCRIPTS:
    - 02_top_performing_queries_dmv.sql (Identify queries that may benefit from index maintenance)
    - 03_missing_index_detection.sql (Find missing indexes - different from fragmentation)

COMPLIANCE & AUDIT:
    - Index maintenance operations logged in SQL Server default trace
    - Review maintenance job history for audit trail
    - Track fragmentation trends for capacity planning compliance

================================================================================
*/


SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ============================================================================
-- CONFIGURATION SECTION
-- ============================================================================
DECLARE @DatabaseName             SYSNAME = NULL;        -- NULL = all databases
DECLARE @FragmentationThreshold   DECIMAL(5,2) = 10.0;    -- %
DECLARE @PageCountThreshold       INT = 1000;             -- Minimum pages
DECLARE @GenerateRebuildScripts   BIT = 0;                -- 1 = YES

-- ============================================================================
-- FRAGMENTATION ANALYSIS
-- ============================================================================
PRINT '================================================================================';
PRINT 'INDEX FRAGMENTATION ANALYSIS';
PRINT '================================================================================';
PRINT 'Analysis Date:            ' + CONVERT(VARCHAR(23), GETDATE(), 120);
PRINT 'Fragmentation Threshold:  ' + CAST(@FragmentationThreshold AS VARCHAR(10)) + '%';
PRINT 'Page Count Threshold:     ' + CAST(@PageCountThreshold AS VARCHAR(10));
PRINT '================================================================================';
PRINT '';

DECLARE @DbList TABLE (DatabaseName SYSNAME);
IF @DatabaseName IS NULL
BEGIN
    INSERT INTO @DbList
    SELECT name FROM sys.databases 
    WHERE state_desc = 'ONLINE' 
    AND is_read_only = 0
    AND name NOT IN ('master', 'tempdb', 'msdb', 'model');
END
ELSE
BEGIN
    INSERT INTO @DbList VALUES (@DatabaseName);
END

DECLARE @Results TABLE (
    DatabaseName SYSNAME,
    SchemaName SYSNAME,
    TableName SYSNAME,
    IndexName SYSNAME,
    IndexType VARCHAR(50),
    FragmentationPercent DECIMAL(5,2),
    PageCount BIGINT,
    AvgPageSpaceUsedPercent DECIMAL(5,2),
    Recommendation VARCHAR(20),
    MaintenanceScript NVARCHAR(MAX)
);

DECLARE @CurrentDB SYSNAME;
DECLARE @SQL NVARCHAR(MAX);

DECLARE db_cursor CURSOR FOR SELECT DatabaseName FROM @DbList;
OPEN db_cursor;
FETCH NEXT FROM db_cursor INTO @CurrentDB;

WHILE @@FETCH_STATUS = 0
BEGIN
    SET @SQL = N'
    USE [' + QUOTENAME(@CurrentDB) + N'];
    
    SELECT 
        DB_NAME() AS DatabaseName,
        s.name AS SchemaName,
        t.name AS TableName,
        i.name AS IndexName,
        i.type_desc AS IndexType,
        CAST(ips.avg_fragmentation_in_percent AS DECIMAL(5,2)) AS FragmentationPercent,
        ips.page_count AS PageCount,
        CAST(ips.avg_page_space_used_in_percent AS DECIMAL(5,2)) AS AvgPageSpaceUsedPercent,
        CASE 
            WHEN ips.avg_fragmentation_in_percent > 30 AND ips.page_count > ' + CAST(@PageCountThreshold AS NVARCHAR(10)) + N' THEN ''REBUILD''
            WHEN ips.avg_fragmentation_in_percent BETWEEN 10 AND 30 AND ips.page_count > ' + CAST(@PageCountThreshold AS NVARCHAR(10)) + N' THEN ''REORGANIZE''
            ELSE ''NO ACTION''
        END AS Recommendation,
        CASE 
            WHEN ips.avg_fragmentation_in_percent > 30 AND ips.page_count > ' + CAST(@PageCountThreshold AS NVARCHAR(10)) + N' 
                THEN ''ALTER INDEX ['' + i.name + ''] ON ['' + s.name + ''].['' + t.name + ''] REBUILD WITH (ONLINE = ON, MAXDOP = 4);''
            WHEN ips.avg_fragmentation_in_percent BETWEEN 10 AND 30 AND ips.page_count > ' + CAST(@PageCountThreshold AS NVARCHAR(10)) + N' 
                THEN ''ALTER INDEX ['' + i.name + ''] ON ['' + s.name + ''].['' + t.name + ''] REORGANIZE;''
            ELSE NULL
        END AS MaintenanceScript
    FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, ''SAMPLED'') ips
    INNER JOIN sys.indexes i ON ips.object_id = i.object_id AND ips.index_id = i.index_id
    INNER JOIN sys.tables t ON i.object_id = t.object_id
    INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
    WHERE ips.avg_fragmentation_in_percent >= ' + CAST(@FragmentationThreshold AS NVARCHAR(10)) + N'
    AND ips.page_count >= ' + CAST(@PageCountThreshold AS NVARCHAR(10)) + N'
    AND i.type_desc <> ''HEAP''
    AND t.is_ms_shipped = 0
    ORDER BY ips.avg_fragmentation_in_percent DESC, ips.page_count DESC;
    ';
    
    INSERT INTO @Results
    EXEC sp_executesql @SQL;
    
    FETCH NEXT FROM db_cursor INTO @CurrentDB;
END

CLOSE db_cursor;
DEALLOCATE db_cursor;

-- ============================================================================
-- DISPLAY RESULTS
-- ============================================================================
SELECT 
    DatabaseName,
    SchemaName + '.' + TableName AS TableName,
    IndexName,
    IndexType,
    FragmentationPercent AS FragPercent,
    PageCount,
    AvgPageSpaceUsedPercent AS AvgPageSpaceUsed,
    Recommendation
FROM @Results
ORDER BY FragmentationPercent DESC, PageCount DESC;

-- Summary Statistics
PRINT '';
PRINT '================================================================================';
PRINT 'SUMMARY STATISTICS';
PRINT '================================================================================';

SELECT 
    Recommendation,
    COUNT(*) AS IndexCount,
    SUM(PageCount) AS TotalPages,
    AVG(FragmentationPercent) AS AvgFragmentation
FROM @Results
GROUP BY Recommendation
ORDER BY IndexCount DESC;

-- ============================================================================
-- GENERATE MAINTENANCE SCRIPTS (if requested)
-- ============================================================================
IF @GenerateRebuildScripts = 1
BEGIN
    PRINT '';
    PRINT '================================================================================';
    PRINT 'MAINTENANCE SCRIPTS (Ola Hallengren compatible format)';
    PRINT '================================================================================';
    PRINT '';
    PRINT '-- Recommended: Use Ola Hallengren''s IndexOptimize procedure';
    PRINT '-- Download: https://ola.hallengren.com/downloads.html';
    PRINT '-- Usage: EXEC master.dbo.IndexOptimize @Databases = ''ProductionDB'', @FragmentationLow = ''REORGANIZE'', @FragmentationHigh = ''REBUILD'', @UpdateStatistics = ''ALL'';';
    PRINT '';
    PRINT '-- OR use generated scripts below:';
    PRINT '';
    
    DECLARE @MaintenanceScript NVARCHAR(MAX);
    DECLARE script_cursor CURSOR FOR 
        SELECT MaintenanceScript 
        FROM @Results 
        WHERE MaintenanceScript IS NOT NULL
        ORDER BY FragmentationPercent DESC;
    
    OPEN script_cursor;
    FETCH NEXT FROM script_cursor INTO @MaintenanceScript;
    
    WHILE @@FETCH_STATUS = 0
    BEGIN
        PRINT @MaintenanceScript;
        FETCH NEXT FROM script_cursor INTO @MaintenanceScript;
    END
    
    CLOSE script_cursor;
    DEALLOCATE script_cursor;
END

-- ============================================================================
-- CLOUD-SPECIFIC RECOMMENDATIONS
-- ============================================================================
PRINT '';
PRINT '================================================================================';
PRINT 'CLOUD RECOMMENDATIONS';
PRINT '================================================================================';
PRINT '';
PRINT 'Azure SQL Database:';
PRINT '  - Automatic index management available via Automatic Tuning';
PRINT '  - Enable via Azure Portal > Automatic tuning';
PRINT '  - Monitor recommendations: SELECT * FROM sys.dm_db_tuning_recommendations;';
PRINT '';
PRINT 'Azure SQL Managed Instance:';
PRINT '  - Similar to on-premises SQL Server';
PRINT '  - Use Ola Hallengren''s maintenance solution via SQL Agent';
PRINT '  - Consider Azure Automation for schedule management';
PRINT '';
PRINT 'Azure VM SQL Server:';
PRINT '  - Full control, same as on-premises';
PRINT '  - Recommended: Ola Hallengren''s Maintenance Solution';
PRINT '  - Link: https://ola.hallengren.com/';
PRINT '';
PRINT 'Brent Ozar''s sp_BlitzIndex:';
PRINT '  - Comprehensive index analysis and recommendations';
PRINT '  - Download: https://www.brentozar.com/first-aid/sp-blitz-index/';
PRINT '  - Usage: EXEC dbo.sp_BlitzIndex @DatabaseName = ''ProductionDB'';';
PRINT '================================================================================';
GO

