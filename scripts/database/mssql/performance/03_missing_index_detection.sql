/*
================================================================================
SCRIPT: Missing Index Detection and Analysis
================================================================================
PURPOSE:
    Identifies missing indexes that could improve query performance based on
    actual workload patterns captured by SQL Server's missing index DMVs.
    Provides CREATE INDEX scripts and impact estimates.

BUSINESS APPLICATION:
    Identifies high-impact index opportunities to improve query performance
    with minimal overhead. Essential for new application deployments and
    performance tuning. Works for on-premises, Azure SQL Managed Instance,
    and can inform Azure SQL Database automatic tuning.

CLOUD CONSIDERATIONS:
    - Azure SQL Database: Automatic index management via Automatic Tuning
    - Azure SQL Managed Instance: Same as on-premises, manual index creation
    - Both: Query Store provides additional insights

PREREQUISITES:
    - SQL Server 2019+ or Azure SQL Managed Instance
    - Permissions: VIEW SERVER STATE
    - Server restart or significant workload needed for accurate DMV data

PARAMETERS:
    @DatabaseName    - Database to analyze (NULL = all databases)
    @MinImpact       - Minimum improvement % to show (default: 10)
    @TopN            - Number of recommendations (default: 20)
    @GenerateScripts - Generate CREATE INDEX scripts (1 = YES)

RELATED TOOLS:
    - Brent Ozar's sp_BlitzIndex: Comprehensive missing index analysis
      https://www.brentozar.com/first-aid/sp-blitz-index/
    - Ola Hallengren's IndexOptimize: Automated index maintenance
      https://ola.hallengren.com/sql-server-index-and-statistics-maintenance.html

USAGE EXAMPLE:
    EXEC dbo.usp_MissingIndexDetection
        @DatabaseName = 'ProductionDB',
        @MinImpact = 20,
        @TopN = 10,
        @GenerateScripts = 1;

EXPECTED OUTPUT:
    Lists missing indexes with estimated improvement impact.
    Provides CREATE INDEX scripts ready to deploy.
    Shows which queries would benefit from each index.

REFERENCES:
    - Microsoft Docs: sys.dm_db_missing_index_details
      https://docs.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-db-missing-index-details-transact-sql
    - Azure SQL: Automatic Tuning
      https://docs.microsoft.com/en-us/azure/azure-sql/database/automatic-tuning-overview
================================================================================
*/

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ============================================================================
-- CONFIGURATION SECTION
-- ============================================================================
DECLARE @DatabaseName    SYSNAME = NULL;        -- NULL = all databases
DECLARE @MinImpact       DECIMAL(5,2) = 10.0;   -- Minimum improvement %
DECLARE @TopN            INT = 20;              -- Number of recommendations
DECLARE @GenerateScripts BIT = 1;               -- 1 = YES

-- ============================================================================
-- MISSING INDEX ANALYSIS
-- ============================================================================
PRINT '================================================================================';
PRINT 'MISSING INDEX DETECTION';
PRINT '================================================================================';
PRINT 'Analysis Date:     ' + CONVERT(VARCHAR(23), GETDATE(), 120);
PRINT 'Database:          ' + ISNULL(@DatabaseName, 'ALL DATABASES');
PRINT 'Min Impact:         ' + CAST(@MinImpact AS VARCHAR(10)) + '%';
PRINT 'Top N:             ' + CAST(@TopN AS VARCHAR(10));
PRINT '';
PRINT 'NOTE: Missing index DMVs reset after SQL Server restart.';
PRINT '      Ensure server has been running with workload to get accurate data.';
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
    IndexHandle INT,
    SchemaName SYSNAME,
    TableName SYSNAME,
    EqualityColumns NVARCHAR(MAX),
    InequalityColumns NVARCHAR(MAX),
    IncludedColumns NVARCHAR(MAX),
    UserSeeks BIGINT,
    UserScans BIGINT,
    AvgTotalUserCost DECIMAL(18,2),
    AvgUserImpact DECIMAL(5,2),
    SystemSeeks BIGINT,
    SystemScans BIGINT,
    LastUserSeek DATETIME,
    LastUserScan DATETIME,
    CreateIndexScript NVARCHAR(MAX),
    ImpactScore DECIMAL(18,2)
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
        mid.index_handle AS IndexHandle,
        OBJECT_SCHEMA_NAME(mid.object_id) AS SchemaName,
        OBJECT_NAME(mid.object_id) AS TableName,
        mid.equality_columns AS EqualityColumns,
        mid.inequality_columns AS InequalityColumns,
        mid.included_columns AS IncludedColumns,
        migs.user_seeks AS UserSeeks,
        migs.user_scans AS UserScans,
        migs.avg_total_user_cost AS AvgTotalUserCost,
        migs.avg_user_impact AS AvgUserImpact,
        migs.system_seeks AS SystemSeeks,
        migs.system_scans AS SystemScans,
        migs.last_user_seek AS LastUserSeek,
        migs.last_user_scan AS LastUserScan,
        ''-- Index recommendation for '' + OBJECT_SCHEMA_NAME(mid.object_id) + ''.'' + OBJECT_NAME(mid.object_id) + CHAR(13) + CHAR(10) +
        ''-- Estimated improvement: '' + CAST(migs.avg_user_impact AS VARCHAR(10)) + ''%'' + CHAR(13) + CHAR(10) +
        ''-- User seeks: '' + CAST(migs.user_seeks AS VARCHAR(20)) + '', User scans: '' + CAST(migs.user_scans AS VARCHAR(20)) + CHAR(13) + CHAR(10) +
        ''CREATE NONCLUSTERED INDEX [IX_'' + OBJECT_SCHEMA_NAME(mid.object_id) + ''_' + OBJECT_NAME(mid.object_id) + ''_' +
        CASE 
            WHEN mid.equality_columns IS NOT NULL THEN REPLACE(REPLACE(REPLACE(LEFT(mid.equality_columns, 50), ''['', ''''), '']'', ''''), '', '', '''')
            ELSE ''Unnamed''
        END + ''_' + 
        RIGHT(NEWID(), 5) + '']
    ON [' + OBJECT_SCHEMA_NAME(mid.object_id) + '].[' + OBJECT_NAME(mid.object_id) + ']' +
        CASE 
            WHEN mid.equality_columns IS NOT NULL THEN CHAR(13) + CHAR(10) + ''    (' + mid.equality_columns + ')' ELSE ''''
        END +
        CASE 
            WHEN mid.inequality_columns IS NOT NULL THEN CHAR(13) + CHAR(10) + ''    INCLUDE (' + mid.inequality_columns + ')' ELSE ''''
        END +
        CASE 
            WHEN mid.included_columns IS NOT NULL THEN CHAR(13) + CHAR(10) + ''    INCLUDE (' + mid.included_columns + ')' ELSE ''''
        END +
        CHAR(13) + CHAR(10) + ''WITH (ONLINE = ON, FILLFACTOR = 90, STATISTICS_NORECOMPUTE = OFF);'' AS CreateIndexScript,
        (migs.avg_user_impact * migs.avg_total_user_cost * (migs.user_seeks + migs.user_scans)) AS ImpactScore
    FROM sys.dm_db_missing_index_details mid
    INNER JOIN sys.dm_db_missing_index_groups mig ON mid.index_handle = mig.index_handle
    INNER JOIN sys.dm_db_missing_index_group_stats migs ON mig.index_group_handle = migs.group_handle
    WHERE migs.avg_user_impact >= ' + CAST(@MinImpact AS NVARCHAR(10)) + N'
    AND OBJECT_SCHEMA_NAME(mid.object_id) <> ''sys''
    AND OBJECT_NAME(mid.object_id) IS NOT NULL;
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
SELECT TOP (@TopN)
    DatabaseName,
    SchemaName + '.' + TableName AS TableName,
    EqualityColumns,
    InequalityColumns,
    IncludedColumns,
    UserSeeks + UserScans AS TotalUses,
    CAST(AvgTotalUserCost AS DECIMAL(18,2)) AS AvgTotalCost,
    CAST(AvgUserImpact AS DECIMAL(5,2)) AS EstImprovementPercent,
    CAST(ImpactScore AS DECIMAL(18,2)) AS ImpactScore,
    LastUserSeek,
    LastUserScan
FROM @Results
ORDER BY ImpactScore DESC;

-- ============================================================================
-- GENERATE CREATE INDEX SCRIPTS (if requested)
-- ============================================================================
IF @GenerateScripts = 1
BEGIN
    PRINT '';
    PRINT '================================================================================';
    PRINT 'CREATE INDEX SCRIPTS (Top ' + CAST(@TopN AS VARCHAR(10)) + ' by Impact)';
    PRINT '================================================================================';
    PRINT '';
    PRINT 'WARNING: Review each index carefully before creating!';
    PRINT '         Consider index overhead (writes, maintenance, storage).';
    PRINT '         Test in non-production environment first.';
    PRINT '';
    PRINT 'Recommendation: Use Brent Ozar''s sp_BlitzIndex for comprehensive analysis:';
    PRINT '                EXEC dbo.sp_BlitzIndex @DatabaseName = ''YourDatabase'';';
    PRINT '';
    
    DECLARE @CreateScript NVARCHAR(MAX);
    DECLARE @ScriptNum INT = 0;
    
    DECLARE script_cursor CURSOR FOR
        SELECT TOP (@TopN) CreateIndexScript
        FROM @Results
        ORDER BY ImpactScore DESC;
    
    OPEN script_cursor;
    FETCH NEXT FROM script_cursor INTO @CreateScript;
    
    WHILE @@FETCH_STATUS = 0
    BEGIN
        SET @ScriptNum = @ScriptNum + 1;
        PRINT '';
        PRINT '-- ============================================================================';
        PRINT '-- Index Recommendation #' + CAST(@ScriptNum AS VARCHAR(10));
        PRINT '-- ============================================================================';
        PRINT @CreateScript;
        
        FETCH NEXT FROM script_cursor INTO @CreateScript;
    END
    
    CLOSE script_cursor;
    DEALLOCATE script_cursor;
END

-- ============================================================================
-- SUMMARY AND RECOMMENDATIONS
-- ============================================================================
PRINT '';
PRINT '================================================================================';
PRINT 'SUMMARY';
PRINT '================================================================================';

SELECT 
    DatabaseName,
    COUNT(*) AS MissingIndexCount,
    SUM(UserSeeks + UserScans) AS TotalIndexUsage,
    AVG(AvgUserImpact) AS AvgImprovementPercent
FROM @Results
GROUP BY DatabaseName
ORDER BY MissingIndexCount DESC;

PRINT '';
PRINT 'CLOUD-SPECIFIC NOTES:';
PRINT '';
PRINT 'Azure SQL Database:';
PRINT '  - Automatic index management available via Automatic Tuning';
PRINT '  - Enable: Azure Portal > SQL Database > Automatic tuning';
PRINT '  - View recommendations:';
PRINT '    SELECT * FROM sys.dm_db_tuning_recommendations;';
PRINT '  - Apply via T-SQL or Portal';
PRINT '';
PRINT 'Azure SQL Managed Instance:';
PRINT '  - Manual index creation (same as on-premises)';
PRINT '  - Use Query Store for index usage analysis';
PRINT '';
PRINT 'TOOLS RECOMMENDATION:';
PRINT '  - Brent Ozar''s sp_BlitzIndex: More comprehensive than DMVs';
PRINT '    Download: https://www.brentozar.com/first-aid/sp-blitz-index/';
PRINT '  - Ola Hallengren''s IndexOptimize: Automated index maintenance';
PRINT '    Download: https://ola.hallengren.com/downloads.html';
PRINT '================================================================================';
GO

