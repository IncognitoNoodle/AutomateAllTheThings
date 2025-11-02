/*
================================================================================
SCRIPT: Top CPU/IO Consuming Queries Analysis (DMV-based)
================================================================================
PURPOSE:
    Identifies top resource-consuming queries using Dynamic Management Views
    (DMVs). Provides actionable insights for performance tuning and query
    optimization. Based on methodology from Brent Ozar's First Responder Kit.

BUSINESS APPLICATION:
    Used by DBAs to identify performance bottlenecks in production. Helps
    prioritize which queries to optimize for maximum impact. Essential for
    troubleshooting slow performance and capacity planning. Works for both
    on-premises and Azure SQL Database/Managed Instance.

CLOUD CONSIDERATIONS:
    - Azure SQL Database: Query Performance Insights available in portal
    - Azure SQL Managed Instance: Query Store + DMVs (same as on-premises)
    - Both: Query Store provides additional historical analysis

PREREQUISITES:
    - SQL Server 2019+ or Azure SQL Database/Managed Instance
    - Permissions: VIEW SERVER STATE, VIEW DATABASE STATE
    - Query Store enabled for additional insights (recommended)

PARAMETERS:
    @DatabaseName    - Database to analyze (NULL = all databases)
    @TopN            - Number of top queries to return (default: 20)
    @SortBy          - Sort by: 'CPU', 'IO', 'Duration', 'Executions' (default: 'CPU')
    @MinExecutionCount - Minimum execution count to include (default: 10)

RELATED TOOLS:
    - Brent Ozar's sp_BlitzCache: Identifies worst performing queries
      https://www.brentozar.com/first-aid/sp-blitz-cache/
    - Query Store: Historical query performance tracking
      https://docs.microsoft.com/en-us/sql/relational-databases/performance/monitoring-performance-by-using-the-query-store

USAGE EXAMPLE:
    EXEC dbo.usp_TopPerformingQueries
        @DatabaseName = 'ProductionDB',
        @TopN = 20,
        @SortBy = 'CPU';

EXPECTED OUTPUT:
    Lists top resource-consuming queries with execution statistics.
    Includes query text, execution plans (if available), and recommendations.

REFERENCES:
    - Microsoft Docs: sys.dm_exec_query_stats
      https://docs.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-exec-query-stats-transact-sql
    - Azure SQL: Query Performance Insights
      https://docs.microsoft.com/en-us/azure/azure-sql/database/query-performance-insight-use
================================================================================
*/

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ============================================================================
-- CONFIGURATION SECTION
-- ============================================================================
DECLARE @DatabaseName       SYSNAME = NULL;      -- NULL = all databases
DECLARE @TopN               INT = 20;            -- Number of queries to return
DECLARE @SortBy             VARCHAR(20) = 'CPU'; -- 'CPU', 'IO', 'Duration', 'Executions'
DECLARE @MinExecutionCount  INT = 10;           -- Minimum executions to consider

-- ============================================================================
-- VALIDATION
-- ============================================================================
IF @SortBy NOT IN ('CPU', 'IO', 'Duration', 'Executions')
BEGIN
    RAISERROR('@SortBy must be CPU, IO, Duration, or Executions', 16, 1);
    RETURN;
END

-- ============================================================================
-- QUERY ANALYSIS
-- ============================================================================
PRINT '================================================================================';
PRINT 'TOP PERFORMING QUERIES ANALYSIS';
PRINT '================================================================================';
PRINT 'Analysis Date:          ' + CONVERT(VARCHAR(23), GETDATE(), 120);
PRINT 'Database:               ' + ISNULL(@DatabaseName, 'ALL DATABASES');
PRINT 'Top N:                  ' + CAST(@TopN AS VARCHAR(10));
PRINT 'Sort By:                ' + @SortBy;
PRINT 'Min Execution Count:    ' + CAST(@MinExecutionCount AS VARCHAR(10));
PRINT '================================================================================';
PRINT '';

DECLARE @SQL NVARCHAR(MAX);
SET @SQL = N'
WITH QueryStats AS (
    SELECT 
        DB_NAME(qt.dbid) AS DatabaseName,
        qs.creation_time,
        qs.last_execution_time,
        qs.execution_count,
        qs.total_worker_time / 1000.0 AS TotalCPUTime_ms,
        qs.total_worker_time / 1000.0 / NULLIF(qs.execution_count, 0) AS AvgCPUTime_ms,
        qs.total_logical_reads AS TotalLogicalReads,
        qs.total_logical_reads / NULLIF(qs.execution_count, 0) AS AvgLogicalReads,
        qs.total_physical_reads AS TotalPhysicalReads,
        qs.total_physical_reads / NULLIF(qs.execution_count, 0) AS AvgPhysicalReads,
        qs.total_elapsed_time / 1000.0 AS TotalDuration_ms,
        qs.total_elapsed_time / 1000.0 / NULLIF(qs.execution_count, 0) AS AvgDuration_ms,
        qs.total_logical_writes AS TotalLogicalWrites,
        qs.max_worker_time / 1000.0 AS MaxCPUTime_ms,
        qs.max_elapsed_time / 1000.0 AS MaxDuration_ms,
        qs.query_hash,
        qs.query_plan_hash,
        SUBSTRING(qt.text, 
            (qs.statement_start_offset/2) + 1,
            ((CASE WHEN qs.statement_end_offset = -1 
                THEN DATALENGTH(qt.text)
                ELSE qs.statement_end_offset 
            END - qs.statement_start_offset)/2) + 1
        ) AS StatementText,
        qt.text AS FullQueryText,
        qp.query_plan,
        OBJECT_SCHEMA_NAME(qt.objectid, qt.dbid) AS SchemaName,
        OBJECT_NAME(qt.objectid, qt.dbid) AS ObjectName
    FROM sys.dm_exec_query_stats qs
    CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) qt
    CROSS APPLY sys.dm_exec_query_plan(qs.plan_handle) qp
    WHERE 
        (' + CASE WHEN @DatabaseName IS NULL THEN N'1=1' ELSE N'DB_NAME(qt.dbid) = ''' + REPLACE(@DatabaseName, '''', '''''') + N'''' END + N')
        AND qt.dbid IS NOT NULL
        AND qt.dbid > 4
        AND qs.execution_count >= ' + CAST(@MinExecutionCount AS NVARCHAR(10)) + N'
)
SELECT TOP (' + CAST(@TopN AS NVARCHAR(10)) + N')
    DatabaseName,
    SchemaName + ''.'' + ObjectName AS ObjectName,
    execution_count AS Executions,
    TotalCPUTime_ms,
    AvgCPUTime_ms,
    TotalDuration_ms,
    AvgDuration_ms,
    MaxDuration_ms,
    TotalLogicalReads,
    AvgLogicalReads,
    TotalPhysicalReads,
    AvgPhysicalReads,
    TotalLogicalWrites,
    MaxCPUTime_ms,
    last_execution_time,
    StatementText,
    FullQueryText,
    query_plan,
    CASE 
        WHEN AvgLogicalReads > 10000 THEN ''HIGH IO - Consider indexing''
        WHEN AvgCPUTime_ms > 1000 THEN ''HIGH CPU - Consider query optimization''
        WHEN AvgDuration_ms > 5000 THEN ''LONG RUNNING - Review execution plan''
        ELSE ''REVIEW''
    END AS Recommendation
FROM QueryStats
ORDER BY 
    CASE @SortByParam
        WHEN ''CPU'' THEN TotalCPUTime_ms
        WHEN ''IO'' THEN TotalLogicalReads
        WHEN ''Duration'' THEN TotalDuration_ms
        WHEN ''Executions'' THEN execution_count
    END DESC;
';

DECLARE @Params NVARCHAR(MAX) = N'@SortByParam VARCHAR(20)';
DECLARE @SortByParam VARCHAR(20) = @SortBy;

-- Create temp table for results
CREATE TABLE #QueryResults (
    DatabaseName SYSNAME,
    ObjectName NVARCHAR(500),
    Executions BIGINT,
    TotalCPUTime_ms DECIMAL(18,2),
    AvgCPUTime_ms DECIMAL(18,2),
    TotalDuration_ms DECIMAL(18,2),
    AvgDuration_ms DECIMAL(18,2),
    MaxDuration_ms DECIMAL(18,2),
    TotalLogicalReads BIGINT,
    AvgLogicalReads BIGINT,
    TotalPhysicalReads BIGINT,
    AvgPhysicalReads BIGINT,
    TotalLogicalWrites BIGINT,
    MaxCPUTime_ms DECIMAL(18,2),
    last_execution_time DATETIME,
    StatementText NVARCHAR(MAX),
    FullQueryText NVARCHAR(MAX),
    query_plan XML,
    Recommendation NVARCHAR(200)
);

INSERT INTO #QueryResults
EXEC sp_executesql @SQL, @Params, @SortByParam = @SortByParam;

-- Display Results
SELECT 
    DatabaseName,
    ObjectName,
    Executions,
    CAST(TotalCPUTime_ms AS DECIMAL(18,2)) AS TotalCPU_ms,
    CAST(AvgCPUTime_ms AS DECIMAL(18,2)) AS AvgCPU_ms,
    CAST(TotalDuration_ms AS DECIMAL(18,2)) AS TotalDuration_ms,
    CAST(AvgDuration_ms AS DECIMAL(18,2)) AS AvgDuration_ms,
    TotalLogicalReads,
    CAST(AvgLogicalReads AS DECIMAL(18,2)) AS AvgLogicalReads,
    Recommendation,
    LEFT(StatementText, 100) AS QueryPreview
FROM #QueryResults
ORDER BY 
    CASE @SortBy
        WHEN 'CPU' THEN TotalCPUTime_ms
        WHEN 'IO' THEN TotalLogicalReads
        WHEN 'Duration' THEN TotalDuration_ms
        WHEN 'Executions' THEN Executions
    END DESC;

-- ============================================================================
-- DETAILED ANALYSIS
-- ============================================================================
PRINT '';
PRINT '================================================================================';
PRINT 'DETAILED QUERY INFORMATION';
PRINT '================================================================================';

DECLARE @DetailSQL NVARCHAR(MAX);
DECLARE @CurrentQuery NVARCHAR(MAX);

DECLARE detail_cursor CURSOR FOR
    SELECT TOP 5 FullQueryText FROM #QueryResults 
    ORDER BY 
        CASE @SortBy
            WHEN 'CPU' THEN TotalCPUTime_ms
            WHEN 'IO' THEN TotalLogicalReads
            WHEN 'Duration' THEN TotalDuration_ms
            WHEN 'Executions' THEN Executions
        END DESC;

OPEN detail_cursor;
FETCH NEXT FROM detail_cursor INTO @CurrentQuery;

DECLARE @QueryNum INT = 0;
WHILE @@FETCH_STATUS = 0
BEGIN
    SET @QueryNum = @QueryNum + 1;
    PRINT '';
    PRINT '--- Query #' + CAST(@QueryNum AS VARCHAR(10)) + ' (Top by ' + @SortBy + ') ---';
    PRINT '';
    PRINT LEFT(@CurrentQuery, 500);
    IF LEN(@CurrentQuery) > 500
        PRINT '... (truncated, use FullQueryText column for complete query)';
    PRINT '';
    
    FETCH NEXT FROM detail_cursor INTO @CurrentQuery;
END

CLOSE detail_cursor;
DEALLOCATE detail_cursor;

-- ============================================================================
-- RECOMMENDATIONS
-- ============================================================================
PRINT '';
PRINT '================================================================================';
PRINT 'RECOMMENDATIONS';
PRINT '================================================================================';
PRINT '';
PRINT '1. For comprehensive analysis, use Brent Ozar''s sp_BlitzCache:';
PRINT '   EXEC dbo.sp_BlitzCache @Top = 20, @SortOrder = ''all'';';
PRINT '   Download: https://www.brentozar.com/first-aid/sp-blitz-cache/';
PRINT '';
PRINT '2. Enable Query Store for historical tracking:';
PRINT '   ALTER DATABASE [YourDatabase] SET QUERY_STORE = ON;';
PRINT '   Query Store provides wait statistics and plan regression detection.';
PRINT '';
PRINT '3. For Azure SQL Database, use Query Performance Insights:';
PRINT '   Azure Portal > SQL Database > Query Performance Insight';
PRINT '';
PRINT '4. Common optimization strategies:';
PRINT '   - Missing indexes (use sp_BlitzIndex)';
PRINT '   - Parameter sniffing issues';
PRINT '   - Outdated statistics';
PRINT '   - Blocking/deadlock analysis';
PRINT '';
PRINT '================================================================================';

DROP TABLE #QueryResults;
GO

