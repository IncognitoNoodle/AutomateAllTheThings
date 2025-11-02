/*
================================================================================
SCRIPT: Azure SQL Database - Automatic Tuning Configuration
================================================================================
PURPOSE:
    Configures and monitors Azure SQL Database Automatic Tuning features
    including automatic index management, parameter sniffing fixes, and
    forced plan corrections.

BUSINESS APPLICATION:
    Leverages Azure's AI-powered automatic tuning to improve performance
    without manual intervention. Reduces DBA workload for routine optimizations.
    Critical for managing large numbers of databases at scale.

PREREQUISITES:
    - Azure SQL Database (not available for SQL Server on-premises)
    - Permissions: Requires dbmanager role or subscription Contributor
    - Automatic Tuning must be enabled at subscription or database level

PARAMETERS:
    @DatabaseName      - Azure SQL Database name (REQUIRED)
    @EnableIndexManagement - Enable automatic index management (1 = YES)
    @EnablePlanCorrection  - Enable automatic plan correction (1 = YES)
    @Mode              - 'INHERIT' (from server), 'AUTO', 'CUSTOM'

USAGE EXAMPLE:
    EXEC dbo.usp_ConfigureAzureAutoTuning
        @DatabaseName = 'ProductionDB',
        @EnableIndexManagement = 1,
        @EnablePlanCorrection = 1;

EXPECTED OUTPUT:
    Returns current automatic tuning configuration.
    Shows pending recommendations.
    Displays tuning history and impact.

REFERENCES:
    - Azure Docs: Automatic Tuning
      https://docs.microsoft.com/en-us/azure/azure-sql/database/automatic-tuning-overview
    - Azure SQL Database Automatic Tuning API
      https://docs.microsoft.com/en-us/rest/api/sql/2021-11-01/database-automatic-tuning
================================================================================
*/

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ============================================================================
-- CONFIGURATION SECTION
-- ============================================================================
DECLARE @DatabaseName            SYSNAME = N'YourAzureDatabase'; -- REQUIRED
DECLARE @EnableIndexManagement   BIT = 1;                         -- 1 = YES
DECLARE @EnablePlanCorrection    BIT = 1;                         -- 1 = YES
DECLARE @Mode                    VARCHAR(20) = 'AUTO';            -- 'AUTO', 'CUSTOM', 'INHERIT'

-- ============================================================================
-- CHECK IF RUNNING ON AZURE SQL DATABASE
-- ============================================================================
DECLARE @IsAzureSQL BIT = 0;

IF EXISTS (SELECT 1 FROM sys.databases WHERE database_id = 2 AND name = 'master' 
           AND CAST(SERVERPROPERTY('EngineEdition') AS INT) = 5) -- Azure SQL Database
    SET @IsAzureSQL = 1;

IF @IsAzureSQL = 0
BEGIN
    PRINT '================================================================================';
    PRINT 'WARNING: This script is designed for Azure SQL Database.';
    PRINT 'Current server type: ' + CAST(SERVERPROPERTY('EngineEdition') AS VARCHAR(10));
    PRINT '  Engine Edition 5 = Azure SQL Database';
    PRINT '  Engine Edition 4 = Azure SQL Managed Instance';
    PRINT '  Engine Edition 1/2/3 = On-premises SQL Server';
    PRINT '';
    PRINT 'For on-premises SQL Server, use:';
    PRINT '  - Ola Hallengren''s Maintenance Solution';
    PRINT '  - Brent Ozar''s First Responder Kit';
    PRINT '================================================================================';
    RETURN;
END

-- ============================================================================
-- VIEW CURRENT AUTOMATIC TUNING CONFIGURATION
-- ============================================================================
PRINT '================================================================================';
PRINT 'AZURE SQL DATABASE - AUTOMATIC TUNING CONFIGURATION';
PRINT '================================================================================';
PRINT 'Database:        ' + @DatabaseName;
PRINT 'Server:          ' + @@SERVERNAME;
PRINT 'Current Date:    ' + CONVERT(VARCHAR(23), GETDATE(), 120);
PRINT '================================================================================';
PRINT '';

PRINT 'Current Automatic Tuning Configuration:';
SELECT 
    name AS TuningOption,
    CASE desired_state_desc
        WHEN 'ON' THEN 'ENABLED'
        WHEN 'OFF' THEN 'DISABLED'
        WHEN 'DEFAULT' THEN 'INHERITED FROM SERVER'
    END AS DesiredState,
    CASE actual_state_desc
        WHEN 'ON' THEN 'ACTIVE'
        WHEN 'OFF' THEN 'INACTIVE'
        WHEN 'DEFAULT' THEN 'INHERITED'
    END AS ActualState,
    reason_desc AS Reason
FROM sys.database_automatic_tuning_options
WHERE database_id = DB_ID(@DatabaseName)
ORDER BY name;

-- ============================================================================
-- VIEW PENDING RECOMMENDATIONS
-- ============================================================================
PRINT '';
PRINT '================================================================================';
PRINT 'PENDING AUTOMATIC TUNING RECOMMENDATIONS';
PRINT '================================================================================';

SELECT 
    DATABASE_NAME AS DatabaseName,
    recommendation_type AS RecommendationType,
    CASE 
        WHEN recommendation_type = 'CreateIndex' THEN 'CREATE INDEX'
        WHEN recommendation_type = 'DropIndex' THEN 'DROP INDEX'
        WHEN recommendation_type = 'ForcePlan' THEN 'FORCE PLAN'
        ELSE recommendation_type
    END AS Action,
    JSON_VALUE(state, '$.currentValue') AS CurrentState,
    JSON_VALUE(state, '$.actionInitiatedBy') AS InitiatedBy,
    reason AS Reason,
    created_time AS CreatedTime,
    valid_until AS ValidUntil,
    JSON_VALUE(details, '$.script') AS RecommendedScript
FROM sys.dm_db_tuning_recommendations
WHERE DATABASE_NAME = @DatabaseName
ORDER BY created_time DESC;

IF @@ROWCOUNT = 0
BEGIN
    PRINT 'No pending recommendations at this time.';
    PRINT '';
    PRINT 'Automatic tuning continuously monitors your database and will';
    PRINT 'generate recommendations when opportunities are identified.';
END

-- ============================================================================
-- VIEW TUNING HISTORY AND IMPACT
-- ============================================================================
PRINT '';
PRINT '================================================================================';
PRINT 'AUTOMATIC TUNING HISTORY';
PRINT '================================================================================';

-- Note: Actual tuning history is available via Azure Portal or REST API
-- This query shows system views available

SELECT 
    OBJECT_SCHEMA_NAME(object_id) + '.' + OBJECT_NAME(object_id) AS TableName,
    name AS IndexName,
    type_desc AS IndexType,
    is_disabled AS IsDisabled,
    CASE 
        WHEN create_date >= DATEADD(DAY, -30, GETDATE()) THEN 'Recently Created (Auto Tuning?)'
        ELSE 'Existing'
    END AS IndexStatus
FROM sys.indexes
WHERE OBJECT_SCHEMA_NAME(object_id) <> 'sys'
AND database_id = DB_ID(@DatabaseName)
ORDER BY create_date DESC;

-- ============================================================================
-- CONFIGURATION INSTRUCTIONS
-- ============================================================================
PRINT '';
PRINT '================================================================================';
PRINT 'CONFIGURATION METHODS';
PRINT '================================================================================';
PRINT '';
PRINT 'METHOD 1: Azure Portal (Recommended for most users)';
PRINT '  1. Navigate to Azure Portal > SQL Database > ' + @DatabaseName;
PRINT '  2. Select "Automatic tuning" from left menu';
PRINT '  3. Enable desired options:';
PRINT '     - Create index';
PRINT '     - Drop index';
PRINT '     - Force last good plan';
PRINT '  4. Select "Apply"';
PRINT '';
PRINT 'METHOD 2: Azure PowerShell';
PRINT '  Set-AzSqlDatabaseAutomaticTuning -ResourceGroupName "YourRG" -ServerName "YourServer"';
PRINT '    -DatabaseName "' + @DatabaseName + '" -DesiredState Enabled -Options "CreateIndex","DropIndex","ForceLastGoodPlan"';
PRINT '';
PRINT 'METHOD 3: Azure CLI';
PRINT '  az sql db autotune update --resource-group YourRG --server YourServer';
PRINT '    --name ' + @DatabaseName + ' --desired-state Auto';
PRINT '';
PRINT 'METHOD 4: REST API';
PRINT '  PUT /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}';
PRINT '    /providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}';
PRINT '    /automaticTuning/current';
PRINT '';
PRINT '================================================================================';
PRINT 'RECOMMENDATIONS';
PRINT '================================================================================';
PRINT '';
PRINT '1. ENABLE AUTOMATIC TUNING for most production databases';
PRINT '   - Low risk, high reward';
PRINT '   - You can review and reject recommendations before applying';
PRINT '';
PRINT '2. MONITOR RECOMMENDATIONS regularly';
PRINT '   - Review via Portal or sys.dm_db_tuning_recommendations';
PRINT '   - Set up alerts for high-impact recommendations';
PRINT '';
PRINT '3. COMBINE WITH MANUAL TUNING';
PRINT '   - Use Brent Ozar''s sp_BlitzIndex for comprehensive analysis';
PRINT '   - Use Query Store for historical performance tracking';
PRINT '';
PRINT '4. FOR HYBRID ENVIRONMENTS:';
PRINT '   - Azure SQL Database: Use Automatic Tuning';
PRINT '   - Azure SQL Managed Instance: Use Ola Hallengren''s solution';
PRINT '   - On-premises: Use Ola Hallengren''s solution';
PRINT '';
PRINT '================================================================================';

-- ============================================================================
-- QUERY STORE INTEGRATION (recommended with Automatic Tuning)
-- ============================================================================
PRINT '';
PRINT 'QUERY STORE STATUS:';
SELECT 
    actual_state_desc AS QueryStoreState,
    readonly_reason AS ReadOnlyReason,
    current_storage_size_mb AS CurrentSizeMB,
    max_storage_size_mb AS MaxSizeMB,
    CASE 
        WHEN actual_state_desc = 'READ_ONLY' THEN 'Query Store is read-only - review configuration'
        WHEN actual_state_desc = 'OFF' THEN 'Query Store is disabled - enable for best results'
        ELSE 'Query Store is active'
    END AS Recommendation
FROM sys.database_query_store_options
WHERE database_id = DB_ID(@DatabaseName);

IF EXISTS (SELECT 1 FROM sys.database_query_store_options 
           WHERE database_id = DB_ID(@DatabaseName) AND actual_state_desc <> 'ReadWrite')
BEGIN
    PRINT '';
    PRINT 'RECOMMENDATION: Enable Query Store for optimal Automatic Tuning results';
    PRINT 'Execute: ALTER DATABASE [' + @DatabaseName + '] SET QUERY_STORE = ON;';
END

PRINT '';
PRINT 'Script completed.';
GO

