/*
================================================================================
SCRIPT: Configure SQL Server Instance-Level Settings
================================================================================
PURPOSE:
    Configures critical instance-level settings following Microsoft best
    practices for performance, reliability, and security. Includes MAXDOP,
    Cost Threshold for Parallelism, TempDB optimization, and other production
    settings.

BUSINESS APPLICATION:
    Used during SQL Server installation, after migration, or when tuning
    existing instances for optimal performance. These settings directly impact
    query performance, resource utilization, and can prevent production issues
    like deadlocks and blocking.

PREREQUISITES:
    - SQL Server 2019 or higher
    - sysadmin role required
    - Instance restart may be required for some settings (backup plan)

PARAMETERS:
    @MaxDOP                   - Maximum Degree of Parallelism (0 = auto, or specific number)
    @CostThresholdForParallelism - Cost threshold for parallel query plans
    @OptimizeForAdHocWorkloads   - Optimize for ad-hoc workloads (1 = ON)
    @TempDBDataFiles         - Number of TempDB data files (recommended: 1 per CPU core, max 8)
    @TempDBDataFileSizeMB    - Initial size of each TempDB data file
    @TempDBLogFileSizeMB     - Initial size of TempDB log file

USAGE EXAMPLE:
    EXEC dbo.usp_ConfigureInstanceSettings
        @MaxDOP = 4,
        @CostThresholdForParallelism = 50,
        @OptimizeForAdHocWorkloads = 1,
        @TempDBDataFiles = 8,
        @TempDBDataFileSizeMB = 4096;

EXPECTED OUTPUT:
    Configures instance-level settings and returns current configuration.
    Reports which settings require instance restart.

REFERENCES:
    - Microsoft Docs: Server Configuration Options
      https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/server-configuration-options-sql-server
    - MAXDOP Best Practices: https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-the-max-degree-of-parallelism-server-configuration-option
    - TempDB Best Practices: https://docs.microsoft.com/en-us/sql/relational-databases/databases/tempdb-database
================================================================================
*/

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ============================================================================
-- CONFIGURATION SECTION
-- ============================================================================
DECLARE @MaxDOP                      INT = NULL; -- NULL = use recommended value (CPU cores)
DECLARE @CostThresholdForParallelism INT = NULL; -- NULL = use recommended value (50)
DECLARE @OptimizeForAdHocWorkloads  BIT = 1;     -- 1 = ON (recommended for OLTP)
DECLARE @TempDBDataFiles             INT = NULL; -- NULL = auto-calculate (min 1 per core, max 8)
DECLARE @TempDBDataFileSizeMB        INT = NULL; -- NULL = use current size or 4096 MB
DECLARE @TempDBLogFileSizeMB         INT = NULL; -- NULL = use current size or 1024 MB
DECLARE @MinMemoryMB                 INT = NULL; -- Minimum server memory (MB)
DECLARE @MaxMemoryMB                 INT = NULL; -- Maximum server memory (MB) - leave room for OS

-- ============================================================================
-- GET RECOMMENDED VALUES
-- ============================================================================
DECLARE @CPUCount INT;
DECLARE @PhysicalCPUCount INT;
DECLARE @SQLServerEdition NVARCHAR(128);

SELECT 
    @CPUCount = cpu_count,
    @PhysicalCPUCount = CASE 
        WHEN hyperthread_ratio > cpu_count THEN cpu_count / hyperthread_ratio 
        ELSE cpu_count 
    END,
    @SQLServerEdition = CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128))
FROM sys.dm_os_sys_info;

-- MAXDOP: Recommended = number of physical cores, max 8
IF @MaxDOP IS NULL
    SET @MaxDOP = CASE 
        WHEN @PhysicalCPUCount <= 8 THEN @PhysicalCPUCount
        ELSE 8
    END;

-- Cost Threshold for Parallelism: Default 50, may need adjustment
IF @CostThresholdForParallelism IS NULL
    SET @CostThresholdForParallelism = 50;

-- TempDB Files: 1 per CPU core, max 8
IF @TempDBDataFiles IS NULL
    SET @TempDBDataFiles = CASE 
        WHEN @PhysicalCPUCount <= 8 THEN @PhysicalCPUCount
        ELSE 8
    END;

PRINT '================================================================================';
PRINT 'INSTANCE CONFIGURATION SCRIPT';
PRINT '================================================================================';
PRINT 'Detected Configuration:';
PRINT '  CPU Count (Logical):      ' + CAST(@CPUCount AS VARCHAR(10));
PRINT '  CPU Count (Physical):     ' + CAST(@PhysicalCPUCount AS VARCHAR(10));
PRINT '  SQL Server Edition:       ' + @SQLServerEdition;
PRINT '';
PRINT 'Recommended Settings:';
PRINT '  MAXDOP:                   ' + CAST(@MaxDOP AS VARCHAR(10));
PRINT '  Cost Threshold:           ' + CAST(@CostThresholdForParallelism AS VARCHAR(10));
PRINT '  TempDB Data Files:        ' + CAST(@TempDBDataFiles AS VARCHAR(10));
PRINT '================================================================================';
PRINT '';

-- ============================================================================
-- CONFIGURE MAXDOP (Maximum Degree of Parallelism)
-- ============================================================================
DECLARE @CurrentMaxDOP INT;
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'max degree of parallelism', @MaxDOP;
RECONFIGURE;

SELECT @CurrentMaxDOP = CAST(value AS INT) FROM sys.configurations WHERE name = 'max degree of parallelism';
PRINT 'Configured MAXDOP: ' + CAST(@CurrentMaxDOP AS VARCHAR(10));

-- ============================================================================
-- CONFIGURE COST THRESHOLD FOR PARALLELISM
-- ============================================================================
EXEC sp_configure 'cost threshold for parallelism', @CostThresholdForParallelism;
RECONFIGURE;

DECLARE @CurrentCostThreshold INT;
SELECT @CurrentCostThreshold = CAST(value AS INT) FROM sys.configurations WHERE name = 'cost threshold for parallelism';
PRINT 'Configured Cost Threshold for Parallelism: ' + CAST(@CurrentCostThreshold AS VARCHAR(10));

-- ============================================================================
-- CONFIGURE OPTIMIZE FOR AD HOC WORKLOADS
-- ============================================================================
EXEC sp_configure 'optimize for ad hoc workloads', @OptimizeForAdHocWorkloads;
RECONFIGURE;

DECLARE @CurrentOptimizeAdHoc BIT;
SELECT @CurrentOptimizeAdHoc = CAST(value AS BIT) FROM sys.configurations WHERE name = 'optimize for ad hoc workloads';
PRINT 'Configured Optimize for Ad Hoc Workloads: ' + CAST(@CurrentOptimizeAdHoc AS VARCHAR(5));

-- ============================================================================
-- CONFIGURE MEMORY SETTINGS (if specified)
-- ============================================================================
IF @MinMemoryMB IS NOT NULL
BEGIN
    EXEC sp_configure 'min server memory (MB)', @MinMemoryMB;
    RECONFIGURE;
    PRINT 'Configured Min Server Memory (MB): ' + CAST(@MinMemoryMB AS VARCHAR(10));
END

IF @MaxMemoryMB IS NOT NULL
BEGIN
    EXEC sp_configure 'max server memory (MB)', @MaxMemoryMB;
    RECONFIGURE;
    PRINT 'Configured Max Server Memory (MB): ' + CAST(@MaxMemoryMB AS VARCHAR(10));
END

-- ============================================================================
-- CONFIGURE TEMPDB
-- ============================================================================
PRINT '';
PRINT 'Configuring TempDB...';

-- Get current TempDB file information
DECLARE @TempDBPath NVARCHAR(260);
SELECT @TempDBPath = SUBSTRING(physical_name, 1, CHARINDEX(N'master.mdf', LOWER(physical_name)) - 1)
FROM sys.master_files 
WHERE database_id = 1 AND file_id = 1;

DECLARE @TempDBLogPath NVARCHAR(260);
SELECT @TempDBLogPath = SUBSTRING(physical_name, 1, CHARINDEX(N'mastlog.ldf', LOWER(physical_name)) - 1)
FROM sys.master_files 
WHERE database_id = 1 AND file_id = 2;

-- Get current TempDB data file size
DECLARE @CurrentTempDBDataSizeMB INT;
SELECT @CurrentTempDBDataSizeMB = CAST(SUM(size) * 8.0 / 1024.0 AS INT)
FROM sys.master_files 
WHERE database_id = 2 AND type_desc = 'ROWS';

IF @TempDBDataFileSizeMB IS NULL
    SET @TempDBDataFileSizeMB = CASE 
        WHEN @CurrentTempDBDataSizeMB < 4096 THEN 4096
        ELSE @CurrentTempDBDataSizeMB
    END;

-- Get current TempDB log file size
DECLARE @CurrentTempDBLogSizeMB INT;
SELECT @CurrentTempDBLogSizeMB = CAST(SUM(size) * 8.0 / 1024.0 AS INT)
FROM sys.master_files 
WHERE database_id = 2 AND type_desc = 'LOG';

IF @TempDBLogFileSizeMB IS NULL
    SET @TempDBLogFileSizeMB = CASE 
        WHEN @CurrentTempDBLogSizeMB < 1024 THEN 1024
        ELSE @CurrentTempDBLogSizeMB
    END;

-- Build TempDB configuration script
DECLARE @TempDBSQL NVARCHAR(MAX) = N'';
DECLARE @FileNum INT = 1;

-- Add data files (create additional files if needed, or resize existing)
WHILE @FileNum <= @TempDBDataFiles
BEGIN
    DECLARE @FileName NVARCHAR(128) = N'tempdev' + CAST(@FileNum AS NVARCHAR(10));
    DECLARE @FilePath NVARCHAR(260) = @TempDBPath + @FileName + N'.ndf';
    
    IF @FileNum = 1
    BEGIN
        -- First file: resize existing tempdev
        SET @TempDBSQL = @TempDBSQL + N'
        ALTER DATABASE [tempdb] MODIFY FILE (
            NAME = N''' + @FileName + N''',
            SIZE = ' + CAST(@TempDBDataFileSizeMB AS NVARCHAR(10)) + N'MB,
            FILEGROWTH = 512MB
        );
        ';
    END
    ELSE
    BEGIN
        -- Additional files: add if they don't exist
        IF NOT EXISTS (SELECT 1 FROM sys.master_files WHERE database_id = 2 AND name = @FileName)
        BEGIN
            SET @TempDBSQL = @TempDBSQL + N'
            ALTER DATABASE [tempdb] ADD FILE (
                NAME = N''' + @FileName + N''',
                FILENAME = N''' + @FilePath + N''',
                SIZE = ' + CAST(@TempDBDataFileSizeMB AS NVARCHAR(10)) + N'MB,
                FILEGROWTH = 512MB
            );
            ';
        END
        ELSE
        BEGIN
            -- Resize existing file
            SET @TempDBSQL = @TempDBSQL + N'
            ALTER DATABASE [tempdb] MODIFY FILE (
                NAME = N''' + @FileName + N''',
                SIZE = ' + CAST(@TempDBDataFileSizeMB AS NVARCHAR(10)) + N'MB,
                FILEGROWTH = 512MB
            );
            ';
        END
    END
    
    SET @FileNum = @FileNum + 1;
END

-- Configure log file
DECLARE @TempDBLogName NVARCHAR(128);
SELECT @TempDBLogName = name FROM sys.master_files WHERE database_id = 2 AND type_desc = 'LOG';

SET @TempDBSQL = @TempDBSQL + N'
ALTER DATABASE [tempdb] MODIFY FILE (
    NAME = N''' + @TempDBLogName + N''',
    SIZE = ' + CAST(@TempDBLogFileSizeMB AS NVARCHAR(10)) + N'MB,
    FILEGROWTH = 512MB
);
';

BEGIN TRY
    EXEC sp_executesql @TempDBSQL;
    PRINT 'TempDB configuration completed successfully.';
    PRINT '  Number of data files: ' + CAST(@TempDBDataFiles AS VARCHAR(10));
    PRINT '  Data file size:       ' + CAST(@TempDBDataFileSizeMB AS VARCHAR(10)) + ' MB each';
    PRINT '  Log file size:        ' + CAST(@TempDBLogFileSizeMB AS VARCHAR(10)) + ' MB';
    PRINT '';
    PRINT 'NOTE: TempDB changes will take effect after SQL Server restart.';
END TRY
BEGIN CATCH
    PRINT 'WARNING: Error configuring TempDB: ' + ERROR_MESSAGE();
    PRINT 'TempDB configuration requires instance restart to complete.';
END CATCH

-- ============================================================================
-- SUMMARY
-- ============================================================================
PRINT '';
PRINT '================================================================================';
PRINT 'CONFIGURATION SUMMARY';
PRINT '================================================================================';

SELECT 
    name AS Setting,
    value AS CurrentValue,
    value_in_use AS ValueInUse,
    CASE 
        WHEN value <> value_in_use THEN '*** RESTART REQUIRED ***'
        ELSE 'Active'
    END AS Status
FROM sys.configurations
WHERE name IN (
    'max degree of parallelism',
    'cost threshold for parallelism',
    'optimize for ad hoc workloads',
    'min server memory (MB)',
    'max server memory (MB)'
)
ORDER BY name;

PRINT '';
PRINT 'NOTE: Settings marked "*** RESTART REQUIRED ***" will take effect';
PRINT '      after SQL Server service restart.';
PRINT '================================================================================';
GO

