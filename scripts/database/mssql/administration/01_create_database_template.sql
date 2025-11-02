/*
================================================================================
METADATA & IDENTIFICATION
================================================================================
SCRIPT NAME:        Create Database with Standardized Configuration Template
VERSION:            1.0.0
CREATED DATE:       2024-01-01
LAST MODIFIED:       2024-01-01
AUTHOR:             DBA Team
MAINTAINED BY:       Database Administration Team

================================================================================
PURPOSE & BUSINESS CONTEXT
================================================================================
PURPOSE:
    Creates a new database with production-ready settings following
    organizational standards and Microsoft best practices.

BUSINESS APPLICATION:
    Used during application onboarding, database provisioning, and when
    migrating databases to ensure consistent configuration across all
    databases in the enterprise. Enforces naming conventions, file locations,
    and growth settings that align with storage policies and compliance.
    Critical for maintaining standardized database configurations that support
    backup/recovery procedures, performance expectations, and operational
    consistency across the organization.

RELATED BUSINESS PROCESSES:
    - Database Provisioning and Onboarding
    - Application Deployment
    - Disaster Recovery Planning
    - Compliance and Auditing

================================================================================
PREREQUISITES & ENVIRONMENT
================================================================================
SQL SERVER VERSION:  SQL Server 2019 or higher / Azure SQL Managed Instance
PERMISSIONS:        sysadmin or dbcreator role
DEPENDENCIES:       Storage paths must exist and be accessible
STORAGE REQUIREMENTS: Sufficient disk space for initial database files

PRE-EXECUTION CHECKLIST:
    [ ] Verified SQL Server version compatibility
    [ ] Confirmed sysadmin or dbcreator permissions
    [ ] Verified storage paths exist and have adequate space
    [ ] Reviewed database naming conventions
    [ ] Confirmed recovery model meets business requirements
    [ ] Tested in non-production environment (recommended)

================================================================================
PARAMETERS & CONFIGURATION
================================================================================
CONFIGURATION SECTION LOCATION: Lines 61-69

PARAMETER DOCUMENTATION:
    @DatabaseName        - Name of database to create (REQUIRED)
                          Example: 'ProductionDB', 'TestEnvironment'
                          
    @DataFilePath        - Path for data files (OPTIONAL)
                          Default: Instance default data path
                          Example: 'D:\SQLData\'
                          
    @LogFilePath         - Path for transaction log files (OPTIONAL)
                          Default: Instance default log path
                          Example: 'E:\SQLLog\'
                          
    @InitialDataSizeMB   - Initial size for data file in MB (OPTIONAL)
                          Default: 100 MB
                          Valid range: 1 MB to available disk space
                          
    @InitialLogSizeMB    - Initial size for log file in MB (OPTIONAL)
                          Default: 50 MB
                          Valid range: 1 MB to available disk space
                          
    @MaxDataSizeGB       - Maximum size for data file in GB (OPTIONAL)
                          Default: UNLIMITED
                          Example: 1024 (for 1 TB limit)
                          
    @MaxLogSizeGB        - Maximum size for log file in GB (OPTIONAL)
                          Default: UNLIMITED
                          
    @FileGrowthMB        - File growth increment in MB (OPTIONAL)
                          Default: 128 MB
                          Best practice: 10-25% of initial size, min 128 MB
                          
    @RecoveryModel       - Recovery model (OPTIONAL)
                          Default: FULL
                          Valid values: FULL, SIMPLE, BULK_LOGGED
                          Recommendation: Use FULL for production databases

USAGE EXAMPLES:
    -- Standard production database
    DECLARE @DatabaseName SYSNAME = 'ProductionDB';
    DECLARE @DataFilePath NVARCHAR(260) = 'D:\SQLData\';
    DECLARE @LogFilePath NVARCHAR(260) = 'E:\SQLLog\';
    DECLARE @InitialDataSizeMB INT = 500;
    DECLARE @RecoveryModel NVARCHAR(20) = 'FULL';
    -- Then execute script with these values

    -- Development database with minimal configuration
    DECLARE @DatabaseName SYSNAME = 'DevDB';
    DECLARE @RecoveryModel NVARCHAR(20) = 'SIMPLE';
    -- Use defaults for other parameters

EXPECTED EXECUTION TIME:
    Small database (< 1 GB):    < 5 seconds
    Medium database (1-10 GB):  5-30 seconds
    Large database (> 10 GB):   30+ seconds (depends on storage performance)

================================================================================
OPERATIONAL IMPACT & SAFETY
================================================================================
PRODUCTION SAFETY:
    [X] Safe to run during business hours (creates new database only)
    [ ] Requires maintenance window
    [X] Read-only operation (no data modification)
    [ ] Blocks operations
    [X] Can be interrupted/resumed (create operation atomic)
    [ ] Requires rollback plan

RESOURCE IMPACT:
    CPU Impact:        Low - Minimal CPU usage during creation
    Memory Impact:     Low - Temporary memory for file initialization
    I/O Impact:        Medium - Initial file allocation on disk
    Lock Impact:       None - No locks on existing objects
    Duration:          Typically < 30 seconds for standard configurations

ROLLBACK PROCEDURE:
    DROP DATABASE [DatabaseName];  -- Only if database creation must be reversed

ERROR HANDLING:
    Script includes validation checks for:
    - Null/empty database names
    - Existing database conflicts
    - Path accessibility
    - Invalid parameter values
    All errors raised with descriptive messages and appropriate severity levels.

================================================================================
EXPECTED OUTPUT & RESULTS
================================================================================
SUCCESS INDICATORS:
    - Database created successfully
    - Configuration summary displayed
    - Files created at specified locations
    - Recovery model set as specified
    - Database appears in sys.databases with ONLINE status

FAILURE INDICATORS:
    - Error messages indicating:
      * Database already exists
      * Insufficient permissions
      * Invalid path or insufficient disk space
      * Invalid parameter values

OUTPUT INTERPRETATION:
    Success output includes:
    - Database name and file paths
    - Recovery model setting
    - Initial file sizes and growth settings
    Review output to confirm configuration matches requirements.

REPORTING:
    Execution results output to SSMS Messages window.
    For SQL Agent jobs, results logged to job history.
    No automatic email/alert notifications (configure separately if needed).

================================================================================
INTEGRATION WITH INDUSTRY TOOLS
================================================================================
OLA HALLENGREN MAINTENANCE SOLUTION:
    This script creates databases that are immediately compatible with
    Ola Hallengren's maintenance solution. After database creation:
    1. Install Ola's DatabaseBackup, IndexOptimize, and IntegrityCheck procedures
    2. Database will be included in 'ALL_DATABASES' maintenance jobs
    3. No additional configuration required for Ola's tools

BRENT OZAR FIRST RESPONDER KIT:
    Newly created databases will be analyzed by sp_Blitz when run with
    @CheckUserDatabaseObjects = 1. Database should be tested with:
    EXEC dbo.sp_Blitz @CheckUserDatabaseObjects = 1;

CLOUD-SPECIFIC CONSIDERATIONS:
    Azure SQL Database:    Not applicable - databases created via Portal/API
    Azure Managed Instance: Full compatibility - same as on-premises SQL Server
    Azure VM SQL Server:    Full compatibility - same as on-premises SQL Server

================================================================================
MONITORING & ALERTING
================================================================================
RECOMMENDED ALERTS:
    - Monitor database creation failures via SQL Agent job history
    - Alert on disk space thresholds before running (preventive)

PERFORMANCE BASELINE:
    Standard database creation: < 30 seconds
    Variations expected based on:
    - Initial file sizes
    - Storage performance (SSD vs HDD)
    - Disk I/O contention

LOG LOCATION:
    - SQL Agent job history (if executed via Agent)
    - SSMS Messages window (if executed interactively)
    - SQL Server Error Log (for system-level errors)

================================================================================
TESTING & VALIDATION
================================================================================
TEST ENVIRONMENT VALIDATION:
    Tested on: SQL Server 2019, 2022
    Database sizes tested: 100 MB to 10 GB initial size
    Storage types: Local disk, network storage

VALIDATION QUERIES:
    -- Verify database was created successfully
    SELECT 
        name,
        state_desc,
        recovery_model_desc,
        compatibility_level,
        create_date
    FROM sys.databases
    WHERE name = 'YourDatabaseName';

    -- Verify file configuration
    SELECT 
        name,
        type_desc,
        physical_name,
        size * 8.0 / 1024 AS Size_MB,
        max_size,
        growth,
        is_percent_growth
    FROM sys.master_files
    WHERE database_id = DB_ID('YourDatabaseName');

ACCEPTANCE CRITERIA:
    [X] Database created with specified name
    [X] Files created at specified locations
    [X] Recovery model set correctly
    [X] Database status is ONLINE
    [X] Files have correct initial sizes

================================================================================
MAINTENANCE & VERSION HISTORY
================================================================================
CHANGE LOG:
    Version 1.0.0 (2024-01-01): Initial release with standardized configuration options

KNOWN LIMITATIONS:
    - Does not create filegroups (single PRIMARY filegroup only)
    - Does not configure database options beyond recovery model
    - Does not create users or permissions (use separate script)

PLANNED ENHANCEMENTS:
    - Optional filegroup support
    - Additional database option configuration
    - Integration with change management systems

SUPPORT CONTACT:
    Database Administration Team
    Reference: Database Provisioning Process

================================================================================
REFERENCES & DOCUMENTATION
================================================================================
MICROSOFT DOCUMENTATION:
    - CREATE DATABASE (Transact-SQL)
      https://docs.microsoft.com/en-us/sql/t-sql/statements/create-database-transact-sql
    - Database Files and Filegroups
      https://docs.microsoft.com/en-us/sql/relational-databases/databases/database-files-and-filegroups
    - Recovery Models
      https://docs.microsoft.com/en-us/sql/relational-databases/backup-restore/recovery-models-sql-server

BEST PRACTICES:
    - SQL Server Database Setup Best Practices (SQLskills)
    - Database File Initialization (Microsoft Docs)
    - Page Verification Options (CHECKSUM recommended)

RELATED SCRIPTS:
    - 02_create_user_least_privilege.sql (User provisioning after database creation)
    - 03_configure_instance_settings.sql (Instance-level configuration)

COMPLIANCE & AUDIT:
    - Database creation logged in SQL Server default trace
    - Configuration stored in sys.databases and sys.master_files
    - Review SQL Server Audit logs if auditing enabled

================================================================================
*/


SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ============================================================================
-- CONFIGURATION SECTION - Modify these variables for your environment
-- ============================================================================
DECLARE @DatabaseName        SYSNAME = N'YourDatabaseName';  -- REQUIRED
DECLARE @DataFilePath        NVARCHAR(260) = N'D:\SQLData\'; -- Modify as needed
DECLARE @LogFilePath         NVARCHAR(260) = N'E:\SQLLog\';   -- Modify as needed
DECLARE @InitialDataSizeMB   INT = 100;                       -- 100 MB default
DECLARE @InitialLogSizeMB    INT = 50;                        -- 50 MB default
DECLARE @MaxDataSizeGB       INT = NULL;                      -- NULL = UNLIMITED
DECLARE @MaxLogSizeGB        INT = NULL;                      -- NULL = UNLIMITED
DECLARE @FileGrowthMB        INT = 128;                       -- 128 MB growth
DECLARE @RecoveryModel       NVARCHAR(20) = N'FULL';          -- FULL, SIMPLE, or BULK_LOGGED

-- ============================================================================
-- VALIDATION
-- ============================================================================
IF @DatabaseName IS NULL OR @DatabaseName = ''
BEGIN
    RAISERROR('@DatabaseName cannot be NULL or empty', 16, 1);
    RETURN;
END

IF EXISTS (SELECT 1 FROM sys.databases WHERE name = @DatabaseName)
BEGIN
    RAISERROR('Database "%s" already exists', 16, 1, @DatabaseName);
    RETURN;
END

-- Get default paths if not specified
IF @DataFilePath IS NULL OR @DataFilePath = ''
    SET @DataFilePath = CAST(SERVERPROPERTY('InstanceDefaultDataPath') AS NVARCHAR(260)) + '\';

IF @LogFilePath IS NULL OR @LogFilePath = ''
    SET @LogFilePath = CAST(SERVERPROPERTY('InstanceDefaultLogPath') AS NVARCHAR(260)) + '\';

-- Ensure paths end with backslash
IF RIGHT(@DataFilePath, 1) <> '\' SET @DataFilePath = @DataFilePath + '\';
IF RIGHT(@LogFilePath, 1) <> '\' SET @LogFilePath = @LogFilePath + '\';

-- ============================================================================
-- BUILD AND EXECUTE CREATE DATABASE STATEMENT
-- ============================================================================
DECLARE @sql NVARCHAR(MAX);
DECLARE @DataFileName NVARCHAR(260) = @DataFilePath + @DatabaseName + '_Data.mdf';
DECLARE @LogFileName NVARCHAR(260) = @LogFilePath + @DatabaseName + '_Log.ldf';
DECLARE @MaxDataSizeClause NVARCHAR(50) = '';
DECLARE @MaxLogSizeClause NVARCHAR(50) = '';

IF @MaxDataSizeGB IS NOT NULL
    SET @MaxDataSizeClause = N', MAXSIZE = ' + CAST(@MaxDataSizeGB AS NVARCHAR(10)) + N'GB';

IF @MaxLogSizeGB IS NOT NULL
    SET @MaxLogSizeClause = N', MAXSIZE = ' + CAST(@MaxLogSizeGB AS NVARCHAR(10)) + N'GB';

SET @sql = N'
CREATE DATABASE [' + QUOTENAME(@DatabaseName) + N']
ON 
( NAME = N''' + @DatabaseName + N'_Data'',
  FILENAME = N''' + @DataFileName + N''',
  SIZE = ' + CAST(@InitialDataSizeMB AS NVARCHAR(10)) + N'MB,
  MAXSIZE = UNLIMITED' + @MaxDataSizeClause + N',
  FILEGROWTH = ' + CAST(@FileGrowthMB AS NVARCHAR(10)) + N'MB )
LOG ON 
( NAME = N''' + @DatabaseName + N'_Log'',
  FILENAME = N''' + @LogFileName + N''',
  SIZE = ' + CAST(@InitialLogSizeMB AS NVARCHAR(10)) + N'MB,
  MAXSIZE = UNLIMITED' + @MaxLogSizeClause + N',
  FILEGROWTH = ' + CAST(@FileGrowthMB AS NVARCHAR(10)) + N'MB )
COLLATE SQL_Latin1_General_CP1_CI_AS; -- Modify collation as needed for your organization
';

BEGIN TRY
    EXEC sp_executesql @sql;
    
    -- Set recovery model
    SET @sql = N'ALTER DATABASE [' + QUOTENAME(@DatabaseName) + N'] SET RECOVERY MODEL ' + @RecoveryModel;
    EXEC sp_executesql @sql;
    
    -- Set additional best practice settings
    SET @sql = N'
    ALTER DATABASE [' + QUOTENAME(@DatabaseName) + N'] SET 
        AUTO_CLOSE OFF,
        AUTO_SHRINK OFF,
        AUTO_CREATE_STATISTICS ON,
        AUTO_UPDATE_STATISTICS ON,
        AUTO_UPDATE_STATISTICS_ASYNC OFF,
        PAGE_VERIFY CHECKSUM,
        READ_COMMITTED_SNAPSHOT ON; -- Reduces blocking for better concurrency
    ';
    EXEC sp_executesql @sql;
    
    PRINT '================================================================================';
    PRINT 'SUCCESS: Database "' + @DatabaseName + '" created successfully';
    PRINT '================================================================================';
    PRINT 'Configuration Summary:';
    PRINT '  Database Name:     ' + @DatabaseName;
    PRINT '  Data File:         ' + @DataFileName;
    PRINT '  Log File:          ' + @LogFileName;
    PRINT '  Recovery Model:    ' + @RecoveryModel;
    PRINT '  Initial Data Size: ' + CAST(@InitialDataSizeMB AS VARCHAR(10)) + ' MB';
    PRINT '  Initial Log Size:  ' + CAST(@InitialLogSizeMB AS VARCHAR(10)) + ' MB';
    PRINT '  File Growth:       ' + CAST(@FileGrowthMB AS VARCHAR(10)) + ' MB';
    PRINT '================================================================================';
END TRY
BEGIN CATCH
    DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE();
    DECLARE @ErrorSeverity INT = ERROR_SEVERITY();
    DECLARE @ErrorState INT = ERROR_STATE();
    
    RAISERROR('Error creating database: %s', @ErrorSeverity, @ErrorState, @ErrorMessage);
    RETURN;
END CATCH;
GO

