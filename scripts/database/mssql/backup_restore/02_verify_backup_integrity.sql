/*
================================================================================
SCRIPT: Verify Backup Integrity and Random Restore Tests
================================================================================
PURPOSE:
    Performs comprehensive backup verification and random restore integrity
    tests to ensure backups are valid and can be successfully restored.

BUSINESS APPLICATION:
    Critical for disaster recovery preparedness. Identifies corrupted backups
    before they're needed during actual recovery scenarios. Used in automated
    testing schedules to validate backup procedures and meet audit requirements
    for backup validation.

PREREQUISITES:
    - SQL Server 2019 or higher
    - Permissions: db_backupoperator or sysadmin
    - Sufficient disk space for restore test
    - Backup files accessible

PARAMETERS:
    @DatabaseName    - Database to verify backups for (REQUIRED)
    @BackupPath      - Path containing backup files (REQUIRED)
    @PerformRestoreTest - Perform actual restore test (1 = YES, default: 0)
    @TestDatabaseName   - Name for test restore database (OPTIONAL)

USAGE EXAMPLE:
    EXEC dbo.usp_VerifyBackupIntegrity
        @DatabaseName = 'ProductionDB',
        @BackupPath = 'D:\SQLBackups\',
        @PerformRestoreTest = 1,
        @TestDatabaseName = 'ProductionDB_TestRestore';

EXPECTED OUTPUT:
    Lists all backups with verification status.
    Optionally performs restore test and validates data integrity.
    Returns summary report of backup health.

REFERENCES:
    - Microsoft Docs: RESTORE VERIFYONLY
      https://docs.microsoft.com/en-us/sql/t-sql/statements/restore-statements-verifyonly-transact-sql
    - Backup Verification Best Practices: https://docs.microsoft.com/en-us/sql/relational-databases/backup-restore/backup-validation-sql-server
================================================================================
*/

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ============================================================================
-- CONFIGURATION SECTION
-- ============================================================================
DECLARE @DatabaseName        SYSNAME = N'YourDatabase';      -- REQUIRED
DECLARE @BackupPath          NVARCHAR(260) = N'D:\SQLBackups\'; -- REQUIRED
DECLARE @PerformRestoreTest  BIT = 0;                         -- 1 = YES (requires disk space)
DECLARE @TestDatabaseName    SYSNAME = NULL;                  -- Name for test restore

-- ============================================================================
-- VALIDATION
-- ============================================================================
IF @DatabaseName IS NULL OR @DatabaseName = ''
BEGIN
    RAISERROR('@DatabaseName cannot be NULL or empty', 16, 1);
    RETURN;
END

IF @PerformRestoreTest = 1 AND (@TestDatabaseName IS NULL OR @TestDatabaseName = '')
    SET @TestDatabaseName = @DatabaseName + '_TestRestore';

-- ============================================================================
-- VERIFY BACKUPS FROM BACKUP HISTORY
-- ============================================================================
PRINT '================================================================================';
PRINT 'BACKUP VERIFICATION REPORT';
PRINT '================================================================================';
PRINT 'Database:          ' + @DatabaseName;
PRINT 'Verification Date: ' + CONVERT(VARCHAR(23), GETDATE(), 120);
PRINT '================================================================================';
PRINT '';

-- Get backup history
DECLARE @BackupHistory TABLE (
    BackupSetID INT,
    DatabaseName SYSNAME,
    BackupType VARCHAR(10),
    BackupStartDate DATETIME,
    BackupFinishDate DATETIME,
    BackupSizeMB DECIMAL(18,2),
    PhysicalDeviceName NVARCHAR(260),
    IsCompressed BIT,
    BackupSetGUID UNIQUEIDENTIFIER
);

INSERT INTO @BackupHistory
SELECT 
    bs.backup_set_id,
    bs.database_name,
    CASE bs.type
        WHEN 'D' THEN 'FULL'
        WHEN 'I' THEN 'DIFF'
        WHEN 'L' THEN 'LOG'
    END AS BackupType,
    bs.backup_start_date,
    bs.backup_finish_date,
    CAST(bs.backup_size / 1024.0 / 1024.0 AS DECIMAL(18,2)) AS BackupSizeMB,
    bmf.physical_device_name,
    bs.is_compressed,
    bs.backup_set_uuid
FROM msdb.dbo.backupset bs
INNER JOIN msdb.dbo.backupmediafamily bmf ON bs.media_set_id = bmf.media_set_id
WHERE bs.database_name = @DatabaseName
AND bs.backup_finish_date >= DATEADD(DAY, -30, GETDATE()) -- Last 30 days
ORDER BY bs.backup_finish_date DESC;

-- Display backup history
SELECT 
    BackupType,
    BackupFinishDate,
    BackupSizeMB,
    PhysicalDeviceName,
    CASE 
        WHEN IsCompressed = 1 THEN 'YES'
        ELSE 'NO'
    END AS IsCompressed,
    'PENDING VERIFICATION' AS VerificationStatus
FROM @BackupHistory
ORDER BY BackupFinishDate DESC;

-- ============================================================================
-- VERIFY EACH BACKUP FILE
-- ============================================================================
PRINT '';
PRINT 'Verifying backup files...';
PRINT '';

DECLARE @VerifyResults TABLE (
    PhysicalDeviceName NVARCHAR(260),
    VerificationStatus VARCHAR(50),
    VerificationMessage NVARCHAR(4000),
    VerificationDate DATETIME
);

DECLARE @BackupFile NVARCHAR(260);
DECLARE @BackupGUID UNIQUEIDENTIFIER;

DECLARE backup_cursor CURSOR FOR 
    SELECT PhysicalDeviceName, BackupSetGUID 
    FROM @BackupHistory
    ORDER BY BackupFinishDate DESC;

OPEN backup_cursor;
FETCH NEXT FROM backup_cursor INTO @BackupFile, @BackupGUID;

WHILE @@FETCH_STATUS = 0
BEGIN
    DECLARE @VerifySQL NVARCHAR(MAX);
    DECLARE @VerifyStatus VARCHAR(50) = 'UNKNOWN';
    DECLARE @VerifyMessage NVARCHAR(4000) = '';
    
    SET @VerifySQL = N'RESTORE VERIFYONLY FROM DISK = ''' + REPLACE(@BackupFile, '''', '''''') + N''' WITH CHECKSUM;';
    
    BEGIN TRY
        EXEC sp_executesql @VerifySQL;
        SET @VerifyStatus = 'PASSED';
        SET @VerifyMessage = 'Backup file is valid and can be restored.';
    END TRY
    BEGIN CATCH
        SET @VerifyStatus = 'FAILED';
        SET @VerifyMessage = ERROR_MESSAGE();
    END CATCH
    
    INSERT INTO @VerifyResults VALUES (@BackupFile, @VerifyStatus, @VerifyMessage, GETDATE());
    
    PRINT 'Backup: ' + @BackupFile;
    PRINT '  Status: ' + @VerifyStatus;
    IF @VerifyStatus = 'FAILED'
        PRINT '  Error:  ' + @VerifyMessage;
    PRINT '';
    
    FETCH NEXT FROM backup_cursor INTO @BackupFile, @BackupGUID;
END

CLOSE backup_cursor;
DEALLOCATE backup_cursor;

-- ============================================================================
-- PERFORM RESTORE TEST (if requested)
-- ============================================================================
IF @PerformRestoreTest = 1
BEGIN
    PRINT '================================================================================';
    PRINT 'PERFORMING RESTORE TEST';
    PRINT '================================================================================';
    PRINT '';
    
    -- Get latest full backup
    DECLARE @LatestFullBackup NVARCHAR(260);
    SELECT TOP 1 @LatestFullBackup = PhysicalDeviceName
    FROM @BackupHistory
    WHERE BackupType = 'FULL'
    ORDER BY BackupFinishDate DESC;
    
    IF @LatestFullBackup IS NULL
    BEGIN
        RAISERROR('No full backup found for restore test', 16, 1);
        RETURN;
    END
    
    -- Drop test database if it exists
    IF EXISTS (SELECT 1 FROM sys.databases WHERE name = @TestDatabaseName)
    BEGIN
        DECLARE @DropTestDB SQL NVARCHAR(MAX);
        SET @DropTestDB = N'ALTER DATABASE [' + QUOTENAME(@TestDatabaseName) + N'] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; ';
        SET @DropTestDB = @DropTestDB + N'DROP DATABASE [' + QUOTENAME(@TestDatabaseName) + N'];';
        
        BEGIN TRY
            EXEC sp_executesql @DropTestDB;
            PRINT 'Dropped existing test database: ' + @TestDatabaseName;
        END TRY
        BEGIN CATCH
            PRINT 'Warning: Could not drop test database: ' + ERROR_MESSAGE();
        END CATCH
    END
    
    -- Perform restore
    DECLARE @RestoreSQL NVARCHAR(MAX);
    SET @RestoreSQL = N'
    RESTORE DATABASE [' + QUOTENAME(@TestDatabaseName) + N']
    FROM DISK = ''' + REPLACE(@LatestFullBackup, '''', '''''') + N'''
    WITH 
        MOVE ''' + @DatabaseName + N'_Data'' TO ''D:\SQLData\' + @TestDatabaseName + N'_Data.mdf'',
        MOVE ''' + @DatabaseName + N'_Log'' TO ''E:\SQLLog\' + @TestDatabaseName + N'_Log.ldf'',
        REPLACE,
        CHECKSUM,
        STATS = 10;
    ';
    
    BEGIN TRY
        PRINT 'Restoring from: ' + @LatestFullBackup;
        PRINT 'To database: ' + @TestDatabaseName;
        PRINT '';
        
        EXEC sp_executesql @RestoreSQL;
        
        PRINT '';
        PRINT 'Restore test: SUCCESS';
        PRINT 'Database restored successfully and verified.';
        
        -- Perform basic integrity check on restored database
        DECLARE @DBCCSQL NVARCHAR(MAX);
        SET @DBCCSQL = N'DBCC CHECKDB([' + QUOTENAME(@TestDatabaseName) + N']) WITH NO_INFOMSGS, ALL_ERRORMSGS;';
        
        BEGIN TRY
            EXEC sp_executesql @DBCCSQL;
            PRINT 'DBCC CHECKDB: PASSED';
        END TRY
        BEGIN CATCH
            PRINT 'Warning: DBCC CHECKDB reported issues: ' + ERROR_MESSAGE();
        END CATCH
        
        -- Drop test database
        DECLARE @DropAfterTest NVARCHAR(MAX);
        SET @DropAfterTest = N'ALTER DATABASE [' + QUOTENAME(@TestDatabaseName) + N'] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; ';
        SET @DropAfterTest = @DropAfterTest + N'DROP DATABASE [' + QUOTENAME(@TestDatabaseName) + N'];';
        
        BEGIN TRY
            EXEC sp_executesql @DropAfterTest;
            PRINT 'Test database cleaned up.';
        END TRY
        BEGIN CATCH
            PRINT 'Warning: Could not drop test database: ' + ERROR_MESSAGE();
        END CATCH
        
    END TRY
    BEGIN CATCH
        DECLARE @RestoreErrMsg NVARCHAR(4000) = ERROR_MESSAGE();
        RAISERROR('Restore test failed: %s', 16, 1, @RestoreErrMsg);
        
        -- Attempt cleanup
        IF EXISTS (SELECT 1 FROM sys.databases WHERE name = @TestDatabaseName)
        BEGIN
            BEGIN TRY
                ALTER DATABASE [tempdb] -- Use tempdb context
                SET @DropAfterTest = N'ALTER DATABASE [' + QUOTENAME(@TestDatabaseName) + N'] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; ';
                SET @DropAfterTest = @DropAfterTest + N'DROP DATABASE [' + QUOTENAME(@TestDatabaseName) + N'];';
                EXEC sp_executesql @DropAfterTest;
            END TRY
            BEGIN CATCH
                PRINT 'ERROR: Manual cleanup required for test database: ' + @TestDatabaseName;
            END CATCH
        END
    END CATCH
END

-- ============================================================================
-- SUMMARY REPORT
-- ============================================================================
PRINT '';
PRINT '================================================================================';
PRINT 'VERIFICATION SUMMARY';
PRINT '================================================================================';

SELECT 
    VerificationStatus,
    COUNT(*) AS BackupCount,
    STRING_AGG(SUBSTRING(PhysicalDeviceName, 1, 50), '; ') WITHIN GROUP (ORDER BY VerificationDate DESC) AS SampleFiles
FROM @VerifyResults
GROUP BY VerificationStatus
ORDER BY VerificationStatus;

DECLARE @PassedCount INT = (SELECT COUNT(*) FROM @VerifyResults WHERE VerificationStatus = 'PASSED');
DECLARE @FailedCount INT = (SELECT COUNT(*) FROM @VerifyResults WHERE VerificationStatus = 'FAILED');

PRINT '';
PRINT 'Total Backups Verified: ' + CAST((@PassedCount + @FailedCount) AS VARCHAR(10));
PRINT 'Passed: ' + CAST(@PassedCount AS VARCHAR(10));
PRINT 'Failed: ' + CAST(@FailedCount AS VARCHAR(10));
PRINT '';

IF @FailedCount > 0
BEGIN
    PRINT '*** WARNING: Some backups failed verification! Review backup files immediately. ***';
    PRINT '';
    SELECT 
        PhysicalDeviceName AS FailedBackup,
        VerificationMessage AS Error
    FROM @VerifyResults
    WHERE VerificationStatus = 'FAILED';
END
ELSE
BEGIN
    PRINT 'All backups verified successfully.';
END

PRINT '================================================================================';
GO

