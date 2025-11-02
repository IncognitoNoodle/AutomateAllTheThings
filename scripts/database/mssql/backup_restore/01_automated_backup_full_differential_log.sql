/*
================================================================================
SCRIPT: Automated Backup Script (Full, Differential, Transaction Log)
================================================================================
PURPOSE:
    Performs automated database backups with date-based naming convention.
    Supports full, differential, and transaction log backups based on
    recovery model and schedule requirements.

BUSINESS APPLICATION:
    Critical for meeting RPO (Recovery Point Objective) and RTO (Recovery
    Time Objective) requirements. Used in SQL Agent jobs for scheduled
    backups. Ensures consistent backup naming for automated restore processes
    and backup retention policies.

PREREQUISITES:
    - SQL Server 2019 or higher
    - Permissions: db_backupoperator or sysadmin
    - Backup directory must exist and be accessible
    - Database must exist

PARAMETERS:
    @DatabaseName    - Database to backup (REQUIRED)
    @BackupType      - 'FULL', 'DIFF', 'LOG' (REQUIRED)
    @BackupPath      - Directory path for backup files (REQUIRED)
    @CompressBackup  - Use backup compression (1 = YES, default: 1)
    @VerifyBackup    - Verify backup after completion (1 = YES, default: 1)
    @CopyOnly        - Copy-only backup (doesn't affect backup chain) (0 = NO, default)
    @RetentionDays   - Number of days to retain backups (default: 7)

USAGE EXAMPLE:
    EXEC dbo.usp_AutomatedBackup
        @DatabaseName = 'ProductionDB',
        @BackupType = 'FULL',
        @BackupPath = 'D:\SQLBackups\',
        @CompressBackup = 1,
        @VerifyBackup = 1;

EXPECTED OUTPUT:
    Creates backup file with date/time stamp in filename.
    Returns backup file path, size, and duration.
    Optionally verifies backup integrity.

REFERENCES:
    - Microsoft Docs: BACKUP DATABASE
      https://docs.microsoft.com/en-us/sql/t-sql/statements/backup-database-transact-sql
    - Backup Best Practices: https://docs.microsoft.com/en-us/sql/relational-databases/backup-restore/sql-server-backup-and-restore
================================================================================
*/

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ============================================================================
-- CONFIGURATION SECTION
-- ============================================================================
DECLARE @DatabaseName    SYSNAME = N'YourDatabase';     -- REQUIRED
DECLARE @BackupType      VARCHAR(10) = 'FULL';          -- 'FULL', 'DIFF', 'LOG'
DECLARE @BackupPath      NVARCHAR(260) = N'D:\SQLBackups\'; -- REQUIRED
DECLARE @CompressBackup  BIT = 1;                       -- 1 = YES (recommended)
DECLARE @VerifyBackup    BIT = 1;                       -- 1 = YES (recommended)
DECLARE @CopyOnly        BIT = 0;                       -- 0 = NO (affects backup chain)
DECLARE @RetentionDays   INT = 7;                       -- Days to retain backups

-- ============================================================================
-- VALIDATION
-- ============================================================================
IF @DatabaseName IS NULL OR @DatabaseName = ''
BEGIN
    RAISERROR('@DatabaseName cannot be NULL or empty', 16, 1);
    RETURN;
END

IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE name = @DatabaseName)
BEGIN
    RAISERROR('Database "%s" does not exist', 16, 1, @DatabaseName);
    RETURN;
END

IF @BackupType NOT IN ('FULL', 'DIFF', 'LOG')
BEGIN
    RAISERROR('@BackupType must be FULL, DIFF, or LOG', 16, 1);
    RETURN;
END

IF @BackupPath IS NULL OR @BackupPath = ''
BEGIN
    RAISERROR('@BackupPath cannot be NULL or empty', 16, 1);
    RETURN;
END

-- Ensure path ends with backslash
IF RIGHT(@BackupPath, 1) <> '\' 
    SET @BackupPath = @BackupPath + '\';

-- Check database recovery model
DECLARE @RecoveryModel NVARCHAR(20);
SELECT @RecoveryModel = recovery_model_desc 
FROM sys.databases 
WHERE name = @DatabaseName;

IF @BackupType = 'LOG' AND @RecoveryModel = 'SIMPLE'
BEGIN
    RAISERROR('Cannot perform transaction log backup on database in SIMPLE recovery model', 16, 1);
    RETURN;
END

IF @BackupType = 'DIFF' AND NOT EXISTS (
    SELECT 1 FROM msdb.dbo.backupset 
    WHERE database_name = @DatabaseName 
    AND type = 'D' 
    AND is_copy_only = 0
)
BEGIN
    RAISERROR('Cannot perform differential backup: No full backup found', 16, 1);
    RETURN;
END

-- ============================================================================
-- BUILD BACKUP FILENAME (Date-based naming)
-- ============================================================================
DECLARE @BackupFileName NVARCHAR(260);
DECLARE @DateStamp VARCHAR(23) = CONVERT(VARCHAR(23), GETDATE(), 112) + '_' + 
                                  REPLACE(CONVERT(VARCHAR(23), GETDATE(), 108), ':', '');

DECLARE @FileExtension VARCHAR(10);
SET @FileExtension = CASE @BackupType
    WHEN 'FULL' THEN '.bak'
    WHEN 'DIFF' THEN '.bak'
    WHEN 'LOG' THEN '.trn'
END;

SET @BackupFileName = @BackupPath + @DatabaseName + '_' + @BackupType + '_' + @DateStamp + @FileExtension;

-- ============================================================================
-- PERFORM BACKUP
-- ============================================================================
DECLARE @BackupSQL NVARCHAR(MAX);
DECLARE @StartTime DATETIME2 = GETDATE();

SET @BackupSQL = N'
BACKUP ' + 
    CASE @BackupType
        WHEN 'FULL' THEN 'DATABASE'
        WHEN 'DIFF' THEN 'DATABASE'
        WHEN 'LOG' THEN 'LOG'
    END + 
    ' [' + QUOTENAME(@DatabaseName) + N'] 
TO DISK = ''' + REPLACE(@BackupFileName, '''', '''''') + N'''
WITH ';

IF @CompressBackup = 1
    SET @BackupSQL = @BackupSQL + N'COMPRESSION, ';

IF @CopyOnly = 1
    SET @BackupSQL = @BackupSQL + N'COPY_ONLY, ';

SET @BackupSQL = @BackupSQL + N'
    FORMAT,
    INIT,
    NAME = N''' + @DatabaseName + N'_' + @BackupType + N'_Backup_' + @DateStamp + N''',
    DESCRIPTION = N''' + @BackupType + N' backup of ' + @DatabaseName + N' created on ' + CONVERT(VARCHAR(23), GETDATE(), 120) + N''',
    SKIP,
    NOREWIND,
    NOUNLOAD,
    STATS = 10;
';

PRINT '================================================================================';
PRINT 'STARTING BACKUP';
PRINT '================================================================================';
PRINT 'Database:          ' + @DatabaseName;
PRINT 'Backup Type:       ' + @BackupType;
PRINT 'Backup File:       ' + @BackupFileName;
PRINT 'Compression:       ' + CASE @CompressBackup WHEN 1 THEN 'YES' ELSE 'NO' END;
PRINT 'Copy Only:         ' + CASE @CopyOnly WHEN 1 THEN 'YES' ELSE 'NO' END;
PRINT 'Start Time:        ' + CONVERT(VARCHAR(23), @StartTime, 120);
PRINT '================================================================================';
PRINT '';

BEGIN TRY
    EXEC sp_executesql @BackupSQL;
    
    DECLARE @EndTime DATETIME2 = GETDATE();
    DECLARE @DurationSeconds INT = DATEDIFF(SECOND, @StartTime, @EndTime);
    
    -- Get backup file size
    DECLARE @FileSizeMB DECIMAL(18,2);
    DECLARE @cmd NVARCHAR(MAX) = N'powershell -Command "(Get-Item ''' + @BackupFileName + ''').Length / 1MB"';
    
    CREATE TABLE #FileSize (SizeMB DECIMAL(18,2));
    INSERT INTO #FileSize EXEC xp_cmdshell @cmd;
    SELECT @FileSizeMB = SizeMB FROM #FileSize WHERE SizeMB IS NOT NULL;
    DROP TABLE #FileSize;
    
    PRINT '';
    PRINT '================================================================================';
    PRINT 'BACKUP COMPLETED SUCCESSFULLY';
    PRINT '================================================================================';
    PRINT 'Backup File:       ' + @BackupFileName;
    PRINT 'File Size:         ' + CAST(ISNULL(@FileSizeMB, 0) AS VARCHAR(20)) + ' MB';
    PRINT 'Duration:          ' + CAST(@DurationSeconds AS VARCHAR(10)) + ' seconds';
    PRINT 'End Time:          ' + CONVERT(VARCHAR(23), @EndTime, 120);
    PRINT '================================================================================';
    
    -- ============================================================================
    -- VERIFY BACKUP (if requested)
    -- ============================================================================
    IF @VerifyBackup = 1
    BEGIN
        PRINT '';
        PRINT 'Verifying backup integrity...';
        DECLARE @VerifySQL NVARCHAR(MAX);
        SET @VerifySQL = N'RESTORE VERIFYONLY FROM DISK = ''' + REPLACE(@BackupFileName, '''', '''''') + N''' WITH CHECKSUM;';
        
        BEGIN TRY
            EXEC sp_executesql @VerifySQL;
            PRINT 'Backup verification: PASSED';
        END TRY
        BEGIN CATCH
            DECLARE @VerifyErrMsg NVARCHAR(4000) = ERROR_MESSAGE();
            PRINT 'WARNING: Backup verification failed: ' + @VerifyErrMsg;
        END CATCH
    END
    
END TRY
BEGIN CATCH
    DECLARE @BackupErrMsg NVARCHAR(4000) = ERROR_MESSAGE();
    DECLARE @BackupErrSeverity INT = ERROR_SEVERITY();
    DECLARE @BackupErrState INT = ERROR_STATE();
    
    RAISERROR('Backup failed: %s', @BackupErrSeverity, @BackupErrState, @BackupErrMsg);
    
    -- Clean up failed backup file if it exists
    IF EXISTS (SELECT 1 FROM sys.dm_os_file_exists(@BackupFileName))
    BEGIN
        DECLARE @DeleteSQL NVARCHAR(MAX) = N'xp_cmdshell ''del /F /Q "' + @BackupFileName + '"''';
        EXEC sp_executesql @DeleteSQL;
    END
    
    RETURN;
END CATCH

-- ============================================================================
-- CLEANUP OLD BACKUPS (optional)
-- ============================================================================
IF @RetentionDays > 0
BEGIN
    PRINT '';
    PRINT 'Cleaning up backups older than ' + CAST(@RetentionDays AS VARCHAR(10)) + ' days...';
    
    DECLARE @CleanupSQL NVARCHAR(MAX);
    SET @CleanupSQL = N'
    DECLARE @OldBackupFile NVARCHAR(260);
    DECLARE @CutoffDate DATETIME = DATEADD(DAY, -' + CAST(@RetentionDays AS VARCHAR(10)) + ', GETDATE());
    
    -- Delete old backup files
    DECLARE backup_cursor CURSOR FOR
    SELECT physical_device_name
    FROM msdb.dbo.backupset bs
    INNER JOIN msdb.dbo.backupmediafamily bmf ON bs.media_set_id = bmf.media_set_id
    WHERE bs.database_name = ''' + REPLACE(@DatabaseName, '''', '''''') + N'''
    AND bs.backup_finish_date < @CutoffDate;
    
    OPEN backup_cursor;
    FETCH NEXT FROM backup_cursor INTO @OldBackupFile;
    
    WHILE @@FETCH_STATUS = 0
    BEGIN
        DECLARE @DeleteCmd NVARCHAR(MAX) = N''xp_cmdshell ''del /F /Q "'' + @OldBackupFile + ''"''';
        EXEC sp_executesql @DeleteCmd;
        FETCH NEXT FROM backup_cursor INTO @OldBackupFile;
    END
    
    CLOSE backup_cursor;
    DEALLOCATE backup_cursor;
    
    -- Clean up backup history
    EXEC msdb.dbo.sp_delete_backuphistory @oldest_date = @CutoffDate;
    ';
    
    BEGIN TRY
        EXEC sp_executesql @CleanupSQL;
        PRINT 'Cleanup completed.';
    END TRY
    BEGIN CATCH
        PRINT 'Warning: Cleanup encountered errors: ' + ERROR_MESSAGE();
    END CATCH
END

PRINT '';
PRINT 'Backup process completed.';
GO

