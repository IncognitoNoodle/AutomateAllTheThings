/*
================================================================================
SCRIPT: Disaster Recovery - Step-by-Step Database Restoration
================================================================================
PURPOSE:
    Provides step-by-step database restoration procedure for disaster recovery
    scenarios. Handles point-in-time recovery, differential restore, and
    transaction log recovery.

BUSINESS APPLICATION:
    Used during actual disaster recovery scenarios (ransomware, hardware failure,
    data corruption). Ensures correct restore sequence to meet RPO requirements
    and minimize data loss. Critical for DR runbooks and emergency procedures.

PREREQUISITES:
    - SQL Server 2019 or higher
    - Permissions: sysadmin
    - Backup files accessible
    - Sufficient disk space
    - Database offline or dropped (for full restore)

PARAMETERS:
    @DatabaseName      - Target database name (REQUIRED)
    @BackupPath        - Path containing backup files (REQUIRED)
    @RestoreToPointInTime - Point in time to restore to (NULL = latest)
    @NewDatabaseName   - New name for restored database (NULL = same name)
    @NewDataPath       - New path for data files (NULL = original paths)
    @NewLogPath        - New path for log files (NULL = original paths)
    @WithRecovery      - Restore with recovery (1 = YES, default for final restore)

USAGE EXAMPLE:
    -- Full restore to latest
    EXEC dbo.usp_DisasterRecoveryRestore
        @DatabaseName = 'ProductionDB',
        @BackupPath = 'D:\SQLBackups\',
        @WithRecovery = 1;

    -- Point-in-time restore
    EXEC dbo.usp_DisasterRecoveryRestore
        @DatabaseName = 'ProductionDB',
        @BackupPath = 'D:\SQLBackups\',
        @RestoreToPointInTime = '2024-01-15 14:30:00',
        @WithRecovery = 1;

EXPECTED OUTPUT:
    Step-by-step restore progress with timestamps.
    Complete restore chain execution.
    Database ready for use after recovery.

REFERENCES:
    - Microsoft Docs: RESTORE DATABASE
      https://docs.microsoft.com/en-us/sql/t-sql/statements/restore-statements-transact-sql
    - Disaster Recovery: https://docs.microsoft.com/en-us/sql/relational-databases/backup-restore/recover-to-a-point-in-time-sql-server
================================================================================
*/

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ============================================================================
-- CONFIGURATION SECTION
-- ============================================================================
DECLARE @DatabaseName          SYSNAME = N'YourDatabase';        -- REQUIRED
DECLARE @BackupPath            NVARCHAR(260) = N'D:\SQLBackups\'; -- REQUIRED
DECLARE @RestoreToPointInTime  DATETIME2 = NULL;                 -- NULL = latest
DECLARE @NewDatabaseName       SYSNAME = NULL;                    -- NULL = same name
DECLARE @NewDataPath           NVARCHAR(260) = NULL;             -- NULL = original
DECLARE @NewLogPath            NVARCHAR(260) = NULL;             -- NULL = original
DECLARE @WithRecovery          BIT = 1;                          -- 1 = YES (final restore)

-- ============================================================================
-- VALIDATION
-- ============================================================================
IF @DatabaseName IS NULL OR @DatabaseName = ''
BEGIN
    RAISERROR('@DatabaseName cannot be NULL or empty', 16, 1);
    RETURN;
END

IF @NewDatabaseName IS NULL
    SET @NewDatabaseName = @DatabaseName;

-- ============================================================================
-- GET BACKUP CHAIN
-- ============================================================================
PRINT '================================================================================';
PRINT 'DISASTER RECOVERY RESTORE PROCEDURE';
PRINT '================================================================================';
PRINT 'Target Database:  ' + @NewDatabaseName;
PRINT 'Restore To:       ' + ISNULL(CONVERT(VARCHAR(23), @RestoreToPointInTime, 120), 'LATEST');
PRINT 'Start Time:       ' + CONVERT(VARCHAR(23), GETDATE(), 120);
PRINT '================================================================================';
PRINT '';

DECLARE @BackupChain TABLE (
    SequenceID INT IDENTITY(1,1),
    BackupType VARCHAR(10),
    BackupSetID INT,
    BackupStartDate DATETIME,
    BackupFinishDate DATETIME,
    PhysicalDeviceName NVARCHAR(260),
    FirstLSN NUMERIC(25,0),
    LastLSN NUMERIC(25,0),
    CheckpointLSN NUMERIC(25,0),
    DatabaseBackupLSN NUMERIC(25,0),
    IsRequired BIT
);

-- Get full backup
INSERT INTO @BackupChain (BackupType, BackupSetID, BackupStartDate, BackupFinishDate, PhysicalDeviceName, FirstLSN, LastLSN, CheckpointLSN, DatabaseBackupLSN, IsRequired)
SELECT TOP 1
    'FULL',
    bs.backup_set_id,
    bs.backup_start_date,
    bs.backup_finish_date,
    bmf.physical_device_name,
    bs.first_lsn,
    bs.last_lsn,
    bs.checkpoint_lsn,
    bs.database_backup_lsn,
    1
FROM msdb.dbo.backupset bs
INNER JOIN msdb.dbo.backupmediafamily bmf ON bs.media_set_id = bmf.media_set_id
WHERE bs.database_name = @DatabaseName
AND bs.type = 'D'
AND bs.is_copy_only = 0
AND (@RestoreToPointInTime IS NULL OR bs.backup_finish_date <= @RestoreToPointInTime)
ORDER BY bs.backup_finish_date DESC;

IF NOT EXISTS (SELECT 1 FROM @BackupChain WHERE BackupType = 'FULL')
BEGIN
    RAISERROR('No full backup found for database "%s"', 16, 1, @DatabaseName);
    RETURN;
END

DECLARE @FullBackupLSN NUMERIC(25,0);
SELECT @FullBackupLSN = LastLSN FROM @BackupChain WHERE BackupType = 'FULL';

-- Get differential backup (if exists and newer than full backup)
INSERT INTO @BackupChain (BackupType, BackupSetID, BackupStartDate, BackupFinishDate, PhysicalDeviceName, FirstLSN, LastLSN, CheckpointLSN, DatabaseBackupLSN, IsRequired)
SELECT TOP 1
    'DIFF',
    bs.backup_set_id,
    bs.backup_start_date,
    bs.backup_finish_date,
    bmf.physical_device_name,
    bs.first_lsn,
    bs.last_lsn,
    bs.checkpoint_lsn,
    bs.database_backup_lsn,
    1
FROM msdb.dbo.backupset bs
INNER JOIN msdb.dbo.backupmediafamily bmf ON bs.media_set_id = bmf.media_set_id
WHERE bs.database_name = @DatabaseName
AND bs.type = 'I'
AND bs.is_copy_only = 0
AND bs.database_backup_lsn = @FullBackupLSN
AND (@RestoreToPointInTime IS NULL OR bs.backup_finish_date <= @RestoreToPointInTime)
ORDER BY bs.backup_finish_date DESC;

DECLARE @LastBackupLSN NUMERIC(25,0);
IF EXISTS (SELECT 1 FROM @BackupChain WHERE BackupType = 'DIFF')
    SELECT @LastBackupLSN = LastLSN FROM @BackupChain WHERE BackupType = 'DIFF';
ELSE
    SELECT @LastBackupLSN = LastLSN FROM @BackupChain WHERE BackupType = 'FULL';

-- Get transaction log backups
INSERT INTO @BackupChain (BackupType, BackupSetID, BackupStartDate, BackupFinishDate, PhysicalDeviceName, FirstLSN, LastLSN, CheckpointLSN, DatabaseBackupLSN, IsRequired)
SELECT 
    'LOG',
    bs.backup_set_id,
    bs.backup_start_date,
    bs.backup_finish_date,
    bmf.physical_device_name,
    bs.first_lsn,
    bs.last_lsn,
    bs.checkpoint_lsn,
    bs.database_backup_lsn,
    1
FROM msdb.dbo.backupset bs
INNER JOIN msdb.dbo.backupmediafamily bmf ON bs.media_set_id = bmf.media_set_id
WHERE bs.database_name = @DatabaseName
AND bs.type = 'L'
AND bs.first_lsn > @LastBackupLSN
AND (@RestoreToPointInTime IS NULL OR bs.backup_finish_date <= @RestoreToPointInTime)
ORDER BY bs.backup_finish_date ASC;

-- Display restore chain
PRINT 'RESTORE CHAIN:';
SELECT 
    SequenceID,
    BackupType,
    BackupFinishDate,
    PhysicalDeviceName,
    CASE 
        WHEN BackupType = 'FULL' THEN 'YES - Start here'
        WHEN BackupType = 'DIFF' THEN 'YES - Apply after full'
        ELSE 'YES - Apply in sequence'
    END AS IsRequired
FROM @BackupChain
ORDER BY SequenceID;

PRINT '';

-- ============================================================================
-- RESTORE FULL BACKUP
-- ============================================================================
DECLARE @FullBackupFile NVARCHAR(260);
SELECT @FullBackupFile = PhysicalDeviceName FROM @BackupChain WHERE BackupType = 'FULL';

PRINT '================================================================================';
PRINT 'STEP 1: RESTORING FULL BACKUP';
PRINT '================================================================================';
PRINT 'Backup File: ' + @FullBackupFile;
PRINT '';

-- Get logical file names from backup
DECLARE @FileList TABLE (
    LogicalName NVARCHAR(128),
    PhysicalName NVARCHAR(260),
    Type CHAR(1),
    FileGroupName NVARCHAR(128),
    Size NUMERIC(20,0),
    MaxSize NUMERIC(20,0),
    FileID INT,
    CreateLSN NUMERIC(25,0),
    DropLSN NUMERIC(25,0),
    UniqueID UNIQUEIDENTIFIER,
    ReadOnlyLSN NUMERIC(25,0),
    ReadWriteLSN NUMERIC(25,0),
    BackupSizeInBytes BIGINT,
    SourceBlockSize INT,
    FileGroupId INT,
    LogGroupGUID UNIQUEIDENTIFIER,
    DifferentialBaseLSN NUMERIC(25,0),
    DifferentialBaseGUID UNIQUEIDENTIFIER,
    IsReadOnly BIT,
    IsPresent BIT,
    TDEThumbprint VARBINARY(32)
);

DECLARE @FileListSQL NVARCHAR(MAX) = N'RESTORE FILELISTONLY FROM DISK = ''' + REPLACE(@FullBackupFile, '''', '''''') + N''';';

INSERT INTO @FileList
EXEC sp_executesql @FileListSQL;

-- Build RESTORE statement
DECLARE @RestoreSQL NVARCHAR(MAX) = N'
RESTORE DATABASE [' + QUOTENAME(@NewDatabaseName) + N']
FROM DISK = ''' + REPLACE(@FullBackupFile, '''', '''''') + N'''
WITH 
    NORECOVERY,
    CHECKSUM,
    STATS = 10
';

-- Add MOVE clauses if new paths specified
DECLARE @LogicalName NVARCHAR(128);
DECLARE @FileType CHAR(1);

DECLARE file_cursor CURSOR FOR 
    SELECT LogicalName, Type FROM @FileList;

OPEN file_cursor;
FETCH NEXT FROM file_cursor INTO @LogicalName, @FileType;

WHILE @@FETCH_STATUS = 0
BEGIN
    DECLARE @NewPath NVARCHAR(260);
    
    IF @FileType = 'D' -- Data file
    BEGIN
        IF @NewDataPath IS NOT NULL
        BEGIN
            IF RIGHT(@NewDataPath, 1) <> '\' SET @NewDataPath = @NewDataPath + '\';
            SET @NewPath = @NewDataPath + @NewDatabaseName + CASE WHEN @LogicalName LIKE '%_Data' THEN '_Data.mdf' ELSE '.ndf' END;
        END
        ELSE
        BEGIN
            SELECT @NewPath = PhysicalName FROM @FileList WHERE LogicalName = @LogicalName;
        END
    END
    ELSE IF @FileType = 'L' -- Log file
    BEGIN
        IF @NewLogPath IS NOT NULL
        BEGIN
            IF RIGHT(@NewLogPath, 1) <> '\' SET @NewLogPath = @NewLogPath + '\';
            SET @NewPath = @NewLogPath + @NewDatabaseName + '_Log.ldf';
        END
        ELSE
        BEGIN
            SELECT @NewPath = PhysicalName FROM @FileList WHERE LogicalName = @LogicalName;
        END
    END
    
    IF @NewPath IS NOT NULL
        SET @RestoreSQL = @RestoreSQL + N',
    MOVE N''' + REPLACE(@LogicalName, '''', '''''') + N''' TO N''' + REPLACE(@NewPath, '''', '''''') + N'''';
    
    FETCH NEXT FROM file_cursor INTO @LogicalName, @FileType;
END

CLOSE file_cursor;
DEALLOCATE file_cursor;

SET @RestoreSQL = @RestoreSQL + N';';

BEGIN TRY
    EXEC sp_executesql @RestoreSQL;
    PRINT 'Full backup restored successfully (NORECOVERY mode).';
END TRY
BEGIN CATCH
    DECLARE @FullErrMsg NVARCHAR(4000) = ERROR_MESSAGE();
    RAISERROR('Full backup restore failed: %s', 16, 1, @FullErrMsg);
    RETURN;
END CATCH

-- ============================================================================
-- RESTORE DIFFERENTIAL BACKUP (if exists)
-- ============================================================================
IF EXISTS (SELECT 1 FROM @BackupChain WHERE BackupType = 'DIFF')
BEGIN
    DECLARE @DiffBackupFile NVARCHAR(260);
    SELECT @DiffBackupFile = PhysicalDeviceName FROM @BackupChain WHERE BackupType = 'DIFF';
    
    PRINT '';
    PRINT '================================================================================';
    PRINT 'STEP 2: RESTORING DIFFERENTIAL BACKUP';
    PRINT '================================================================================';
    PRINT 'Backup File: ' + @DiffBackupFile;
    PRINT '';
    
    DECLARE @DiffRestoreSQL NVARCHAR(MAX) = N'
    RESTORE DATABASE [' + QUOTENAME(@NewDatabaseName) + N']
    FROM DISK = ''' + REPLACE(@DiffBackupFile, '''', '''''') + N'''
    WITH 
        NORECOVERY,
        CHECKSUM,
        STATS = 10;
    ';
    
    BEGIN TRY
        EXEC sp_executesql @DiffRestoreSQL;
        PRINT 'Differential backup restored successfully (NORECOVERY mode).';
    END TRY
    BEGIN CATCH
        DECLARE @DiffErrMsg NVARCHAR(4000) = ERROR_MESSAGE();
        RAISERROR('Differential backup restore failed: %s', 16, 1, @DiffErrMsg);
        RETURN;
    END CATCH
END

-- ============================================================================
-- RESTORE TRANSACTION LOG BACKUPS
-- ============================================================================
DECLARE @LogBackupFile NVARCHAR(260);
DECLARE @LogSequence INT = 0;

DECLARE log_cursor CURSOR FOR 
    SELECT PhysicalDeviceName FROM @BackupChain WHERE BackupType = 'LOG' ORDER BY SequenceID;

OPEN log_cursor;
FETCH NEXT FROM log_cursor INTO @LogBackupFile;

WHILE @@FETCH_STATUS = 0
BEGIN
    SET @LogSequence = @LogSequence + 1;
    
    PRINT '';
    PRINT '================================================================================';
    PRINT 'STEP ' + CAST((2 + @LogSequence) AS VARCHAR(10)) + ': RESTORING TRANSACTION LOG #' + CAST(@LogSequence AS VARCHAR(10));
    PRINT '================================================================================';
    PRINT 'Backup File: ' + @LogBackupFile;
    PRINT '';
    
    DECLARE @LogRestoreSQL NVARCHAR(MAX);
    
    IF @LogSequence = (SELECT COUNT(*) FROM @BackupChain WHERE BackupType = 'LOG')
    AND @WithRecovery = 1
    AND (@RestoreToPointInTime IS NULL)
    BEGIN
        -- Last log backup, restore with recovery
        SET @LogRestoreSQL = N'
        RESTORE LOG [' + QUOTENAME(@NewDatabaseName) + N']
        FROM DISK = ''' + REPLACE(@LogBackupFile, '''', '''''') + N'''
        WITH 
            RECOVERY,
            CHECKSUM,
            STATS = 10;
        ';
    END
    ELSE
    BEGIN
        -- Intermediate log backups, restore with NORECOVERY
        SET @LogRestoreSQL = N'
        RESTORE LOG [' + QUOTENAME(@NewDatabaseName) + N']
        FROM DISK = ''' + REPLACE(@LogBackupFile, '''', '''''') + N'''
        WITH 
            NORECOVERY,
            CHECKSUM,
            STATS = 10';
        
        -- Add point-in-time recovery if specified
        IF @RestoreToPointInTime IS NOT NULL
        BEGIN
            IF @LogSequence = (SELECT COUNT(*) FROM @BackupChain WHERE BackupType = 'LOG')
            BEGIN
                SET @LogRestoreSQL = @LogRestoreSQL + N',
            STOPAT = ''' + CONVERT(VARCHAR(23), @RestoreToPointInTime, 120) + N''',
            RECOVERY';
            END
        END
        
        SET @LogRestoreSQL = @LogRestoreSQL + N';';
    END
    
    BEGIN TRY
        EXEC sp_executesql @LogRestoreSQL;
        PRINT 'Transaction log restored successfully.';
    END TRY
    BEGIN CATCH
        DECLARE @LogErrMsg NVARCHAR(4000) = ERROR_MESSAGE();
        PRINT 'Warning: Transaction log restore failed: ' + @LogErrMsg;
        -- Continue with next log if possible
    END CATCH
    
    FETCH NEXT FROM log_cursor INTO @LogBackupFile;
END

CLOSE log_cursor;
DEALLOCATE log_cursor;

-- ============================================================================
-- FINAL RECOVERY (if not already done)
-- ============================================================================
IF @WithRecovery = 1
BEGIN
    DECLARE @RecoveryState VARCHAR(20);
    SELECT @RecoveryState = state_desc 
    FROM sys.databases 
    WHERE name = @NewDatabaseName;
    
    IF @RecoveryState = 'RESTORING'
    BEGIN
        PRINT '';
        PRINT '================================================================================';
        PRINT 'FINAL STEP: RECOVERING DATABASE';
        PRINT '================================================================================';
        
        DECLARE @RecoverySQL NVARCHAR(MAX) = N'
        RESTORE DATABASE [' + QUOTENAME(@NewDatabaseName) + N'] WITH RECOVERY;';
        
        BEGIN TRY
            EXEC sp_executesql @RecoverySQL;
            PRINT 'Database recovered successfully and is now online.';
        END TRY
        BEGIN CATCH
            DECLARE @RecoveryErrMsg NVARCHAR(4000) = ERROR_MESSAGE();
            RAISERROR('Recovery failed: %s', 16, 1, @RecoveryErrMsg);
        END CATCH
    END
END

-- ============================================================================
-- SUMMARY
-- ============================================================================
PRINT '';
PRINT '================================================================================';
PRINT 'RESTORE COMPLETED';
PRINT '================================================================================';
PRINT 'Database:         ' + @NewDatabaseName;
PRINT 'Restore Time:     ' + CONVERT(VARCHAR(23), GETDATE(), 120);
PRINT 'Database Status:  ' + (
    SELECT state_desc FROM sys.databases WHERE name = @NewDatabaseName
);
PRINT '================================================================================';
GO

