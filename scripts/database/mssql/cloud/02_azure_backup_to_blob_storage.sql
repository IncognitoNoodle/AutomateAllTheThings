/*
================================================================================
SCRIPT: Azure SQL Database/Managed Instance - Backup to Blob Storage
================================================================================
PURPOSE:
    Configures automated backups to Azure Blob Storage for Azure SQL Database
    and Managed Instance. Demonstrates URL backup syntax and retention policies.

BUSINESS APPLICATION:
    Essential for Azure cloud-native backup strategies. Provides geo-redundant
    backup storage with automated retention management. Critical for disaster
    recovery in cloud environments and compliance with backup requirements.

CLOUD CONSIDERATIONS:
    - Azure SQL Database: Automatic backups enabled by default (PITR)
    - Azure SQL Managed Instance: Can use URL backups for manual/external backups
    - Both: Long-term retention available via Azure Backup vault

PREREQUISITES:
    - Azure SQL Database or Managed Instance
    - Azure Storage Account with Blob Container
    - Shared Access Signature (SAS) or Storage Account Key
    - Credential created in SQL Server for blob storage access

PARAMETERS:
    @DatabaseName    - Database to backup (REQUIRED)
    @StorageAccount  - Azure Storage Account name (REQUIRED)
    @ContainerName   - Blob container name (REQUIRED)
    @SASOrKey        - Shared Access Signature or Storage Account Key
    @BackupType      - 'FULL', 'DIFF', 'LOG' (REQUIRED)

RELATED TOOLS:
    - Azure Backup for SQL: Long-term retention and automated management
      https://docs.microsoft.com/en-us/azure/backup/backup-azure-sql-database
    - Ola Hallengren: Supports URL backups for Azure
      https://ola.hallengren.com/sql-server-backup.html

USAGE EXAMPLE:
    -- For Azure SQL Managed Instance
    EXEC dbo.usp_BackupToAzureBlob
        @DatabaseName = 'ProductionDB',
        @StorageAccount = 'mystorageaccount',
        @ContainerName = 'sql-backups',
        @BackupType = 'FULL';

EXPECTED OUTPUT:
    Creates backup in Azure Blob Storage.
    Returns backup URL and verification status.

REFERENCES:
    - Microsoft Docs: SQL Server Backup to URL
      https://docs.microsoft.com/en-us/sql/relational-databases/backup-restore/sql-server-backup-to-url
    - Azure Storage: Shared Access Signatures
      https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview
================================================================================
*/

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ============================================================================
-- CONFIGURATION SECTION
-- ============================================================================
DECLARE @DatabaseName    SYSNAME = N'YourDatabase';           -- REQUIRED
DECLARE @StorageAccount  NVARCHAR(100) = N'YourStorageAccount'; -- REQUIRED
DECLARE @ContainerName  NVARCHAR(100) = N'sql-backups';       -- REQUIRED
DECLARE @SASOrKey        NVARCHAR(500) = NULL;                  -- SAS token or storage key
DECLARE @BackupType      VARCHAR(10) = 'FULL';                  -- 'FULL', 'DIFF', 'LOG'
DECLARE @CredentialName  SYSNAME = N'AzureBlobStorageCredential'; -- Credential name

-- ============================================================================
-- NOTES ON AZURE SQL DATABASE
-- ============================================================================
PRINT '================================================================================';
PRINT 'AZURE BACKUP CONFIGURATION';
PRINT '================================================================================';
PRINT '';
PRINT 'IMPORTANT: Azure SQL Database automatically manages backups!';
PRINT '  - Point-in-time restore (PITR): 7-35 days retention';
PRINT '  - Long-term retention: Configure via Azure Portal or PowerShell';
PRINT '  - Manual URL backups: Available for Managed Instance, not SQL Database';
PRINT '';
PRINT 'This script is primarily for Azure SQL Managed Instance.';
PRINT '================================================================================';
PRINT '';

-- Check if Azure SQL Database (doesn't support URL backups)
DECLARE @EngineEdition INT = CAST(SERVERPROPERTY('EngineEdition') AS INT);

IF @EngineEdition = 5 -- Azure SQL Database
BEGIN
    PRINT 'Azure SQL Database detected. Manual URL backups are not supported.';
    PRINT '';
    PRINT 'For Azure SQL Database backup management:';
    PRINT '  1. Automatic PITR backups are already enabled';
    PRINT '  2. Configure long-term retention via Azure Portal';
    PRINT '  3. Use Azure Backup for external backup requirements';
    PRINT '';
    PRINT 'To configure long-term retention:';
    PRINT '  Azure Portal > SQL Database > Backups > Configure policy';
    PRINT '';
    RETURN;
END

-- ============================================================================
-- CREATE CREDENTIAL FOR BLOB STORAGE (if needed)
-- ============================================================================
IF NOT EXISTS (SELECT 1 FROM sys.credentials WHERE name = @CredentialName)
BEGIN
    IF @SASOrKey IS NULL
    BEGIN
        PRINT 'ERROR: @SASOrKey is required to create credential.';
        PRINT '';
        PRINT 'To obtain SAS token:';
        PRINT '  1. Azure Portal > Storage Account > Shared access signature';
        PRINT '  2. Generate SAS token with Read, Write, Delete permissions';
        PRINT '  3. Use full SAS URL as @SASOrKey parameter';
        PRINT '';
        PRINT 'Alternatively, use Storage Account Key:';
        PRINT '  1. Azure Portal > Storage Account > Access keys';
        PRINT '  2. Copy key1 or key2';
        PRINT '  3. Use in format: AccountName=YourAccount;AccountKey=YourKey';
        RETURN;
    END
    
    DECLARE @CreateCredSQL NVARCHAR(MAX);
    
    -- Determine if SAS token or storage key
    IF @SASOrKey LIKE 'https://%'
    BEGIN
        -- SAS token URL
        SET @CreateCredSQL = N'
        CREATE CREDENTIAL [' + REPLACE(@CredentialName, ']', ']]') + N']
        WITH IDENTITY = ''SHARED ACCESS SIGNATURE'',
        SECRET = ''' + REPLACE(@SASOrKey, '''', '''''') + N''';';
    END
    ELSE
    BEGIN
        -- Storage Account Key format: AccountName=Name;AccountKey=Key
        DECLARE @AccountName NVARCHAR(100);
        DECLARE @AccountKey NVARCHAR(500);
        
        -- Parse account name and key (simplified - real implementation would be more robust)
        SET @AccountName = SUBSTRING(@SASOrKey, CHARINDEX('AccountName=', @SASOrKey) + 12, 
            CHARINDEX(';', @SASOrKey, CHARINDEX('AccountName=', @SASOrKey)) - CHARINDEX('AccountName=', @SASOrKey) - 12);
        SET @AccountKey = SUBSTRING(@SASOrKey, CHARINDEX('AccountKey=', @SASOrKey) + 11, LEN(@SASOrKey));
        
        SET @CreateCredSQL = N'
        CREATE CREDENTIAL [' + REPLACE(@CredentialName, ']', ']]') + N']
        WITH IDENTITY = ''' + REPLACE(@AccountName, '''', '''''') + N''',
        SECRET = ''' + REPLACE(@AccountKey, '''', '''''') + N''';';
    END
    
    BEGIN TRY
        EXEC sp_executesql @CreateCredSQL;
        PRINT 'Created credential: ' + @CredentialName;
    END TRY
    BEGIN CATCH
        DECLARE @CredErrMsg NVARCHAR(4000) = ERROR_MESSAGE();
        RAISERROR('Error creating credential: %s', 16, 1, @CredErrMsg);
        RETURN;
    END CATCH
END
ELSE
BEGIN
    PRINT 'Credential already exists: ' + @CredentialName;
END

-- ============================================================================
-- BUILD BACKUP URL
-- ============================================================================
DECLARE @BackupURL NVARCHAR(500);
DECLARE @DateStamp VARCHAR(23) = CONVERT(VARCHAR(23), GETDATE(), 112) + '_' + 
                                  REPLACE(CONVERT(VARCHAR(23), GETDATE(), 108), ':', '');

DECLARE @FileExtension VARCHAR(10);
SET @FileExtension = CASE @BackupType
    WHEN 'FULL' THEN '.bak'
    WHEN 'DIFF' THEN '.bak'
    WHEN 'LOG' THEN '.trn'
END;

-- Construct URL: https://storageaccount.blob.core.windows.net/container/database_backuptype_date.bak
SET @BackupURL = N'https://' + @StorageAccount + N'.blob.core.windows.net/' + 
                 @ContainerName + N'/' + @DatabaseName + N'_' + @BackupType + N'_' + 
                 @DateStamp + @FileExtension;

-- ============================================================================
-- PERFORM BACKUP TO BLOB STORAGE
-- ============================================================================
PRINT '';
PRINT '================================================================================';
PRINT 'BACKUP TO AZURE BLOB STORAGE';
PRINT '================================================================================';
PRINT 'Database:        ' + @DatabaseName;
PRINT 'Backup Type:     ' + @BackupType;
PRINT 'Storage Account: ' + @StorageAccount;
PRINT 'Container:       ' + @ContainerName;
PRINT 'Backup URL:      ' + @BackupURL;
PRINT 'Start Time:      ' + CONVERT(VARCHAR(23), GETDATE(), 120);
PRINT '================================================================================';
PRINT '';

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
TO URL = ''' + REPLACE(@BackupURL, '''', '''''') + N'''
WITH 
    CREDENTIAL = ''' + REPLACE(@CredentialName, '''', '''''') + N''',
    COMPRESSION,
    FORMAT,
    INIT,
    NAME = N''' + @DatabaseName + N'_' + @BackupType + N'_Backup_' + @DateStamp + N''',
    DESCRIPTION = N''' + @BackupType + N' backup to Azure Blob Storage',
    STATS = 10;
';

BEGIN TRY
    EXEC sp_executesql @BackupSQL;
    
    DECLARE @EndTime DATETIME2 = GETDATE();
    DECLARE @DurationSeconds INT = DATEDIFF(SECOND, @StartTime, @EndTime);
    
    PRINT '';
    PRINT '================================================================================';
    PRINT 'BACKUP COMPLETED SUCCESSFULLY';
    PRINT '================================================================================';
    PRINT 'Backup URL:       ' + @BackupURL;
    PRINT 'Duration:         ' + CAST(@DurationSeconds AS VARCHAR(10)) + ' seconds';
    PRINT 'End Time:         ' + CONVERT(VARCHAR(23), @EndTime, 120);
    PRINT '================================================================================';
    
END TRY
BEGIN CATCH
    DECLARE @BackupErrMsg NVARCHAR(4000) = ERROR_MESSAGE();
    DECLARE @BackupErrSeverity INT = ERROR_SEVERITY();
    DECLARE @BackupErrState INT = ERROR_STATE();
    
    RAISERROR('Backup failed: %s', @BackupErrSeverity, @BackupErrState, @BackupErrMsg);
    RETURN;
END CATCH

-- ============================================================================
-- RESTORE VERIFICATION (optional)
-- ============================================================================
PRINT '';
PRINT 'Verifying backup...';

DECLARE @VerifySQL NVARCHAR(MAX);
SET @VerifySQL = N'RESTORE VERIFYONLY FROM URL = ''' + REPLACE(@BackupURL, '''', '''''') + N'''
WITH CREDENTIAL = ''' + REPLACE(@CredentialName, '''', '''''') + N''';';

BEGIN TRY
    EXEC sp_executesql @VerifySQL;
    PRINT 'Backup verification: PASSED';
END TRY
BEGIN CATCH
    PRINT 'Warning: Backup verification failed: ' + ERROR_MESSAGE();
END CATCH

-- ============================================================================
-- SUMMARY AND CLOUD-SPECIFIC NOTES
-- ============================================================================
PRINT '';
PRINT '================================================================================';
PRINT 'CLOUD BACKUP RECOMMENDATIONS';
PRINT '================================================================================';
PRINT '';
PRINT 'Azure SQL Database:';
PRINT '  - Automatic PITR backups: 7-35 days (configurable)';
PRINT '  - Long-term retention: Configure via Azure Portal';
PRINT '  - Geo-redundant storage: Enabled by default';
PRINT '  - No manual URL backups required';
PRINT '';
PRINT 'Azure SQL Managed Instance:';
PRINT '  - Automatic backups: Enabled by default';
PRINT '  - Manual URL backups: Use this script';
PRINT '  - Recommended: Use Ola Hallengren''s Backup solution with URL support';
PRINT '  - Link: https://ola.hallengren.com/sql-server-backup.html';
PRINT '';
PRINT 'Azure Backup Integration:';
PRINT '  - Use Azure Backup for centralized backup management';
PRINT '  - Long-term retention policies';
PRINT '  - Cross-region backup';
PRINT '  - Compliance and audit support';
PRINT '';
PRINT '================================================================================';
GO

