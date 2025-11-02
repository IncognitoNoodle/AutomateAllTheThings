/*
================================================================================
SCRIPT: Audit Schema Changes and Track Login History
================================================================================
PURPOSE:
    Sets up SQL Server Audit to track schema changes, object modifications,
    and login history for compliance and security monitoring.

BUSINESS APPLICATION:
    Required for audit compliance (SOC2, HIPAA, PCI-DSS, SOX). Tracks who
    changed what and when, enabling forensic analysis after security incidents
    and ensuring change management policies are followed.

PREREQUISITES:
    - SQL Server 2019 or higher (Audit feature available)
    - sysadmin role required
    - Disk space for audit logs
    - Permissions to write to audit file location

PARAMETERS:
    @AuditName           - Name for the audit object
    @AuditFilePath       - File path for audit logs (must exist)
    @MaxRolloverFiles    - Maximum number of audit files (default: 10)
    @MaxFileSizeMB       - Maximum size per audit file in MB (default: 1024)
    @TrackSchemaChanges  - Track DDL changes (1 = ON, default)
    @TrackLoginHistory   - Track login/logout events (1 = ON, default)
    @TrackDataChanges    - Track data modifications (optional, increases overhead)

USAGE EXAMPLE:
    EXEC dbo.usp_SetupSchemaChangeAudit
        @AuditName = 'ProductionSchemaAudit',
        @AuditFilePath = 'D:\SQLAudit\',
        @MaxRolloverFiles = 20,
        @TrackSchemaChanges = 1,
        @TrackLoginHistory = 1;

EXPECTED OUTPUT:
    Creates server audit and database audit specification.
    Returns audit configuration and query examples for reviewing audit logs.

REFERENCES:
    - Microsoft Docs: SQL Server Audit
      https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine
    - Compliance and Auditing: https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine
================================================================================
*/

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ============================================================================
-- CONFIGURATION SECTION
-- ============================================================================
DECLARE @AuditName           SYSNAME = N'ProductionSchemaAudit';
DECLARE @AuditFilePath       NVARCHAR(260) = N'D:\SQLAudit\'; -- Modify as needed
DECLARE @MaxRolloverFiles    INT = 10;
DECLARE @MaxFileSizeMB       INT = 1024; -- 1 GB per file
DECLARE @TrackSchemaChanges  BIT = 1;    -- Track DDL changes
DECLARE @TrackLoginHistory   BIT = 1;    -- Track login/logout
DECLARE @TrackDataChanges    BIT = 0;    -- Track INSERT/UPDATE/DELETE (optional, high overhead)
DECLARE @DatabaseName        SYSNAME = NULL; -- NULL = track all databases, or specify database

-- ============================================================================
-- VALIDATION
-- ============================================================================
IF @AuditName IS NULL OR @AuditName = ''
BEGIN
    RAISERROR('@AuditName cannot be NULL or empty', 16, 1);
    RETURN;
END

IF @AuditFilePath IS NULL OR @AuditFilePath = ''
BEGIN
    RAISERROR('@AuditFilePath cannot be NULL or empty', 16, 1);
    RETURN;
END

-- Ensure path ends with backslash
IF RIGHT(@AuditFilePath, 1) <> '\' 
    SET @AuditFilePath = @AuditFilePath + '\';

-- Check if audit already exists
IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = @AuditName)
BEGIN
    PRINT 'Audit "' + @AuditName + '" already exists. Dropping and recreating...';
    DECLARE @DropAuditSQL NVARCHAR(MAX) = N'DROP SERVER AUDIT [' + REPLACE(@AuditName, ']', ']]') + N'];';
    EXEC sp_executesql @DropAuditSQL;
END

-- ============================================================================
-- CREATE SERVER AUDIT
-- ============================================================================
DECLARE @CreateAuditSQL NVARCHAR(MAX);
SET @CreateAuditSQL = N'
CREATE SERVER AUDIT [' + REPLACE(@AuditName, ']', ']]') + N']
TO FILE (
    FILEPATH = ''' + REPLACE(@AuditFilePath, '''', '''''') + N''',
    MAXSIZE = ' + CAST(@MaxFileSizeMB AS NVARCHAR(10)) + N'MB,
    MAX_ROLLOVER_FILES = ' + CAST(@MaxRolloverFiles AS NVARCHAR(10)) + N',
    RESERVE_DISK_SPACE = OFF
)
WITH (
    QUEUE_DELAY = 1000,              -- 1 second delay (milliseconds)
    ON_FAILURE = CONTINUE,           -- Continue if audit fails (change to SHUTDOWN for strict compliance)
    AUDIT_GUID = NEWID()
);
';

BEGIN TRY
    EXEC sp_executesql @CreateAuditSQL;
    PRINT 'Created server audit: ' + @AuditName;
END TRY
BEGIN CATCH
    DECLARE @ErrMsg NVARCHAR(4000) = ERROR_MESSAGE();
    RAISERROR('Error creating server audit: %s', 16, 1, @ErrMsg);
    RETURN;
END CATCH

-- ============================================================================
-- ENABLE SERVER AUDIT
-- ============================================================================
DECLARE @EnableAuditSQL NVARCHAR(MAX);
SET @EnableAuditSQL = N'ALTER SERVER AUDIT [' + REPLACE(@AuditName, ']', ']]') + N'] WITH (STATE = ON);';

BEGIN TRY
    EXEC sp_executesql @EnableAuditSQL;
    PRINT 'Enabled server audit: ' + @AuditName;
END TRY
BEGIN CATCH
    DECLARE @EnableErrMsg NVARCHAR(4000) = ERROR_MESSAGE();
    RAISERROR('Error enabling server audit: %s', 16, 1, @EnableErrMsg);
    RETURN;
END CATCH

-- ============================================================================
-- CREATE SERVER AUDIT SPECIFICATION (for login/logout events)
-- ============================================================================
IF @TrackLoginHistory = 1
BEGIN
    DECLARE @ServerSpecName SYSNAME = @AuditName + '_ServerSpec';
    
    IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = @ServerSpecName)
    BEGIN
        DECLARE @DropServerSpecSQL NVARCHAR(MAX) = N'
        ALTER SERVER AUDIT SPECIFICATION [' + REPLACE(@ServerSpecName, ']', ']]') + N'] WITH (STATE = OFF);
        DROP SERVER AUDIT SPECIFICATION [' + REPLACE(@ServerSpecName, ']', ']]') + N'];
        ';
        EXEC sp_executesql @DropServerSpecSQL;
    END
    
    DECLARE @CreateServerSpecSQL NVARCHAR(MAX);
    SET @CreateServerSpecSQL = N'
    CREATE SERVER AUDIT SPECIFICATION [' + REPLACE(@ServerSpecName, ']', ']]') + N']
    FOR SERVER AUDIT [' + REPLACE(@AuditName, ']', ']]') + N']
    ADD (SUCCESSFUL_LOGIN_GROUP),
    ADD (FAILED_LOGIN_GROUP),
    ADD (LOGOUT_GROUP),
    ADD (SERVER_STATE_CHANGE_GROUP),
    ADD (SERVER_PRINCIPAL_IMPERSONATION_GROUP),
    ADD (DATABASE_PRINCIPAL_IMPERSONATION_GROUP),
    ADD (SERVER_PERMISSION_CHANGE_GROUP),
    ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP)
    WITH (STATE = ON);
    ';
    
    BEGIN TRY
        EXEC sp_executesql @CreateServerSpecSQL;
        PRINT 'Created server audit specification for login tracking: ' + @ServerSpecName;
    END TRY
    BEGIN CATCH
        PRINT 'Warning: Could not create server audit specification: ' + ERROR_MESSAGE();
    END CATCH
END

-- ============================================================================
-- CREATE DATABASE AUDIT SPECIFICATION (for schema and data changes)
-- ============================================================================
IF @TrackSchemaChanges = 1
BEGIN
    DECLARE @TargetDatabase SYSNAME;
    DECLARE @DbList TABLE (DatabaseName SYSNAME);
    
    -- Get list of databases to audit
    IF @DatabaseName IS NULL
    BEGIN
        INSERT INTO @DbList
        SELECT name FROM sys.databases 
        WHERE state_desc = 'ONLINE' 
        AND is_read_only = 0
        AND name NOT IN ('master', 'tempdb', 'msdb'); -- Skip system databases (optional)
    END
    ELSE
    BEGIN
        INSERT INTO @DbList VALUES (@DatabaseName);
    END
    
    DECLARE db_cursor CURSOR FOR SELECT DatabaseName FROM @DbList;
    OPEN db_cursor;
    FETCH NEXT FROM db_cursor INTO @TargetDatabase;
    
    WHILE @@FETCH_STATUS = 0
    BEGIN
        DECLARE @DbSpecName SYSNAME = @TargetDatabase + '_SchemaAuditSpec';
        DECLARE @CreateDbSpecSQL NVARCHAR(MAX);
        
        SET @CreateDbSpecSQL = N'
        USE [' + QUOTENAME(@TargetDatabase) + N'];
        
        IF EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name = ''' + REPLACE(@DbSpecName, '''', '''''') + N''')
        BEGIN
            ALTER DATABASE AUDIT SPECIFICATION [' + REPLACE(@DbSpecName, ']', ']]') + N'] WITH (STATE = OFF);
            DROP DATABASE AUDIT SPECIFICATION [' + REPLACE(@DbSpecName, ']', ']]') + N'];
        END
        
        CREATE DATABASE AUDIT SPECIFICATION [' + REPLACE(@DbSpecName, ']', ']]') + N']
        FOR SERVER AUDIT [' + REPLACE(@AuditName, ']', ']]') + N']
        ADD (SCHEMA_OBJECT_ACCESS_GROUP),
        ADD (SCHEMA_OBJECT_CHANGE_GROUP),
        ADD (DATABASE_OBJECT_CHANGE_GROUP),
        ADD (DATABASE_PERMISSION_CHANGE_GROUP),
        ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP)
        ';
        
        IF @TrackDataChanges = 1
        BEGIN
            SET @CreateDbSpecSQL = @CreateDbSpecSQL + N',
        ADD (INSERT ON DATABASE::[' + QUOTENAME(@TargetDatabase) + N'] BY [public]),
        ADD (UPDATE ON DATABASE::[' + QUOTENAME(@TargetDatabase) + N'] BY [public]),
        ADD (DELETE ON DATABASE::[' + QUOTENAME(@TargetDatabase) + N'] BY [public])';
        END
        
        SET @CreateDbSpecSQL = @CreateDbSpecSQL + N'
        WITH (STATE = ON);
        ';
        
        BEGIN TRY
            EXEC sp_executesql @CreateDbSpecSQL;
            PRINT 'Created database audit specification for database: ' + @TargetDatabase;
        END TRY
        BEGIN CATCH
            PRINT 'Warning: Could not create database audit specification for ' + @TargetDatabase + ': ' + ERROR_MESSAGE();
        END CATCH
        
        FETCH NEXT FROM db_cursor INTO @TargetDatabase;
    END
    
    CLOSE db_cursor;
    DEALLOCATE db_cursor;
END

-- ============================================================================
-- SUMMARY AND QUERY EXAMPLES
-- ============================================================================
PRINT '';
PRINT '================================================================================';
PRINT 'AUDIT CONFIGURATION COMPLETE';
PRINT '================================================================================';
PRINT 'Audit Name:              ' + @AuditName;
PRINT 'Audit File Path:         ' + @AuditFilePath;
PRINT 'Max File Size:           ' + CAST(@MaxFileSizeMB AS VARCHAR(10)) + ' MB';
PRINT 'Max Rollover Files:      ' + CAST(@MaxRolloverFiles AS VARCHAR(10));
PRINT 'Track Schema Changes:    ' + CASE @TrackSchemaChanges WHEN 1 THEN 'YES' ELSE 'NO' END;
PRINT 'Track Login History:     ' + CASE @TrackLoginHistory WHEN 1 THEN 'YES' ELSE 'NO' END;
PRINT 'Track Data Changes:      ' + CASE @TrackDataChanges WHEN 1 THEN 'YES' ELSE 'NO' END;
PRINT '';
PRINT 'QUERY EXAMPLES:';
PRINT '';
PRINT '-- View all audit events:';
PRINT 'SELECT * FROM sys.fn_get_audit_file(''' + @AuditFilePath + '*.sqlaudit'', DEFAULT, DEFAULT);';
PRINT '';
PRINT '-- View recent schema changes:';
PRINT 'SELECT event_time, server_principal_name, database_name, object_name, statement';
PRINT 'FROM sys.fn_get_audit_file(''' + @AuditFilePath + '*.sqlaudit'', DEFAULT, DEFAULT)';
PRINT 'WHERE action_id IN (''DDL'', ''CREATE'', ''ALTER'', ''DROP'')';
PRINT 'ORDER BY event_time DESC;';
PRINT '';
PRINT '-- View failed login attempts:';
PRINT 'SELECT event_time, server_principal_name, client_ip, application_name, succeeded';
PRINT 'FROM sys.fn_get_audit_file(''' + @AuditFilePath + '*.sqlaudit'', DEFAULT, DEFAULT)';
PRINT 'WHERE action_id = ''LOGIN'' AND succeeded = 0';
PRINT 'ORDER BY event_time DESC;';
PRINT '';
PRINT '================================================================================';
GO

