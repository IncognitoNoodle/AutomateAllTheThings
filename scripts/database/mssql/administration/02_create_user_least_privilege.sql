/*
================================================================================
SCRIPT: Create Database User with Least Privilege Principles
================================================================================
PURPOSE:
    Provisions database users with appropriate permissions following the
    principle of least privilege. Supports Windows Authentication, SQL
    Authentication, and application service accounts.

BUSINESS APPLICATION:
    Used when onboarding new applications, developers, or services to ensure
    security compliance and prevent privilege escalation. Critical for audit
    requirements (SOC2, HIPAA, PCI-DSS) where user access must be documented
    and minimized.

PREREQUISITES:
    - SQL Server 2019 or higher
    - Permissions: sysadmin or securityadmin role
    - For Windows Authentication: Domain account must exist

PARAMETERS:
    @LoginType       - 'WINDOWS' or 'SQL' (REQUIRED)
    @LoginName       - Login name (domain\username or SQL login) (REQUIRED)
    @DatabaseName    - Target database (REQUIRED)
    @UserName        - Database user name (OPTIONAL, defaults to @LoginName)
    @DefaultSchema   - Default schema for user (OPTIONAL, default: dbo)
    @RoleMemberships - Comma-separated list of roles: 'db_datareader,db_datawriter'

USAGE EXAMPLE:
    -- Windows Authentication User
    EXEC dbo.usp_CreateUserLeastPrivilege
        @LoginType = 'WINDOWS',
        @LoginName = 'DOMAIN\John.Doe',
        @DatabaseName = 'ProductionDB',
        @DefaultSchema = 'Sales',
        @RoleMemberships = 'db_datareader,db_datawriter';

    -- SQL Authentication User
    EXEC dbo.usp_CreateUserLeastPrivilege
        @LoginType = 'SQL',
        @LoginName = 'AppServiceAccount',
        @DatabaseName = 'ProductionDB',
        @DefaultSchema = 'dbo',
        @RoleMemberships = 'db_datareader';

EXPECTED OUTPUT:
    Creates login (if SQL) and database user with specified permissions.
    Returns summary of created objects and permissions granted.

REFERENCES:
    - Microsoft Docs: CREATE LOGIN
      https://docs.microsoft.com/en-us/sql/t-sql/statements/create-login-transact-sql
    - Microsoft Docs: CREATE USER
      https://docs.microsoft.com/en-us/sql/t-sql/statements/create-user-transact-sql
    - Principle of Least Privilege Best Practices
      https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices
================================================================================
*/

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ============================================================================
-- CONFIGURATION SECTION
-- ============================================================================
DECLARE @LoginType       VARCHAR(10) = 'WINDOWS';     -- 'WINDOWS' or 'SQL'
DECLARE @LoginName       SYSNAME = N'DOMAIN\user';   -- REQUIRED
DECLARE @DatabaseName    SYSNAME = N'YourDatabase';   -- REQUIRED
DECLARE @UserName        SYSNAME = NULL;              -- OPTIONAL (defaults to login name)
DECLARE @DefaultSchema   SYSNAME = N'dbo';            -- OPTIONAL (default: dbo)
DECLARE @RoleMemberships NVARCHAR(500) = 'db_datareader'; -- Comma-separated roles
DECLARE @SQLPassword     NVARCHAR(128) = NULL;        -- Required if @LoginType = 'SQL'

-- ============================================================================
-- VALIDATION
-- ============================================================================
IF @LoginName IS NULL OR @LoginName = ''
BEGIN
    RAISERROR('@LoginName cannot be NULL or empty', 16, 1);
    RETURN;
END

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

IF @LoginType NOT IN ('WINDOWS', 'SQL')
BEGIN
    RAISERROR('@LoginType must be either "WINDOWS" or "SQL"', 16, 1);
    RETURN;
END

IF @LoginType = 'SQL' AND (@SQLPassword IS NULL OR @SQLPassword = '')
BEGIN
    RAISERROR('@SQLPassword is required when @LoginType = "SQL"', 16, 1);
    RETURN;
END

IF @UserName IS NULL OR @UserName = ''
    SET @UserName = @LoginName;

-- ============================================================================
-- CREATE LOGIN (if SQL authentication or if login doesn't exist)
-- ============================================================================
IF @LoginType = 'SQL'
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = @LoginName)
    BEGIN
        DECLARE @CreateLoginSQL NVARCHAR(MAX);
        SET @CreateLoginSQL = N'
        CREATE LOGIN [' + REPLACE(@LoginName, ']', ']]') + N']
        WITH PASSWORD = ''' + @SQLPassword + N''' MUST_CHANGE,
             DEFAULT_DATABASE = [' + QUOTENAME(@DatabaseName) + N'],
             CHECK_EXPIRATION = ON,
             CHECK_POLICY = ON;
        ';
        
        BEGIN TRY
            EXEC sp_executesql @CreateLoginSQL;
            PRINT 'Created SQL Server login: ' + @LoginName;
        END TRY
        BEGIN CATCH
            DECLARE @ErrMsg NVARCHAR(4000) = ERROR_MESSAGE();
            RAISERROR('Error creating login: %s', 16, 1, @ErrMsg);
            RETURN;
        END CATCH
    END
    ELSE
    BEGIN
        PRINT 'Login already exists: ' + @LoginName;
    END
END
ELSE -- Windows Authentication
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = @LoginName)
    BEGIN
        DECLARE @CreateWinLoginSQL NVARCHAR(MAX);
        SET @CreateWinLoginSQL = N'
        CREATE LOGIN [' + REPLACE(@LoginName, ']', ']]') + N']
        FROM WINDOWS
        WITH DEFAULT_DATABASE = [' + QUOTENAME(@DatabaseName) + N'];
        ';
        
        BEGIN TRY
            EXEC sp_executesql @CreateWinLoginSQL;
            PRINT 'Created Windows login: ' + @LoginName;
        END TRY
        BEGIN CATCH
            DECLARE @WinErrMsg NVARCHAR(4000) = ERROR_MESSAGE();
            RAISERROR('Error creating Windows login: %s', 16, 1, @WinErrMsg);
            RETURN;
        END CATCH
    END
    ELSE
    BEGIN
        PRINT 'Login already exists: ' + @LoginName;
    END
END

-- ============================================================================
-- CREATE DATABASE USER
-- ============================================================================
USE [tempdb]; -- Switch to tempdb to execute in target database context
GO

DECLARE @CreateUserSQL NVARCHAR(MAX);
SET @CreateUserSQL = N'
USE [' + QUOTENAME(@DatabaseName) + N'];
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = ''' + REPLACE(@UserName, '''', '''''') + N''')
BEGIN
    CREATE USER [' + REPLACE(@UserName, ']', ']]') + N']
    FOR LOGIN [' + REPLACE(@LoginName, ']', ']]') + N'];
    
    -- Set default schema
    IF SCHEMA_ID(''' + REPLACE(@DefaultSchema, '''', '''''') + N''') IS NOT NULL
    BEGIN
        ALTER USER [' + REPLACE(@UserName, ']', ']]') + N'] WITH DEFAULT_SCHEMA = [' + REPLACE(@DefaultSchema, ']', ']]') + N'];
    END
    
    PRINT ''Created database user: ' + @UserName + ' mapped to login: ' + @LoginName + '';
END
ELSE
BEGIN
    PRINT ''Database user already exists: ' + @UserName + '';
    -- Update default schema if changed
    IF SCHEMA_ID(''' + REPLACE(@DefaultSchema, '''', '''''') + N''') IS NOT NULL
    BEGIN
        ALTER USER [' + REPLACE(@UserName, ']', ']]') + N'] WITH DEFAULT_SCHEMA = [' + REPLACE(@DefaultSchema, ']', ']]') + N'];
        PRINT ''Updated default schema to: ' + @DefaultSchema + '';
    END
END
';

BEGIN TRY
    EXEC sp_executesql @CreateUserSQL;
END TRY
BEGIN CATCH
    DECLARE @UserErrMsg NVARCHAR(4000) = ERROR_MESSAGE();
    RAISERROR('Error creating database user: %s', 16, 1, @UserErrMsg);
    RETURN;
END CATCH

-- ============================================================================
-- GRANT ROLE MEMBERSHIPS
-- ============================================================================
IF @RoleMemberships IS NOT NULL AND @RoleMemberships <> ''
BEGIN
    DECLARE @RoleList TABLE (RoleName NVARCHAR(128));
    DECLARE @RoleName NVARCHAR(128);
    
    -- Parse comma-separated roles
    DECLARE @Roles NVARCHAR(500) = @RoleMemberships;
    WHILE LEN(@Roles) > 0
    BEGIN
        SET @RoleName = LTRIM(RTRIM(LEFT(@Roles, CHARINDEX(',', @Roles + ',') - 1)));
        IF @RoleName <> ''
            INSERT INTO @RoleList VALUES (@RoleName);
        SET @Roles = SUBSTRING(@Roles, CHARINDEX(',', @Roles + ',') + 1, LEN(@Roles));
    END
    
    DECLARE role_cursor CURSOR FOR SELECT RoleName FROM @RoleList;
    OPEN role_cursor;
    FETCH NEXT FROM role_cursor INTO @RoleName;
    
    WHILE @@FETCH_STATUS = 0
    BEGIN
        DECLARE @AddRoleSQL NVARCHAR(MAX);
        SET @AddRoleSQL = N'
        USE [' + QUOTENAME(@DatabaseName) + N'];
        
        IF IS_ROLEMEMBER(''' + REPLACE(@RoleName, '''', '''''') + N''', ''' + REPLACE(@UserName, '''', '''''') + N''') = 0
        BEGIN
            ALTER ROLE [' + REPLACE(@RoleName, ']', ']]') + N'] ADD MEMBER [' + REPLACE(@UserName, ']', ']]') + N'];
            PRINT ''Added user to role: ' + @RoleName + '';
        END
        ELSE
        BEGIN
            PRINT ''User already in role: ' + @RoleName + '';
        END
        ';
        
        BEGIN TRY
            EXEC sp_executesql @AddRoleSQL;
        END TRY
        BEGIN CATCH
            PRINT 'Warning: Could not add user to role ' + @RoleName + ': ' + ERROR_MESSAGE();
        END CATCH
        
        FETCH NEXT FROM role_cursor INTO @RoleName;
    END
    
    CLOSE role_cursor;
    DEALLOCATE role_cursor;
END

-- ============================================================================
-- SUMMARY
-- ============================================================================
PRINT '';
PRINT '================================================================================';
PRINT 'USER PROVISIONING SUMMARY';
PRINT '================================================================================';
PRINT 'Login Type:        ' + @LoginType;
PRINT 'Login Name:        ' + @LoginName;
PRINT 'Database:          ' + @DatabaseName;
PRINT 'Database User:     ' + @UserName;
PRINT 'Default Schema:    ' + @DefaultSchema;
PRINT 'Role Memberships:  ' + ISNULL(@RoleMemberships, 'None');
PRINT '================================================================================';
GO

