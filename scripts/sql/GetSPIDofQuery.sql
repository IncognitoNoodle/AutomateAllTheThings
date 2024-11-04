DECLARE @sqltext VARBINARY(128)
SELECT @sqltext = sql_handle
FROM sys.sysprocesses
WHERE spid = 61
SELECT TEXT
FROM ::fn_get_sql(@sqltext)
GO