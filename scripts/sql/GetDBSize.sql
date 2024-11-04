SELECT
    db_name(database_id) db_name,
    --name,
    sum(size) size,
    sum(size * 8/1024) 'Size (MB)',
    sum(size * 8/(1024 * 1024)) 'Size (GB)',
    max(max_size) max_size
FROM sys.master_files
--WHERE DB_NAME(database_id) = 'WideWorldImporters'
group  by  database_id
order  by  1
;