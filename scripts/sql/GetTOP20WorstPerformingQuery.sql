SELECT TOP 20
 ObjectName                 = OBJECT_SCHEMA_NAME(qt.objectid,DBID) + '.' + OBJECT_NAME(qt.objectid, qt.DBID)
,StatementText = SUBSTRING(qt.TEXT, (QS.statement_start_offset/2) + 1,
    ((CASE statement_end_offset
        WHEN -1 THEN DATALENGTH(qt.TEXT)
        ELSE QS.statement_end_offset END
            - QS.statement_start_offset)/2) + 1) 
---- Query within the proc
 
,TextData                   = qt.TEXT 
---- The SQL Text that was executed
 
,DiskReads                  = qs.total_physical_reads 
---- The worst reads, disk reads
 
,MemoryReads                = qs.total_logical_reads 
---- Logical Reads are memory reads
 
,Executions                 = qs.execution_count 
---- the counts of the query being executed since reboot
 
,TotalCPUTime_ms            = qs.total_worker_time/1000 
---- The CPU time that the query consumes
 
,AverageCPUTime_ms          = qs.total_worker_time/(1000*qs.execution_count) 
---- the Average CPU Time for the query
 
,AvgDiskWaitAndCPUTime_ms   = qs.total_elapsed_time/(1000*qs.execution_count) 
---- the average duration to execute the plan - CPU and Disk
 
,MemoryWrites               = qs.max_logical_writes
,DateCached                 = qs.creation_time
,DatabaseName               = DB_Name(qt.DBID)
,LastExecutionTime          = qs.last_execution_time
FROM sys.dm_exec_query_stats AS qs
CROSS APPLY sys.dm_exec_sql_text(qs.SQL_HANDLE) AS qt
WHERE DB_Name(qt.dbid) IS NOT NULL AND qt.dbid > 5
----connect and give your db name here (cross db works fine in on-premises and not works on Azure)
--ORDER BY qs.total_worker_time DESC 
---- (Most CPU usage = Worst performing CPU bound queries)
--ORDER BY qs.total_worker_time/qs.execution_count DESC 
---- highest average CPU usage
--ORDER BY qs.total_elapsed_time/(1000*qs.execution_count) DESC 
---- highest average w/ wait time
ORDER BY total_logical_reads DESC
---- (Memory Reads = Worst performing I/O bound queries)