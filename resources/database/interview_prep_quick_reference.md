# SQL DBA Interview Quick Reference

Quick reference guide for discussing this script collection in technical interviews.

## Key Points to Emphasize

### 1. Production-Ready Approach
- All scripts include error handling and safety checks
- Real-world business applications documented
- Integration with industry-standard tools (Ola Hallengren, Brent Ozar)
- Cloud-native considerations for Azure infrastructure

### 2. Industry Best Practices
- **Ola Hallengren's Maintenance Solution**: Industry standard for production automation
- **Brent Ozar's First Responder Kit**: Gold standard for troubleshooting
- Microsoft best practices embedded throughout
- Documentation references included

### 3. Cloud Expertise
- Azure SQL Database: Automatic Tuning, Query Performance Insights
- Azure SQL Managed Instance: Full SQL Server compatibility
- Hybrid cloud strategies
- Cloud-native backup strategies (Blob Storage)

## Common Interview Topics & Script References

### Performance Tuning

**Scripts**:
- `performance/02_top_performing_queries_dmv.sql` - Identify problem queries
- `performance/03_missing_index_detection.sql` - Find index opportunities
- `performance/01_index_fragmentation_analysis.sql` - Maintenance needs

**How to Discuss**:
1. Use DMVs (`sys.dm_exec_query_stats`) for real-time analysis
2. Query Store for historical tracking (if enabled)
3. Brent Ozar's `sp_BlitzCache` for comprehensive query analysis
4. Missing index DMVs (`sys.dm_db_missing_index_details`) for opportunities
5. Index fragmentation analysis with Ola's `IndexOptimize` for automation

### Backup & Recovery

**Scripts**:
- `backup_restore/01_automated_backup_full_differential_log.sql` - Automation
- `backup_restore/02_verify_backup_integrity.sql` - Validation
- `backup_restore/03_disaster_recovery_restore.sql` - DR procedures

**How to Discuss**:
1. RPO/RTO requirements drive backup strategy
2. Regular backup verification (not just backup creation)
3. Point-in-time recovery requires log backups
4. Ola Hallengren's `DatabaseBackup` for production (AG-aware, intelligent)
5. Azure: Automatic backups + long-term retention
6. Test restores regularly (automated where possible)

### High Availability

**Scripts**:
- `high_availability/01_always_on_availability_group_monitoring.sql` - AG health
- References to Always On in configuration scripts

**How to Discuss**:
1. Always On AGs for high availability (automatic/manual failover)
2. Synchronization status monitoring critical
3. Failover readiness assessment
4. Replication lag monitoring
5. Azure Managed Instance: Built-in Always On (Business Critical)
6. Azure SQL Database: Active Geo-Replication (different model)

### Security & Compliance

**Scripts**:
- `administration/02_create_user_least_privilege.sql` - User provisioning
- `administration/04_audit_schema_changes.sql` - Auditing

**How to Discuss**:
1. Least privilege principle for user access
2. SQL Server Audit for compliance (SOX, HIPAA, PCI-DSS)
3. Regular access reviews
4. Separation of duties
5. Azure: Additional layer with Azure AD integration

### Monitoring & Proactive Management

**Scripts**:
- `monitoring/01_daily_health_check.sql` - Comprehensive monitoring

**How to Discuss**:
1. Daily health checks prevent issues before users affected
2. Monitor CPU, memory, I/O, blocking
3. SQL Agent alerts for critical conditions
4. Brent Ozar's `sp_Blitz` for overall health
5. Azure Monitor for cloud resources
6. Automated maintenance jobs (Ola's solution)

### Data Integrity

**Scripts**:
- `data_integrity/01_dbcc_checkdb_automation.sql` - Corruption detection

**How to Discuss**:
1. Regular DBCC CHECKDB prevents silent corruption
2. Ola Hallengren's `IntegrityCheck` for production
3. Physical-only checks for large databases (faster)
4. Full checks during maintenance windows
5. Automated alerting on corruption detection

### Cloud Migration & Hybrid Strategies

**Scripts**:
- `cloud/01_azure_sql_database_automatic_tuning.sql` - Azure automation
- `cloud/02_azure_backup_to_blob_storage.sql` - Cloud backups

**How to Discuss**:
1. **Azure SQL Database**: Fully managed, Automatic Tuning, PITR built-in
2. **Azure Managed Instance**: Lift-and-shift compatible, SQL Agent available
3. **Azure VM SQL Server**: Full control, same as on-premises
4. Choose platform based on requirements (management overhead vs. control)
5. Use Azure-native features when available (Automatic Tuning)
6. Hybrid approach: Ola's solution for Managed Instance/VM, Azure features for Database

## Sample Interview Answers

### "How do you optimize a slow database?"

**Answer Framework**:
1. **Identify the problem**:
   - Run `monitoring/01_daily_health_check.sql` for overall health
   - Use `performance/02_top_performing_queries_dmv.sql` to find slow queries
   - Brent Ozar's `sp_BlitzCache` for comprehensive query analysis

2. **Find opportunities**:
   - `performance/03_missing_index_detection.sql` for missing indexes
   - `performance/01_index_fragmentation_analysis.sql` for fragmentation
   - Brent Ozar's `sp_BlitzIndex` for comprehensive index analysis

3. **Implement solutions**:
   - Create high-impact missing indexes (test first!)
   - Rebuild/reorganize fragmented indexes (Ola's `IndexOptimize`)
   - Optimize problematic queries (execution plan analysis)
   - Update statistics if needed

4. **Validate and monitor**:
   - Compare before/after metrics
   - Monitor Query Store (if available)
   - Azure: Review Automatic Tuning recommendations

### "Describe your backup strategy"

**Answer Framework**:
1. **Strategy**:
   - Full backups: Daily or weekly (based on database size/criticality)
   - Differential backups: Between full backups
   - Transaction log backups: Every 15 minutes (critical DBs) to hourly
   - Use Ola Hallengren's `DatabaseBackup` for production automation

2. **Verification**:
   - Automated backup verification (`backup_restore/02_verify_backup_integrity.sql`)
   - Regular restore tests (monthly or quarterly)
   - Monitor backup job success/failure

3. **Retention**:
   - Local backups: 7-14 days
   - Long-term: Azure Blob Storage or separate storage
   - Azure: Long-term retention policies

4. **Cloud Considerations**:
   - Azure SQL Database: Automatic PITR (7-35 days), configure long-term retention
   - Managed Instance: Ola's solution + URL backups to Blob Storage
   - VM SQL Server: Traditional backups + Blob Storage

### "How do you handle a production outage?"

**Answer Framework** (using runbooks):
1. **Assess**:
   - Check daily health check script output
   - Review error logs
   - Identify root cause

2. **Incident Response**:
   - Follow runbooks (`resources/database/runbooks/`)
   - TempDB full: `tempdb_full_incident_response.md`
   - Transaction log full: `transaction_log_full.md`
   - Other incidents: Documented procedures

3. **Resolution**:
   - Quick fix if possible (grow files, kill blocking sessions)
   - Root cause analysis
   - Permanent fix implementation

4. **Prevention**:
   - Update monitoring and alerts
   - Implement proactive measures
   - Document lessons learned

### "How do you ensure security and compliance?"

**Answer Framework**:
1. **Least Privilege**:
   - Use `administration/02_create_user_least_privilege.sql` patterns
   - Regular access reviews
   - Principle of least privilege for all accounts

2. **Auditing**:
   - SQL Server Audit (`administration/04_audit_schema_changes.sql`)
   - Track schema changes, login history
   - Compliance requirements (SOX, HIPAA, PCI-DSS)

3. **Monitoring**:
   - Failed login attempts
   - Unusual access patterns
   - Regular security reviews

4. **Azure Considerations**:
   - Azure AD integration for authentication
   - Azure SQL Database: Built-in advanced threat protection
   - Azure Monitor for security alerts

## Tool Integration Points

### When to Use Ola Hallengren
- **Production automation**: Backup, index maintenance, integrity checks
- **Scheduling**: SQL Agent jobs
- **Logging**: Comprehensive execution logging
- **AG Awareness**: Understands Always On environments

### When to Use Brent Ozar
- **Troubleshooting**: Quick health checks, problem identification
- **Analysis**: Query performance, index analysis
- **Education**: Detailed explanations of findings

### When to Use This Collection
- **Specific scenarios**: Custom requirements, specific use cases
- **Learning**: Understanding how tools work internally
- **Cloud scenarios**: Azure-specific automation
- **Integration**: Combining multiple tools

## Key Takeaways for Interview

1. **Industry Knowledge**: References to Ola Hallengren and Brent Ozar show you know industry standards
2. **Production Experience**: Scripts demonstrate understanding of production requirements
3. **Cloud Expertise**: Azure considerations show modern infrastructure knowledge
4. **Problem-Solving**: Scripts solve real business problems, not just technical exercises
5. **Best Practices**: Documentation references show commitment to following Microsoft best practices
6. **Safety First**: All scripts include safety considerations and testing recommendations

## Quick Script Reference

| Need | Script | Tool Alternative |
|------|--------|------------------|
| Find slow queries | `performance/02_top_performing_queries_dmv.sql` | `sp_BlitzCache` |
| Missing indexes | `performance/03_missing_index_detection.sql` | `sp_BlitzIndex` |
| Index fragmentation | `performance/01_index_fragmentation_analysis.sql` | Ola's `IndexOptimize` |
| Daily health check | `monitoring/01_daily_health_check.sql` | `sp_Blitz` |
| Backup automation | `backup_restore/01_automated_backup_*.sql` | Ola's `DatabaseBackup` |
| Backup verification | `backup_restore/02_verify_backup_integrity.sql` | Manual verification |
| DBCC CHECKDB | `data_integrity/01_dbcc_checkdb_automation.sql` | Ola's `IntegrityCheck` |
| Always On monitoring | `high_availability/01_always_on_*.sql` | Built-in DMVs |
| Azure tuning | `cloud/01_azure_sql_database_automatic_tuning.sql` | Azure Portal |

---

**Remember**: In interviews, emphasize that you use industry-standard tools (Ola, Brent Ozar) for production, and this collection demonstrates your deep understanding of how those tools work and when to use custom solutions.

