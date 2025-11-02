# Daily DBA Checklist

This checklist outlines critical daily tasks for SQL Server Database Administrators to ensure system health, performance, and availability.

## Morning Checks (First 2 Hours)

### 1. System Health Overview
- [ ] **Run Health Check Script**
  - Execute `scripts/database/mssql/monitoring/01_daily_health_check.sql`
  - Review CPU, memory, I/O utilization
  - Check for blocking sessions
  - Verify no failed SQL Agent jobs

- [ ] **Check Error Logs**
  - Review SQL Server Error Log for critical errors
  - Check Application Event Log for system issues
  - Verify Windows Event Log for hardware/OS issues

- [ ] **Database Status**
  - Confirm all databases are ONLINE
  - Check for databases in SUSPECT or RECOVERING state
  - Verify read-only databases are intentional

### 2. Backup Verification
- [ ] **Backup Status**
  - Verify overnight backups completed successfully
  - Check backup file sizes are reasonable (not suspiciously small)
  - Confirm backups are written to expected locations
  - For cloud: Verify Azure backup retention policies

- [ ] **Backup Integrity** (Weekly or as scheduled)
  - Run backup verification script
  - `scripts/database/mssql/backup_restore/02_verify_backup_integrity.sql`

### 3. Performance Baseline
- [ ] **Top Resource Consumers**
  - Run `scripts/database/mssql/performance/02_top_performing_queries_dmv.sql`
  - Identify any queries with sudden performance degradation
  - Check for missing index opportunities

- [ ] **Wait Statistics** (Optional but recommended)
  - Review wait statistics for bottlenecks
  - Use Brent Ozar's `sp_BlitzWait` if available

## Ongoing Monitoring

### 4. Active Sessions
- [ ] **Current Activity**
  - Monitor active blocking chains
  - Check for long-running queries
  - Identify resource-intensive operations

### 5. Disk Space
- [ ] **Storage Monitoring**
  - Check available disk space on all drives
  - Monitor database file growth
  - Verify transaction log sizes
  - Review backup retention policies

### 6. Always On / High Availability
- [ ] **Availability Groups** (If applicable)
  - Run `scripts/database/mssql/high_availability/01_always_on_availability_group_monitoring.sql`
  - Verify synchronization status
  - Check failover readiness
  - Review replication lag metrics

## Cloud-Specific Checks

### Azure SQL Database
- [ ] **Azure Portal Review**
  - Check Query Performance Insights
  - Review Automatic Tuning recommendations
  - Verify DTU/VCore utilization
  - Check long-term retention backup status

### Azure SQL Managed Instance
- [ ] **Managed Instance Health**
  - Review Azure Monitor metrics
  - Check resource utilization
  - Verify backup status via Portal
  - Review Always On status (Business Critical tier)

### Azure VM SQL Server
- [ ] **VM Health**
  - Check VM status in Azure Portal
  - Verify VM backups are running
  - Review disk performance metrics
  - Check for VM-level alerts

## Tools Reference

### Recommended Daily Tools
1. **Brent Ozar's First Responder Kit**
   - `sp_Blitz`: Overall health check
   - `sp_BlitzCache`: Query performance
   - `sp_BlitzIndex`: Index analysis
   - Download: https://www.brentozar.com/first-aid/

2. **Ola Hallengren's Maintenance Solution**
   - Automated backup, integrity checks, index maintenance
   - Download: https://ola.hallengren.com/downloads.html

3. **Built-in Scripts**
   - Use scripts in this repository for specific checks
   - Reference documentation in each script

## Weekly Tasks

- [ ] **Index Maintenance Review**
  - Run `scripts/database/mssql/performance/01_index_fragmentation_analysis.sql`
  - Review fragmentation levels
  - Plan maintenance windows if needed

- [ ] **Missing Index Analysis**
  - Run `scripts/database/mssql/performance/03_missing_index_detection.sql`
  - Evaluate index recommendations
  - Test and implement high-impact indexes

- [ ] **DBCC CHECKDB Review**
  - Review integrity check results
  - Verify Ola's IntegrityCheck completed successfully
  - Investigate any corruption warnings

## Monthly Tasks

- [ ] **Capacity Planning**
  - Review database growth trends
  - Project storage requirements
  - Plan for future capacity needs

- [ ] **Security Audit**
  - Review user access and permissions
  - Audit schema changes
  - Review failed login attempts

- [ ] **Documentation Update**
  - Update runbooks with lessons learned
  - Document configuration changes
  - Review and update disaster recovery procedures

## Emergency Response

If critical issues are detected:

1. **Immediate Actions**
   - Assess impact and severity
   - Notify stakeholders if SLA impact
   - Begin incident documentation

2. **Resolution Steps**
   - Follow runbooks in `resources/database/runbooks/`
   - Escalate to senior DBA if needed
   - Document resolution steps

3. **Post-Incident**
   - Conduct post-mortem review
   - Update documentation with findings
   - Implement preventive measures

## Automation Recommendations

### SQL Agent Jobs
- Schedule health checks during off-peak hours
- Automate backup verification
- Set up alerting for critical conditions

### Azure Automation (Cloud)
- Use Azure Automation runbooks for cloud resources
- Set up alert rules in Azure Monitor
- Configure automated responses where appropriate

### Monitoring Solutions
- Consider enterprise monitoring tools:
  - Azure Monitor (for cloud)
  - SQL Server Monitoring solutions
  - Third-party DBA tools

## Notes

- Customize this checklist for your environment
- Adjust frequency based on criticality of systems
- Document any environment-specific checks
- Review and update checklist quarterly

---

**Last Updated**: [Date]  
**Maintained By**: [Team Name]

