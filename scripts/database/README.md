# SQL Server Database Administration Scripts

A comprehensive, production-ready collection of SQL Server DBA scripts demonstrating real-world expertise in database administration, performance tuning, and automation. This collection is designed for **SQL Database Administrator interviews** and **production use**, with focus on **Microsoft SQL Server** and **Azure cloud infrastructure**.

## 📋 Table of Contents

- [Overview](#overview)
- [Directory Structure](#directory-structure)
- [Script Categories](#script-categories)
- [Prerequisites](#prerequisites)
- [Usage Guidelines](#usage-guidelines)
- [Cloud Infrastructure Focus](#cloud-infrastructure-focus)
- [Industry-Standard Tools Integration](#industry-standard-tools-integration)
- [Interview Preparation](#interview-preparation)
- [Best Practices](#best-practices)
- [References](#references)

## Overview

This collection provides **production-ready, business-applied scripts** that showcase deep understanding of:

- **Database Reliability**: Data integrity, consistency, and disaster recovery
- **Performance Optimization**: Query tuning, index management, and resource optimization
- **Automation**: Maintenance tasks, monitoring, and proactive issue detection
- **Cloud Infrastructure**: Azure SQL Database, Managed Instance, and hybrid scenarios
- **Security & Compliance**: Auditing, least privilege, and compliance requirements

Each script includes:
- **Detailed documentation** with purpose and business application
- **Real-world context** explaining when and why to use it
- **Usage examples** with parameters
- **Expected output** descriptions
- **Safety considerations** and production warnings
- **References** to Microsoft documentation and best practices

## Directory Structure

```
scripts/database/
│
├── README.md                    # This file
│
├── mssql/                       # Microsoft SQL Server scripts
│   ├── administration/          # Configuration and setup
│   │   ├── 01_create_database_template.sql
│   │   ├── 02_create_user_least_privilege.sql
│   │   ├── 03_configure_instance_settings.sql
│   │   └── 04_audit_schema_changes.sql
│   │
│   ├── backup_restore/          # Disaster recovery
│   │   ├── 01_automated_backup_full_differential_log.sql
│   │   ├── 02_verify_backup_integrity.sql
│   │   └── 03_disaster_recovery_restore.sql
│   │
│   ├── performance/             # Performance tuning
│   │   ├── 01_index_fragmentation_analysis.sql
│   │   ├── 02_top_performing_queries_dmv.sql
│   │   └── 03_missing_index_detection.sql
│   │
│   ├── monitoring/              # Health checks and alerts
│   │   └── 01_daily_health_check.sql
│   │
│   ├── data_integrity/         # Corruption detection
│   │   └── 01_dbcc_checkdb_automation.sql
│   │
│   ├── high_availability/      # Always On and replication
│   │   └── 01_always_on_availability_group_monitoring.sql
│   │
│   └── cloud/                   # Azure-specific scripts
│       ├── 01_azure_sql_database_automatic_tuning.sql
│       └── 02_azure_backup_to_blob_storage.sql
│
└── (postgresql/ and mysql/ folders - optional, to be added)

resources/database/              # Documentation and playbooks
    ├── daily_dba_checklist.md
    └── runbooks/
        ├── tempdb_full_incident_response.md
        └── transaction_log_full.md
```

## Script Categories

### 1. Administration & Configuration

**Purpose**: Standardize database creation, user provisioning, and instance configuration.

**Scripts**:
- **`01_create_database_template.sql`**: Creates databases with production-ready settings following organizational standards.
- **`02_create_user_least_privilege.sql`**: Provisions users with appropriate permissions using least privilege principles.
- **`03_configure_instance_settings.sql`**: Configures critical instance-level settings (MAXDOP, Cost Threshold, TempDB).
- **`04_audit_schema_changes.sql`**: Sets up SQL Server Audit for compliance tracking.

**Business Application**: Used during application onboarding, ensuring consistent configuration and security compliance across all databases.

### 2. Backup, Restore & Disaster Recovery

**Purpose**: Automated backup strategies and disaster recovery procedures.

**Scripts**:
- **`01_automated_backup_full_differential_log.sql`**: Performs automated backups with date-based naming and verification.
- **`02_verify_backup_integrity.sql`**: Verifies backups and performs restore tests to ensure recoverability.
- **`03_disaster_recovery_restore.sql`**: Step-by-step restoration procedures for disaster recovery scenarios.

**Business Application**: Critical for meeting RPO/RTO requirements and ensuring data recovery readiness during outages or ransomware events.

### 3. Performance Tuning & Optimization

**Purpose**: Identify and resolve performance bottlenecks.

**Scripts**:
- **`01_index_fragmentation_analysis.sql`**: Analyzes index fragmentation and generates maintenance recommendations.
- **`02_top_performing_queries_dmv.sql`**: Identifies top resource-consuming queries using DMVs.
- **`03_missing_index_detection.sql`**: Detects missing index opportunities based on workload patterns.

**Business Application**: Used to troubleshoot slow queries in production, reduce costly downtime, and optimize resource utilization.

**Related Tools**: 
- **Brent Ozar's First Responder Kit**: `sp_BlitzCache`, `sp_BlitzIndex`
- **Ola Hallengren's Maintenance Solution**: `IndexOptimize` for automated index maintenance

### 4. Monitoring & Maintenance

**Purpose**: Proactive health monitoring and automated maintenance.

**Scripts**:
- **`01_daily_health_check.sql`**: Comprehensive daily health checks (CPU, memory, I/O, blocking, failed jobs).

**Business Application**: Proactively detects issues before users are affected and supports SLA monitoring.

**Related Tools**:
- **Brent Ozar's `sp_Blitz`**: Overall health check
- **Ola Hallengren's Maintenance Solution**: Automated maintenance jobs

### 5. Data Integrity & Reliability

**Purpose**: Ensure database consistency and prevent corruption.

**Scripts**:
- **`01_dbcc_checkdb_automation.sql`**: Automates DBCC CHECKDB execution with comprehensive reporting.

**Business Application**: Prevents data corruption from going unnoticed and ensures compliance audits pass smoothly.

**Related Tools**: 
- **Ola Hallengren's `IntegrityCheck`**: Production-grade DBCC automation (recommended)

### 6. High Availability & Replication

**Purpose**: Monitor and manage Always On Availability Groups.

**Scripts**:
- **`01_always_on_availability_group_monitoring.sql`**: Monitors AG health, synchronization status, and failover readiness.

**Business Application**: Ensures uptime and fault tolerance across data centers, critical for business continuity.

### 7. Cloud Infrastructure

**Purpose**: Azure-specific scripts for cloud-native database management.

**Scripts**:
- **`01_azure_sql_database_automatic_tuning.sql`**: Configures and monitors Azure SQL Database Automatic Tuning.
- **`02_azure_backup_to_blob_storage.sql`**: Configures backups to Azure Blob Storage for Managed Instance.

**Business Application**: Leverages Azure's AI-powered automation and cloud-native backup strategies.

## Prerequisites

### SQL Server Requirements
- **SQL Server 2019 or higher** (or Azure SQL Managed Instance)
- Appropriate permissions (varies by script - see individual script documentation)
- SQL Server Management Studio (SSMS) or Azure Data Studio

### Permissions
Most scripts require:
- `VIEW SERVER STATE` - For DMV queries
- `VIEW DATABASE STATE` - For database-level DMVs
- `sysadmin` or `db_owner` - For administrative operations

Check individual scripts for specific permission requirements.

### Tools (Recommended)
1. **Ola Hallengren's Maintenance Solution**
   - Download: https://ola.hallengren.com/downloads.html
   - Provides: `DatabaseBackup`, `IndexOptimize`, `IntegrityCheck`
   - **Recommended for production use** over standalone scripts

2. **Brent Ozar's First Responder Kit**
   - Download: https://www.brentozar.com/first-aid/
   - Provides: `sp_Blitz`, `sp_BlitzCache`, `sp_BlitzIndex`, `sp_BlitzWait`
   - **Recommended for troubleshooting and analysis**

## Usage Guidelines

### ⚠️ Safety First

**Before running any script in production:**

1. **Read the entire script** - Understand what it does
2. **Test in non-production** - Always test first
3. **Review parameters** - Adjust for your environment
4. **Check prerequisites** - Ensure requirements are met
5. **Backup first** - Have a recovery plan
6. **Monitor execution** - Watch for errors or unexpected behavior

### Running Scripts Safely

```sql
-- Example: Running a script with custom parameters
-- 1. Review the script header for configuration section
-- 2. Modify variables at the top of the script
-- 3. Execute in a query window
-- 4. Review output and warnings

-- Example: Daily Health Check
USE [master];
GO

-- Review and modify configuration section at top of script
-- Then execute
EXEC dbo.usp_DailyHealthCheck
    @CheckCPU = 1,
    @CheckMemory = 1,
    @CheckBlocking = 1;
```

### Script Execution Patterns

**Standalone Execution**: Most scripts can be run directly in SSMS.

**SQL Agent Jobs**: Scripts are designed to be integrated into SQL Agent jobs:
```sql
-- Example SQL Agent Job step
EXEC dbo.usp_AutomatedBackup
    @DatabaseName = 'ProductionDB',
    @BackupType = 'FULL',
    @BackupPath = 'D:\SQLBackups\';
```

**Azure Automation**: For cloud resources, use Azure Automation runbooks.

## Cloud Infrastructure Focus

This collection emphasizes **cloud-native database administration** with specific focus on:

### Azure SQL Database
- **Automatic Tuning**: AI-powered performance optimization
- **Query Performance Insights**: Built-in performance monitoring
- **Automatic Backups**: Point-in-time restore (PITR) and long-term retention
- **Scaling**: DTU/vCore-based scaling strategies

### Azure SQL Managed Instance
- **Hybrid Cloud**: Same as on-premises SQL Server, but in the cloud
- **Always On AGs**: Business Critical tier support
- **SQL Agent**: Available for automation
- **Ola Hallengren**: Full compatibility with maintenance solution

### Azure VM SQL Server
- **IaaS Pattern**: Full control, same as on-premises
- **Best of Both**: Cloud benefits + on-premises flexibility
- **All Scripts Apply**: Same tools and techniques

### Cloud Best Practices

1. **Use Azure-native Tools When Available**
   - Automatic Tuning for Azure SQL Database
   - Azure Monitor for metrics and alerts
   - Query Performance Insights for analysis

2. **Hybrid Approach**
   - Ola Hallengren's solution for Managed Instance
   - Brent Ozar's tools for troubleshooting
   - Azure Automation for cloud-native scheduling

3. **Backup Strategy**
   - Azure SQL Database: Automatic PITR + long-term retention
   - Managed Instance: Ola's solution + URL backups to Blob Storage
   - VM SQL Server: Traditional backups + Azure Blob Storage

## Industry-Standard Tools Integration

This collection references and integrates with industry-standard DBA tools:

### Ola Hallengren's Maintenance Solution

**Why It's Recommended**: Production-tested, widely adopted, comprehensive.

**Components**:
- **`DatabaseBackup`**: Intelligent backup automation with AG awareness
- **`IndexOptimize`**: Fragmentation analysis and maintenance
- **`IntegrityCheck`**: DBCC CHECKDB automation
- **`CommandExecute`**: Job execution with logging

**Installation**: Run `MaintenanceSolution.sql` in your SQL Server instance.

**Usage Examples** (referenced in scripts):
```sql
-- Index maintenance
EXEC master.dbo.IndexOptimize
    @Databases = 'ALL_DATABASES',
    @FragmentationLow = 'REORGANIZE',
    @FragmentationHigh = 'REBUILD',
    @UpdateStatistics = 'ALL';

-- Backup automation
EXEC master.dbo.DatabaseBackup
    @Databases = 'ALL_DATABASES',
    @BackupType = 'FULL',
    @Verify = 'Y',
    @CleanupTime = 168; -- 7 days
```

### Brent Ozar's First Responder Kit

**Why It's Recommended**: Excellent for troubleshooting and quick health checks.

**Key Procedures**:
- **`sp_Blitz`**: Overall health check with prioritized findings
- **`sp_BlitzCache`**: Worst performing queries
- **`sp_BlitzIndex`**: Comprehensive index analysis
- **`sp_BlitzWait`**: Wait statistics analysis
- **`sp_BlitzLock`**: Deadlock and blocking analysis

**Installation**: Download and run setup scripts from https://www.brentozar.com/first-aid/

**Usage** (referenced in scripts):
```sql
-- Overall health check
EXEC dbo.sp_Blitz @CheckUserDatabaseObjects = 1;

-- Query performance
EXEC dbo.sp_BlitzCache @Top = 20, @SortOrder = 'cpu';

-- Index analysis
EXEC dbo.sp_BlitzIndex @DatabaseName = 'YourDatabase';
```

## Interview Preparation

### Understanding Scripts for Interviews

When discussing these scripts in interviews, be prepared to explain:

1. **Business Context**: Why this script solves a real business problem
2. **Technical Details**: How the script works internally
3. **Alternatives**: Other approaches and trade-offs
4. **Production Considerations**: Safety, testing, monitoring

### Common Interview Questions

**Q: Explain how you would optimize a slow database.**

**A**: I would:
1. Run `02_top_performing_queries_dmv.sql` to identify problem queries
2. Use `03_missing_index_detection.sql` to find index opportunities
3. Run `01_index_fragmentation_analysis.sql` to check fragmentation
4. Use Brent Ozar's `sp_BlitzCache` and `sp_BlitzIndex` for comprehensive analysis
5. Review execution plans and statistics
6. Test optimizations in non-production

**Q: How do you ensure backup recoverability?**

**A**: I use a multi-layered approach:
1. Automated backups with `01_automated_backup_full_differential_log.sql`
2. Regular verification with `02_verify_backup_integrity.sql` including restore tests
3. Ola Hallengren's `DatabaseBackup` for production-grade automation
4. Documented disaster recovery procedures in `03_disaster_recovery_restore.sql`
5. Monitor backup job success in daily health checks

**Q: How do you handle cloud vs. on-premises?**

**A**: I adapt tools based on platform:
- **Azure SQL Database**: Use Automatic Tuning, Query Performance Insights, Azure Monitor
- **Azure Managed Instance**: Ola's solution + Brent Ozar's tools (same as on-premises)
- **On-premises/VM**: Full Ola + Brent Ozar implementation
- Scripts in this collection handle all scenarios with cloud-specific notes

## Best Practices

### Script Usage

1. **Always Test First**: Never run production scripts without testing
2. **Review Parameters**: Customize scripts for your environment
3. **Monitor Execution**: Watch for errors and performance impact
4. **Document Changes**: Track what scripts you run and when
5. **Version Control**: Keep scripts in source control

### Production Deployment

1. **Schedule Appropriately**: Run maintenance during off-peak hours
2. **Set Up Alerts**: Monitor script execution success/failure
3. **Review Output**: Regularly review script outputs for trends
4. **Update Regularly**: Keep scripts updated with latest best practices

### Integration with Tools

1. **Use Ola's Solution for Production**: More robust than standalone scripts
2. **Use Brent Ozar's Tools for Analysis**: Excellent for troubleshooting
3. **Combine Approaches**: Use this collection for specific scenarios, tools for automation
4. **Cloud-Native When Available**: Prefer Azure-native features where applicable

## Documentation References

### Playbooks and Checklists

Located in `resources/database/`:
- **`daily_dba_checklist.md`**: Daily operational checklist
- **`runbooks/tempdb_full_incident_response.md`**: TempDB incident response
- **`runbooks/transaction_log_full.md`**: Transaction log incident response

### Microsoft Documentation

Each script includes references to relevant Microsoft documentation:
- SQL Server documentation
- Azure SQL Database documentation
- Best practices guides

### External Resources

- **Ola Hallengren**: https://ola.hallengren.com/
- **Brent Ozar**: https://www.brentozar.com/
- **SQLskills**: https://www.sqlskills.com/
- **Azure SQL Documentation**: https://docs.microsoft.com/azure/azure-sql/

## Contributing

When adding new scripts:

1. Follow the existing script structure and documentation format
2. Include business application context
3. Reference cloud considerations
4. Integrate with industry-standard tools (Ola, Brent Ozar)
5. Test thoroughly before adding
6. Document prerequisites and parameters clearly

## License

See main repository LICENSE file.

## Support

For questions or issues:
- Review script documentation
- Check references and related tools
- Consult Microsoft documentation
- Review playbooks in `resources/database/`

---

**Collection Maintained By**: [Your Name/Team]  
**Last Updated**: [Date]  
**SQL Server Compatibility**: 2019+ and Azure SQL Database/Managed Instance

---

**Remember**: These scripts are tools to support your DBA expertise. Always understand what a script does before running it in production, and test thoroughly. When in doubt, use industry-standard tools like Ola Hallengren's Maintenance Solution for production automation.

