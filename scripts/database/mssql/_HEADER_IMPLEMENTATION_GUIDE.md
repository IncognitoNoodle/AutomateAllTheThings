# SQL Script Header Implementation Guide

## Overview

All SQL scripts in this collection now use a standardized enterprise-grade header template that follows documentation standards expected by senior DBAs and database architects in production environments.

## Header Template Location

**Template File**: `scripts/database/mssql/_TEMPLATE_SQL_SCRIPT_HEADER.sql`

**Reference Implementation**: See updated scripts:
- `administration/01_create_database_template.sql` (Fully updated)
- `performance/01_index_fragmentation_analysis.sql` (Fully updated)

## Header Structure

The standardized header includes these sections:

### 1. Metadata & Identification
- Script name, version, dates
- Author and maintainer information
- Version control tracking

### 2. Purpose & Business Context
- Clear purpose statement
- Real-world business application
- Related business processes
- **Key**: Addresses "Why does this matter?" not just "What does it do?"

### 3. Prerequisites & Environment
- SQL Server version requirements
- Permissions needed
- Dependencies
- Pre-execution checklist

### 4. Parameters & Configuration
- Detailed parameter documentation
- Default values
- Valid ranges
- Usage examples
- Expected execution time

### 5. Operational Impact & Safety
- Production safety checklist
- Resource impact assessment
- Rollback procedures
- Error handling approach

### 6. Expected Output & Results
- Success indicators
- Failure indicators
- Output interpretation
- Reporting mechanisms

### 7. Integration with Industry Tools
- **Ola Hallengren's Maintenance Solution** integration
- **Brent Ozar's First Responder Kit** integration
- Cloud-specific considerations
- **Key**: Always explain when to use this script vs. industry-standard tools

### 8. Monitoring & Alerting
- Recommended alerts
- Performance baselines
- Log locations

### 9. Testing & Validation
- Test environment details
- Validation queries
- Acceptance criteria

### 10. Maintenance & Version History
- Change log
- Known limitations
- Planned enhancements
- Support contact

### 11. References & Documentation
- Microsoft documentation links
- Best practices references
- Related scripts
- Compliance/audit notes

## Key Principles

### Real-World Business Context
Every script must explain:
- **When** it's used (scenario)
- **Why** it's needed (business problem)
- **What** problem it solves (value)

Example:
❌ Bad: "Backs up a database"
✅ Good: "Critical for meeting RPO/RTO requirements. Used during disaster recovery scenarios to ensure data recovery readiness during outages or ransomware events."

### Industry Tool Integration
Always reference:
- **Ola Hallengren**: When to use this script vs. Ola's solution
- **Brent Ozar**: When to use this script vs. Brent's tools
- **Clear guidance**: Production should typically use industry-standard tools

### Cloud-Native Focus
Include cloud considerations:
- Azure SQL Database differences
- Azure Managed Instance compatibility
- Azure VM SQL Server notes
- Cloud-native alternatives when available

### Production Safety
Clearly indicate:
- Safe for business hours?
- Requires maintenance window?
- Read-only or modifies data?
- Can be interrupted?
- Rollback available?

## Implementation Checklist

When updating a script header:

- [ ] Replace basic header with standardized template
- [ ] Fill in all metadata sections
- [ ] Add real-world business context (not theoretical)
- [ ] Document all parameters with examples
- [ ] Include Ola Hallengren integration notes
- [ ] Include Brent Ozar integration notes
- [ ] Add cloud-specific considerations
- [ ] Document production safety clearly
- [ ] Include validation queries
- [ ] Add references to Microsoft docs
- [ ] Link to related scripts in collection

## Remaining Scripts to Update

### Administration Scripts
- [x] `01_create_database_template.sql` - Updated
- [ ] `02_create_user_least_privilege.sql`
- [ ] `03_configure_instance_settings.sql`
- [ ] `04_audit_schema_changes.sql`

### Backup/Restore Scripts
- [ ] `01_automated_backup_full_differential_log.sql`
- [ ] `02_verify_backup_integrity.sql`
- [ ] `03_disaster_recovery_restore.sql`

### Performance Scripts
- [x] `01_index_fragmentation_analysis.sql` - Updated
- [ ] `02_top_performing_queries_dmv.sql`
- [ ] `03_missing_index_detection.sql`

### Monitoring Scripts
- [ ] `01_daily_health_check.sql`

### Data Integrity Scripts
- [ ] `01_dbcc_checkdb_automation.sql`

### High Availability Scripts
- [ ] `01_always_on_availability_group_monitoring.sql`

### Cloud Scripts
- [ ] `01_azure_sql_database_automatic_tuning.sql`
- [ ] `02_azure_backup_to_blob_storage.sql`

## Best Practices for Header Content

### Business Application Section
**DO**:
- Describe real scenarios: "Used during application onboarding..."
- Explain business impact: "Critical for meeting SLA requirements..."
- Connect to operations: "Prevents incidents before users are affected..."

**DON'T**:
- Just describe functionality: "Backs up databases"
- Use theoretical examples: "Demonstrates backup concepts"
- Skip business context

### Tool Integration Section
**DO**:
- State clearly: "For production, use Ola's solution"
- Explain when this script is appropriate: "Use for analysis/troubleshooting"
- Provide usage examples for both tools

**DON'T**:
- Imply this script replaces industry tools
- Skip integration guidance
- Claim this is the only way to accomplish the task

### Parameter Documentation
**DO**:
- Provide examples for every parameter
- Include valid ranges/values
- Explain defaults and rationale
- Reference best practices (e.g., "Per Brent Ozar guidance...")

**DON'T**:
- Just list parameter names
- Skip examples
- Assume readers know best practices

### Cloud Considerations
**DO**:
- List differences for each Azure platform
- Mention alternatives when available
- Note compatibility

**DON'T**:
- Skip cloud section
- Assume on-premises only
- Ignore Azure-native features

## Quality Assurance

Before considering a script header complete:

1. **Readability**: Can a new DBA understand the script's purpose?
2. **Business Value**: Is the real-world application clear?
3. **Safety**: Are production risks clearly identified?
4. **Integration**: Is relationship to industry tools explained?
5. **Completeness**: Are all template sections filled?
6. **Accuracy**: Do examples and parameters match the script?

## Example: Good vs. Bad Header

### ❌ Bad (Basic)
```
/*
SCRIPT: Backup Database
PURPOSE: Backs up a database
USAGE: Run this script
*/
```

### ✅ Good (Enterprise-Grade)
```
/*
================================================================================
METADATA & IDENTIFICATION
================================================================================
SCRIPT NAME:        Automated Backup Script (Full, Differential, Transaction Log)
VERSION:            1.0.0
CREATED DATE:       2024-01-01
AUTHOR:             DBA Team

================================================================================
PURPOSE & BUSINESS CONTEXT
================================================================================
PURPOSE:
    Performs automated database backups with date-based naming convention.

BUSINESS APPLICATION:
    Critical for meeting RPO (Recovery Point Objective) and RTO (Recovery
    Time Objective) requirements. Used in SQL Agent jobs for scheduled
    backups. Ensures consistent backup naming for automated restore processes
    and backup retention policies. Addresses real-world need: "Can we restore
    to last night's backup?" Answer: Only if backups ran successfully and
    are verified.

RELATED BUSINESS PROCESSES:
    - Disaster Recovery Planning
    - Compliance and Audit Requirements
    - Business Continuity

... [continues with all sections]
```

## Notes for Interview Preparation

When discussing these scripts:
1. **Emphasize real-world context**: "This solves X business problem..."
2. **Acknowledge industry tools**: "For production, I'd use Ola's solution, but this demonstrates..."
3. **Show cloud expertise**: "In Azure, we'd use Automatic Tuning instead..."
4. **Safety first**: "Before running, I'd verify permissions and test in non-production..."

---

**Last Updated**: 2024-01-01  
**Template Version**: 1.0.0

