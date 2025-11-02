/*
================================================================================
SCRIPT HEADER TEMPLATE - Enterprise-Grade SQL Script Documentation
================================================================================
Use this template as the header for all production SQL scripts.
Copy and customize sections as needed for your specific script.

================================================================================
METADATA & IDENTIFICATION
================================================================================
SCRIPT NAME:        [Descriptive Script Name]
SCRIPT ID:          [Optional: Internal tracking ID]
VERSION:            [Version number, e.g., 1.0.0]
CREATED DATE:       [YYYY-MM-DD]
LAST MODIFIED:      [YYYY-MM-DD]
AUTHOR:             [Author Name/Team]
MAINTAINED BY:       [Maintainer Name/Team]

================================================================================
PURPOSE & BUSINESS CONTEXT
================================================================================
PURPOSE:
    [One-line summary of what this script does]

BUSINESS APPLICATION:
    [2-3 sentences explaining the real-world business problem this solves.
     Include: When it's used, why it matters, what problem it prevents/resolves.
     Examples: "Used during application onboarding to ensure consistent database
     configuration." "Critical for meeting RPO/RTO requirements during disaster
     recovery scenarios."]

RELATED BUSINESS PROCESSES:
    [List related processes, e.g., "Database Provisioning", "Disaster Recovery",
     "Performance Optimization", "Compliance Auditing"]

================================================================================
PREREQUISITES & ENVIRONMENT
================================================================================
SQL SERVER VERSION:  SQL Server 2019 or higher / Azure SQL Database / Managed Instance
PERMISSIONS:        [Specific permissions required, e.g., "sysadmin", 
                     "VIEW SERVER STATE", "db_backupoperator"]
DEPENDENCIES:       [Other objects, jobs, or scripts required]
STORAGE REQUIREMENTS: [Disk space, backup space, etc. if applicable]
NETWORK REQUIREMENTS: [Network access, firewall rules, etc. if applicable]

PRE-EXECUTION CHECKLIST:
    [ ] Verified SQL Server version compatibility
    [ ] Confirmed required permissions are granted
    [ ] Tested in non-production environment
    [ ] Reviewed parameter values for accuracy
    [ ] Verified sufficient disk/storage space
    [ ] Scheduled during appropriate maintenance window (if applicable)
    [ ] Notified stakeholders (if production impact expected)

================================================================================
PARAMETERS & CONFIGURATION
================================================================================
CONFIGURATION SECTION LOCATION: [Line numbers where parameters are defined]

PARAMETER DOCUMENTATION:
    @ParameterName      - [Description] (REQUIRED/OPTIONAL)
                          Default: [value]
                          Valid values: [list if applicable]
                          Example: [example value]

USAGE EXAMPLES:
    -- Example 1: [Brief description]
    EXEC dbo.ProcedureName
        @Parameter1 = 'Value1',
        @Parameter2 = 'Value2';

    -- Example 2: [Brief description]
    EXEC dbo.ProcedureName @Parameter1 = 'Value1';

EXPECTED EXECUTION TIME:
    Small database (< 10 GB):    [Time estimate]
    Medium database (10-100 GB): [Time estimate]
    Large database (> 100 GB):   [Time estimate]
    Note: [Any factors affecting execution time]

================================================================================
OPERATIONAL IMPACT & SAFETY
================================================================================
PRODUCTION SAFETY:
    [ ] Safe to run during business hours
    [ ] Requires maintenance window
    [ ] Read-only operation (no data modification)
    [ ] Blocks operations (specify what)
    [ ] Can be interrupted/resumed
    [ ] Requires rollback plan

RESOURCE IMPACT:
    CPU Impact:        [Low/Medium/High] - [Brief explanation]
    Memory Impact:     [Low/Medium/High] - [Brief explanation]
    I/O Impact:        [Low/Medium/High] - [Brief explanation]
    Lock Impact:       [None/Minimal/Blocks reads/Blocks writes] - [Explanation]
    Duration:          [Estimated duration and factors affecting it]

ROLLBACK PROCEDURE:
    [If applicable, describe how to undo changes or restore state]

ERROR HANDLING:
    [Description of how errors are handled, logged, and reported]

================================================================================
EXPECTED OUTPUT & RESULTS
================================================================================
SUCCESS INDICATORS:
    [What output indicates successful execution]
    [Expected result sets, messages, or log entries]

FAILURE INDICATORS:
    [What indicates failure or issues]
    [Common error messages and their meanings]

OUTPUT INTERPRETATION:
    [How to interpret results]
    [What actions to take based on results]

REPORTING:
    [How results are logged/reported]
    [Where to find execution logs]
    [Email/alert notifications if configured]

================================================================================
INTEGRATION WITH INDUSTRY TOOLS
================================================================================
OLA HALLENGREN MAINTENANCE SOLUTION:
    [If applicable, explain how this relates to or integrates with Ola's tools]
    Related Component: [DatabaseBackup, IndexOptimize, IntegrityCheck, etc.]
    Integration Notes: [How to use together, when to use this vs. Ola's solution]

BRENT OZAR FIRST RESPONDER KIT:
    [If applicable, explain relationship to Brent Ozar's tools]
    Related Tool: [sp_Blitz, sp_BlitzCache, sp_BlitzIndex, etc.]
    When to Use: [When to use this script vs. Brent Ozar's tools]

CLOUD-SPECIFIC CONSIDERATIONS:
    Azure SQL Database:    [Differences, alternatives, or notes]
    Azure Managed Instance: [Differences, alternatives, or notes]
    Azure VM SQL Server:    [Differences, alternatives, or notes]

================================================================================
MONITORING & ALERTING
================================================================================
RECOMMENDED ALERTS:
    [What conditions should trigger alerts]
    [How to set up monitoring for this script]

PERFORMANCE BASELINE:
    [Expected performance metrics]
    [What deviations indicate issues]

LOG LOCATION:
    [Where execution logs are stored]
    [SQL Agent job history, custom log tables, file system, etc.]

================================================================================
TESTING & VALIDATION
================================================================================
TEST ENVIRONMENT VALIDATION:
    [Tested on: SQL Server version, database sizes, configurations]

VALIDATION QUERIES:
    -- Query to verify script execution success
    [SQL query to validate results]

    -- Query to check for issues after execution
    [SQL query to identify problems]

ACCEPTANCE CRITERIA:
    [ ] [Criterion 1]
    [ ] [Criterion 2]
    [ ] [Criterion 3]

================================================================================
MAINTENANCE & VERSION HISTORY
================================================================================
CHANGE LOG:
    Version 1.0.0 (YYYY-MM-DD): Initial release
    Version 1.1.0 (YYYY-MM-DD): [Change description]
    Version 1.2.0 (YYYY-MM-DD): [Change description]

KNOWN LIMITATIONS:
    [Any known limitations or constraints]

PLANNED ENHANCEMENTS:
    [Future improvements or features]

SUPPORT CONTACT:
    [Team email, Slack channel, or support process]

================================================================================
REFERENCES & DOCUMENTATION
================================================================================
MICROSOFT DOCUMENTATION:
    - [Title and URL]
    - [Title and URL]

BEST PRACTICES:
    - [Reference to industry best practices]
    - [White papers, blog posts, etc.]

RELATED SCRIPTS:
    - [Other scripts in this collection that relate]
    - [File paths or script names]

COMPLIANCE & AUDIT:
    [If applicable, compliance requirements this addresses]
    [Audit trail information]

================================================================================
LICENSE & COPYRIGHT
================================================================================
[Copyright notice if applicable]
[License information]

================================================================================
END OF HEADER
================================================================================

-- BEGIN SCRIPT EXECUTION SECTION BELOW THIS LINE
-- Do not modify header above without updating version and change log

