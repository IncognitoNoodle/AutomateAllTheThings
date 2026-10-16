@{
    RootModule        = 'SqlDecom.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a3c8e2f1-9b4d-4e7a-8c21-decom001cupa'
    Author            = 'CUPA DBA Automation'
    CompanyName       = 'CUPA'
    Description       = 'SQL Server decommission playbook module (standalone + Availability Group).'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Initialize-DecomSession'
        'Resolve-DecomTargets'
        'Invoke-DecomPreflight'
        'Invoke-DecomStandalonePipeline'
        'Invoke-DecomAvailabilityGroupPipeline'
        'Update-DecomInventory'
        'Write-DecomSummary'
        'Complete-DecomSession'
        'Get-DecomExitCode'
        'Set-DecomHadFailures'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags = @('SQL', 'Decommission', 'AvailabilityGroup', 'CUPA')
        }
    }
}
