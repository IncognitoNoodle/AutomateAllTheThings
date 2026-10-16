@{
    RootModule        = 'SqlDecom.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'fa398924-aefb-420e-b653-82454779e4ee'
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
