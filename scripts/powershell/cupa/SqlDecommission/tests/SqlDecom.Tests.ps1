#Requires -Modules Pester
<#
.SYNOPSIS
    Pester stubs for SqlDecom.

.DESCRIPTION
    Run on a Windows jump box with Pester 5+:

      Invoke-Pester -Path .\tests\SqlDecom.Tests.ps1
#>

BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $projectRoot 'module\SqlDecom.psd1') -Force
}

Describe 'SqlDecom module surface' {
    It 'exports the orchestrator commands' {
        $expected = @(
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
        $exported = (Get-Command -Module SqlDecom).Name
        foreach ($name in $expected) {
            $exported | Should -Contain $name
        }
    }

    It 'does not export private helper Invoke-DecomBackupWithFallback' {
        Get-Command Invoke-DecomBackupWithFallback -ErrorAction SilentlyContinue |
            Should -BeNullOrEmpty
    }
}

Describe 'config defaults' {
    It 'ships a hosts.csv next to defaults.ps1' {
        $hosts = Join-Path (Split-Path -Parent $PSScriptRoot) 'config\hosts.csv'
        Test-Path -LiteralPath $hosts | Should -BeTrue
    }
}
