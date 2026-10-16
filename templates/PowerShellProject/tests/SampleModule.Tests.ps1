#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'module\SampleModule.psd1') -Force
}

Describe 'SampleModule' {
    It 'exports Invoke-SampleAction' {
        (Get-Command -Module SampleModule).Name | Should -Contain 'Invoke-SampleAction'
    }
}
