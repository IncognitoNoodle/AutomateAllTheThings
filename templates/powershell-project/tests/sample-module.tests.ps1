#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'module\sample-module.psd1') -Force
}

Describe 'sample-module' {
    It 'exports Invoke-SampleAction' {
        (Get-Command -Module sample-module).Name | Should -Contain 'Invoke-SampleAction'
    }
}
