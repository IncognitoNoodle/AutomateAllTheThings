[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Name
)

Import-Module (Join-Path $PSScriptRoot 'module\SampleModule.psd1') -Force
Invoke-SampleAction -Name $Name
