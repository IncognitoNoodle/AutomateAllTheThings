<#
.SYNOPSIS
    CUPA SQL Server decommission orchestrator (standalone + Availability Group).

.DESCRIPTION
    Thin entry point. Shared helpers and branch pipelines live under Common\:

      Common\Config.ps1                  Environment defaults
      Common\Decom.Common.ps1            Session, backup/rename/info helpers
      Common\Decom.Resolve.ps1           Classify targets (standalone vs AG)
      Common\Decom.Standalone.ps1        Branch A - standalone pipeline
      Common\Decom.AvailabilityGroup.ps1 Branch B - AG node pipeline
      Common\Decom.Inventory.ps1         Mark processed standalone servers inactive

    Flow:
      1. Initialize session / dbatools
      2. Resolve each target -> standalone list OR AG (with discovered replicas)
      3. Branch A: process standalone servers
      4. Branch B: process each valid AG across its replica nodes
      5. Inventory update (standalone successes only)
      6. Summary

.EXAMPLE
    .\Decommission-SqlServer.ps1 -RFCNumber '12345' -Targets 'SQLBOX01'

.EXAMPLE
    .\Decommission-SqlServer.ps1 -RFCNumber '12345' -Targets 'AGNODE1','SQLBOX02' -WhatIf

.NOTES
    See Decommission-SqlServer.md for the full process walkthrough.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_-]+$')]   # blocks bracket/path-breaking chars
    [string]$RFCNumber,

    [Parameter(Mandatory = $true)]
    [string[]]$Targets
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

. (Join-Path $here 'Common\Decom.Common.ps1')
. (Join-Path $here 'Common\Decom.Resolve.ps1')
. (Join-Path $here 'Common\Decom.Standalone.ps1')
. (Join-Path $here 'Common\Decom.AvailabilityGroup.ps1')
. (Join-Path $here 'Common\Decom.Inventory.ps1')

try {
    Initialize-DecomSession -RFCNumber $RFCNumber -Targets $Targets

    # Classify inputs: each target becomes either standalone or an AG unit
    # (AG resolution expands to all discovered replica nodes).
    $null = Resolve-DecomTargets

    # ----- Pipeline branch: standalone vs AG -----
    Invoke-DecomStandalonePipeline
    Invoke-DecomAvailabilityGroupPipeline

    Update-DecomInventory
    Write-DecomSummary
}
finally {
    if (Get-Command Complete-DecomSession -ErrorAction SilentlyContinue) {
        Complete-DecomSession
    }
}
