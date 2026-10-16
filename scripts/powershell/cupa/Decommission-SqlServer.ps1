<#
.SYNOPSIS
    CUPA SQL Server decommission orchestrator (standalone + Availability Group).

.DESCRIPTION
    Thin entry point. Shared helpers and branch pipelines live under Common\:

      Common\Config.ps1                  Environment defaults
      Common\DecomHosts.csv              Hostname <-> ExpectedIP inventory
      Common\Decom.Common.ps1            Session, backup/rename/AG-config helpers
      Common\Decom.Resolve.ps1           Classify targets (standalone vs AG)
      Common\Decom.Preflight.ps1         IP validation, SQL checks, plan file
      Common\Decom.Standalone.ps1        Branch A - two-phase standalone pipeline
      Common\Decom.AvailabilityGroup.ps1 Branch B - two-phase AG pipeline
      Common\Decom.Inventory.ps1         Mark processed standalone servers inactive

    Flow:
      1. Initialize session / dbatools / host inventory
      2. Resolve each target -> standalone list OR AG (with discovered replicas)
      3. Preflight: hostname/IP validation, SQL connect, write plan JSON
      4. Stop on preflight hard failures (unless overridden)
      5. Branch A / Branch B (skipped when -PlanOnly)
      6. Inventory update (standalone successes only)
      7. Summary + non-zero exit code on failures

.EXAMPLE
    # Validate plan + IPs only
    .\Decommission-SqlServer.ps1 -RFCNumber '12345' -Targets 'sresmsq400' -PlanOnly

.EXAMPLE
    .\Decommission-SqlServer.ps1 -RFCNumber '12345' -Targets 'srsclsq405','suinfsq018'

.EXAMPLE
    .\Decommission-SqlServer.ps1 -RFCNumber '12345' -Targets 'AGNODE1' -AvailabilityGroup 'AG_APP' -WhatIf

.NOTES
    See Decommission-SqlServer.md for the full process walkthrough.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_-]+$')]
    [string]$RFCNumber,

    [Parameter(Mandatory = $true)]
    [string[]]$Targets,

    # When an instance has multiple AGs, select which one(s) to process
    [string[]]$AvailabilityGroup,

    # Process every AG on the instance when more than one exists
    [switch]$AllAvailabilityGroups,

    # Override default Common\DecomHosts.csv
    [string]$HostsFile,

    # Additional DB names to skip (merged with Config excludes)
    [string[]]$ExcludeDatabase,

    # Resolve + preflight + plan only; no backup/rename/inventory
    [switch]$PlanOnly,

    # Do not validate hostname vs ExpectedIP
    [switch]$SkipIpValidation,

    # Fail preflight when a target host is missing from DecomHosts.csv
    [switch]$RequireHostInventory,

    # Continue even when DNS IP does not match ExpectedIP (dangerous)
    [switch]$ForceIpMismatch
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

. (Join-Path $here 'Common\Decom.Common.ps1')
. (Join-Path $here 'Common\Decom.Resolve.ps1')
. (Join-Path $here 'Common\Decom.Preflight.ps1')
. (Join-Path $here 'Common\Decom.Standalone.ps1')
. (Join-Path $here 'Common\Decom.AvailabilityGroup.ps1')
. (Join-Path $here 'Common\Decom.Inventory.ps1')

$exitCode = 0

try {
    Initialize-DecomSession `
        -RFCNumber $RFCNumber `
        -Targets $Targets `
        -AvailabilityGroup $AvailabilityGroup `
        -AllAvailabilityGroups:$AllAvailabilityGroups `
        -HostsFile $HostsFile `
        -ExcludeDatabase $ExcludeDatabase `
        -PlanOnly:$PlanOnly `
        -SkipIpValidation:$SkipIpValidation `
        -RequireHostInventory:$RequireHostInventory `
        -ForceIpMismatch:$ForceIpMismatch

    $null = Resolve-DecomTargets

    $preflight = Invoke-DecomPreflight
    if (-not $preflight.Ok) {
        Write-Warning '[ABORT] Preflight hard failures detected - refusing to mutate any databases.'
        Write-DecomSummary
        $exitCode = Get-DecomExitCode
    }
    elseif ($script:DecomPlanOnly) {
        Write-Host "`n[INFO] PlanOnly complete - review the plan/IP results, then re-run without -PlanOnly." -ForegroundColor Yellow
        Write-DecomSummary
        $exitCode = Get-DecomExitCode
    }
    else {
        # ----- Pipeline branch: standalone vs AG -----
        Invoke-DecomStandalonePipeline
        Invoke-DecomAvailabilityGroupPipeline

        Update-DecomInventory
        Write-DecomSummary
        $exitCode = Get-DecomExitCode
    }
}
catch {
    Write-Warning "[FATAL] $($_.Exception.Message)"
    $script:DecomHadFailures = $true
    try { Write-DecomSummary } catch { }
    $exitCode = 1
}
finally {
    if (Get-Command Complete-DecomSession -ErrorAction SilentlyContinue) {
        Complete-DecomSession
    }
}

if ($exitCode -ne 0) {
    Write-Host "[EXIT] $exitCode" -ForegroundColor Red
}
exit $exitCode
