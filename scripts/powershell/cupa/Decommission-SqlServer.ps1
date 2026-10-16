<#
.SYNOPSIS
    CUPA SQL Server decommission orchestrator (standalone + Availability Group).

.DESCRIPTION
    Thin entry point. Shared helpers and branch pipelines live under Common\:

      Common\Config.ps1                  Environment defaults
      Common\DecomHosts.csv              Default host list (CSV)
      Common\Decom.Common.ps1            Session, backup/rename/AG-config helpers
      Common\Decom.Resolve.ps1           Classify hosts (standalone vs AG)
      Common\Decom.Preflight.ps1         IP validation, SQL checks, plan file
      Common\Decom.Standalone.ps1        Branch A - two-phase standalone pipeline
      Common\Decom.AvailabilityGroup.ps1 Branch B - two-phase AG pipeline
      Common\Decom.Inventory.ps1         Mark processed standalone servers inactive

    Pass -HostList with a CSV or XLSX path. Every ServerName row in that file is processed.
    There is no separate -Targets parameter.

.EXAMPLE
    .\Decommission-SqlServer.ps1 -RFCNumber '12345' -PlanOnly

.EXAMPLE
    .\Decommission-SqlServer.ps1 -RFCNumber '12345' -HostList '.\Common\DecomHosts.csv'

.EXAMPLE
    .\Decommission-SqlServer.ps1 -RFCNumber '12345' -HostList '\\share\Decom\Wave1.xlsx'

.NOTES
    See Decommission-SqlServer.md for the full process walkthrough.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_-]+$')]
    [string]$RFCNumber,

    # CSV or XLSX with ServerName + ExpectedIP columns (filename or full path)
    [Parameter(Mandatory = $false)]
    [string]$HostList = (Join-Path $PSScriptRoot 'Common\DecomHosts.csv'),

    # When an instance has multiple AGs, select which one(s) to process
    [string[]]$AvailabilityGroup,

    # Process every AG on the instance when more than one exists
    [switch]$AllAvailabilityGroups,

    # Additional DB names to skip (merged with Config excludes)
    [string[]]$ExcludeDatabase,

    # Resolve + preflight + plan only; no backup/rename/inventory
    [switch]$PlanOnly,

    # Do not validate hostname vs ExpectedIP
    [switch]$SkipIpValidation,

    # Fail preflight when a discovered AG replica is missing from the host list
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

# Allow bare filenames relative to the script folder or Common\
if (-not [System.IO.Path]::IsPathRooted($HostList) -and -not (Test-Path -LiteralPath $HostList)) {
    $candidateCommon = Join-Path $here "Common\$HostList"
    $candidateHere   = Join-Path $here $HostList
    if (Test-Path -LiteralPath $candidateCommon) {
        $HostList = $candidateCommon
    }
    elseif (Test-Path -LiteralPath $candidateHere) {
        $HostList = $candidateHere
    }
}

$exitCode = 0

try {
    Initialize-DecomSession `
        -RFCNumber $RFCNumber `
        -HostList $HostList `
        -AvailabilityGroup $AvailabilityGroup `
        -AllAvailabilityGroups:$AllAvailabilityGroups `
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
