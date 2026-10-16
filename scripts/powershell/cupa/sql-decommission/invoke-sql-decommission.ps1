<#
.SYNOPSIS
    CUPA SQL Server decommission orchestrator.

.DESCRIPTION
    Production entry point for the sql-decommission playbook.

    Project layout:
      config/     defaults + host list (CSV/XLSX)
      module/     sql-decom PowerShell module (public/ + private/)
      docs/       process + architecture
      tests/      Pester stubs

.EXAMPLE
    .\invoke-sql-decommission.ps1 -RFCNumber '45012' -PlanOnly

.EXAMPLE
    .\invoke-sql-decommission.ps1 -RFCNumber '45012' -HostList '.\config\hosts.csv'

.EXAMPLE
    .\invoke-sql-decommission.ps1 -RFCNumber '45012' -HostList '\\share\Decom\Wave1.xlsx'
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_-]+$')]
    [string]$RFCNumber,

    # CSV or XLSX with ServerName + ExpectedIP (filename or full path)
    [Parameter(Mandatory = $false)]
    [string]$HostList,

    [string[]]$AvailabilityGroup,
    [switch]$AllAvailabilityGroups,
    [string[]]$ExcludeDatabase,
    [switch]$PlanOnly,
    [switch]$SkipIpValidation,
    [switch]$RequireHostInventory,
    [switch]$ForceIpMismatch
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

Import-Module (Join-Path $here 'module\sql-decom.psd1') -Force

# Default host list from project config when -HostList omitted
if (-not $HostList) {
    $HostList = Join-Path $here 'config\hosts.csv'
}

# Resolve relative / legacy paths (pre-refactor Common\DecomHosts.csv names)
if (-not (Test-Path -LiteralPath $HostList)) {
    $leaf = [System.IO.Path]::GetFileName($HostList)
    # Old inventory filename -> current config\hosts.csv
    if ($leaf -match '^(?i)DecomHosts\.csv$') {
        $leaf = 'hosts.csv'
    }

    $candidates = @(
        (Join-Path $here $HostList)
        (Join-Path $here "config\$leaf")
        (Join-Path $here $leaf)
        (Join-Path $here "config\hosts.csv")
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            Write-Host "[INFO] Resolved -HostList '$HostList' -> $candidate"
            $HostList = $candidate
            break
        }
    }
}

$exitCode = 0

try {
    $session = Initialize-DecomSession `
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
    elseif ($session.PlanOnly) {
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
    Set-DecomHadFailures -Value $true
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
