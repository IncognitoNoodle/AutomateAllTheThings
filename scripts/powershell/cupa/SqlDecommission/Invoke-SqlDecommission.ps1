<#
.SYNOPSIS
    CUPA SQL Server decommission orchestrator.

.DESCRIPTION
    Production entry point for the SqlDecommission playbook.

    Project layout:
      config/              defaults + host list (CSV/XLSX)
      module/SqlDecom.*    PowerShell module (Public/ + Private/)
      docs/                process + architecture
      tests/               Pester stubs

.EXAMPLE
    .\Invoke-SqlDecommission.ps1 -RFCNumber '45012' -PlanOnly

.EXAMPLE
    .\Invoke-SqlDecommission.ps1 -RFCNumber '45012' -HostList '.\config\hosts.csv'

.EXAMPLE
    .\Invoke-SqlDecommission.ps1 -RFCNumber '45012' -HostList '\\share\Decom\Wave1.xlsx'
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

Import-Module (Join-Path $here 'module\SqlDecom.psd1') -Force

# Default host list from project config when -HostList omitted
if (-not $HostList) {
    $HostList = Join-Path $here 'config\hosts.csv'
}
else {
    # Resolve relative / legacy bare names only — never silently substitute
    # config\hosts.csv when the caller passed an explicit missing path.
    $originalHostList = $HostList
    if (-not (Test-Path -LiteralPath $HostList)) {
        $leaf = [System.IO.Path]::GetFileName($HostList)
        $isBareOrLegacyName = -not [System.IO.Path]::IsPathRooted($HostList) -or
            ($leaf -match '^(?i)(DecomHosts|hosts)\.csv$')

        $candidates = @()
        if (-not [System.IO.Path]::IsPathRooted($originalHostList)) {
            $candidates += (Join-Path $here $originalHostList)
            $candidates += (Join-Path $here "config\$leaf")
            $candidates += (Join-Path $here $leaf)
        }
        # Legacy inventory filename only
        if ($leaf -match '^(?i)DecomHosts\.csv$') {
            $candidates += (Join-Path $here 'config\hosts.csv')
        }

        $resolved = $null
        foreach ($candidate in ($candidates | Select-Object -Unique)) {
            if (Test-Path -LiteralPath $candidate) {
                $resolved = $candidate
                break
            }
        }

        if ($resolved) {
            Write-Host "[INFO] Resolved -HostList '$originalHostList' -> $resolved"
            $HostList = $resolved
        }
        elseif (-not $isBareOrLegacyName -or [System.IO.Path]::IsPathRooted($originalHostList)) {
            throw "Host list not found: $originalHostList"
        }
    }
}

if (-not (Test-Path -LiteralPath $HostList)) {
    throw "Host list not found: $HostList"
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
