<#
.SYNOPSIS
    Compatibility shim — forwards to SqlDecommission\Invoke-SqlDecommission.ps1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_-]+$')]
    [string]$RFCNumber,

    [string]$HostList,
    [string[]]$AvailabilityGroup,
    [switch]$AllAvailabilityGroups,
    [string[]]$ExcludeDatabase,
    [switch]$PlanOnly,
    [switch]$SkipIpValidation,
    [switch]$RequireHostInventory,
    [switch]$ForceIpMismatch
)

$target = Join-Path $PSScriptRoot 'SqlDecommission\Invoke-SqlDecommission.ps1'
if (-not (Test-Path -LiteralPath $target)) {
    throw "Entry point not found: $target"
}

& $target @PSBoundParameters
exit $LASTEXITCODE
