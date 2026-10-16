<#
.SYNOPSIS
    Compatibility shim — forwards to sql-decommission/invoke-sql-decommission.ps1

.DESCRIPTION
    The playbook lives under sql-decommission/. This lowercase shim preserves
    older call sites that pointed at the cupa folder root.
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

$target = Join-Path $PSScriptRoot 'sql-decommission\invoke-sql-decommission.ps1'
if (-not (Test-Path -LiteralPath $target)) {
    throw "Moved entry point not found: $target"
}

& $target @PSBoundParameters
exit $LASTEXITCODE
