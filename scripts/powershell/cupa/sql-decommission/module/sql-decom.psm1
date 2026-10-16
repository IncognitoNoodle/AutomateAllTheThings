#Requires -Version 5.1
<#
.SYNOPSIS
    sql-decom module loader.

.DESCRIPTION
    Loads config, then private helpers, then public commands.
    Files/folders use lowercase-dash names; exported functions keep
    PowerShell approved-verb PascalCase (Invoke-*, Get-*, etc.).
#>

$script:SqlDecomModuleRoot  = $PSScriptRoot
$script:SqlDecomProjectRoot = Split-Path -Parent $PSScriptRoot
$script:SqlDecomConfigDir   = Join-Path $script:SqlDecomProjectRoot 'config'

# --- configuration (project-scoped defaults) ---
$configFile = Join-Path $script:SqlDecomConfigDir 'defaults.ps1'
if (-not (Test-Path -LiteralPath $configFile)) {
    throw "sql-decom config not found: $configFile"
}
. $configFile

# --- private helpers (not exported) ---
Get-ChildItem -Path (Join-Path $PSScriptRoot 'private') -Filter '*.ps1' -File |
    Sort-Object Name |
    ForEach-Object { . $_.FullName }

# --- public commands ---
$publicFiles = @(
    Get-ChildItem -Path (Join-Path $PSScriptRoot 'public') -Filter '*.ps1' -File |
        Sort-Object Name
)
foreach ($file in $publicFiles) {
    . $file.FullName
}

$exportNames = foreach ($file in $publicFiles) {
    Select-String -Path $file.FullName -Pattern '^function\s+([A-Za-z][\w-]*)' |
        ForEach-Object { $_.Matches.Groups[1].Value }
}

Export-ModuleMember -Function ($exportNames | Select-Object -Unique)
