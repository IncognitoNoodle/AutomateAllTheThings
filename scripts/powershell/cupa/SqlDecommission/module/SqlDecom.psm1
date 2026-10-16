#Requires -Version 5.1
<#
.SYNOPSIS
    SqlDecom module loader.

.DESCRIPTION
    Loads config, then Private helpers, then Public commands.
    Naming follows PowerShell conventions:
      - Folders: Public / Private / config / docs / tests
      - Module:  SqlDecom.psd1 / SqlDecom.psm1
      - Scripts: Verb-Noun.ps1 matching the primary function
      - Functions / parameters: Approved Verb + PascalCase
#>

$script:SqlDecomModuleRoot  = $PSScriptRoot
$script:SqlDecomProjectRoot = Split-Path -Parent $PSScriptRoot
$script:SqlDecomConfigDir   = Join-Path $script:SqlDecomProjectRoot 'config'

# --- configuration (project-scoped defaults) ---
$configFile = Join-Path $script:SqlDecomConfigDir 'defaults.ps1'
if (-not (Test-Path -LiteralPath $configFile)) {
    throw "SqlDecom config not found: $configFile"
}
. $configFile

# --- Private helpers (not exported) ---
Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -File |
    Sort-Object Name |
    ForEach-Object { . $_.FullName }

# --- Public commands ---
$publicFiles = @(
    Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File |
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
