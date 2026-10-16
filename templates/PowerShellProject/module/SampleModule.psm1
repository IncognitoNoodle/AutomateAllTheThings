#Requires -Version 5.1

$script:SampleProjectRoot = Split-Path -Parent $PSScriptRoot
$config = Join-Path $script:SampleProjectRoot 'config\defaults.ps1'
if (Test-Path -LiteralPath $config) { . $config }

Get-ChildItem (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -File -ErrorAction SilentlyContinue |
    ForEach-Object { . $_.FullName }

$public = @(Get-ChildItem (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File)
foreach ($f in $public) { . $f.FullName }

Export-ModuleMember -Function @(
    $public | ForEach-Object {
        (Select-String -Path $_.FullName -Pattern '^function\s+([A-Za-z][\w-]*)').Matches.Groups[1].Value
    } | Select-Object -Unique
)
