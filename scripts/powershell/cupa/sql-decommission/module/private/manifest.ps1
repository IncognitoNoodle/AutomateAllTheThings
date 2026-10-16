function Add-DecomFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FailureKey,
        [Parameter(Mandatory)][string]$DatabaseName
    )

    if (-not $script:DecomRenameFailures.ContainsKey($FailureKey)) {
        $script:DecomRenameFailures[$FailureKey] = @()
    }
    $script:DecomRenameFailures[$FailureKey] += $DatabaseName
    $script:DecomHadFailures = $true
}

function Save-DecomManifest {
    [CmdletBinding()]
    param()

    $script:DecomManifest['UpdatedAt'] = (Get-Date -Format o)
    $script:DecomManifest | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $script:DecomManifestPath -Encoding UTF8
}

function Set-DecomDbManifestState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Standalone', 'AvailabilityGroup')]$Branch,
        [Parameter(Mandatory)][string]$OwnerKey,
        [Parameter(Mandatory)][string]$DatabaseName,
        [Parameter(Mandatory)][string]$State,
        [string]$BackupPath,
        [string]$ErrorMessage
    )

    $bucketName = if ($Branch -eq 'Standalone') { 'Standalone' } else { 'AvailabilityGroups' }
    if (-not $script:DecomManifest[$bucketName].Contains($OwnerKey)) {
        $script:DecomManifest[$bucketName][$OwnerKey] = [ordered]@{
            Databases = [ordered]@{}
        }
    }

    $dbEntry = [ordered]@{
        State     = $State
        UpdatedAt = (Get-Date -Format o)
    }
    if ($BackupPath)   { $dbEntry['BackupPath'] = $BackupPath }
    if ($ErrorMessage) { $dbEntry['Error'] = $ErrorMessage }

    $script:DecomManifest[$bucketName][$OwnerKey].Databases[$DatabaseName] = $dbEntry
    Save-DecomManifest
}

function Get-DecomDestinationPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$FallbackHost
    )

    if ($script:DecomEffectiveBasePath) {
        return (Join-Path $script:DecomEffectiveBasePath "${Label}_RFC$($script:DecomRFCNumber)")
    }

    return "\\$FallbackHost\N$\${Label}_RFC$($script:DecomRFCNumber)"
}

