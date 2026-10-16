function Test-DecomBackupArtifact {
    <#
    Confirms a usable backup file for the database.
    Prefer an explicit FilePath from Backup-DbaDatabase; otherwise require the
    database name in the filename (never accept an unrelated newest .bak).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Database,
        [string]$FilePath
    )

    if ($FilePath) {
        if (-not (Test-Path -LiteralPath $FilePath)) {
            return [pscustomobject]@{ Ok = $false; File = $FilePath; Length = 0; Message = "Backup file missing: $FilePath" }
        }
        $item = Get-Item -LiteralPath $FilePath
        if ($item.Length -le 0) {
            return [pscustomobject]@{ Ok = $false; File = $item.FullName; Length = 0; Message = "Backup file is empty: $($item.FullName)" }
        }
        return [pscustomobject]@{
            Ok      = $true
            File    = $item.FullName
            Length  = $item.Length
            Message = "Verified $($item.FullName) ($([math]::Round($item.Length / 1MB, 2)) MB)"
        }
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Ok = $false; File = $null; Length = 0; Message = "Backup path missing: $Path" }
    }

    # Escape regex metacharacters in DB name for a safe wildcard-ish match via -like
    $file = Get-ChildItem -LiteralPath $Path -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Extension -match '\.(bak|trn|diff)$' -and
            ($_.BaseName -like "*$Database*" -or $_.Name -like "*$Database*")
        } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $file) {
        return [pscustomobject]@{
            Ok      = $false
            File    = $null
            Length  = 0
            Message = "No backup file whose name contains '$Database' under $Path"
        }
    }
    if ($file.Length -le 0) {
        return [pscustomobject]@{ Ok = $false; File = $file.FullName; Length = 0; Message = "Backup file is empty: $($file.FullName)" }
    }

    return [pscustomobject]@{
        Ok      = $true
        File    = $file.FullName
        Length  = $file.Length
        Message = "Verified $($file.FullName) ($([math]::Round($file.Length / 1MB, 2)) MB)"
    }
}

function Get-DecomBackupResultPath {
    <# Extract a concrete backup file path from Backup-DbaDatabase output. #>
    [CmdletBinding()]
    param($BackupResult)

    foreach ($row in @($BackupResult)) {
        foreach ($prop in @('BackupPath', 'Path', 'FullName', 'FileName', 'FileList')) {
            $val = $row.$prop
            if (-not $val) { continue }
            if ($val -is [System.Array]) {
                $first = @($val | Where-Object { $_ }) | Select-Object -First 1
                if ($first) { return "$first" }
            }
            else {
                return "$val"
            }
        }
    }
    return $null
}

function Invoke-DecomBackupWithFallback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SqlInstance,
        [Parameter(Mandatory)][string]$Database,
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$FallbackPath
    )

    try {
        $backupResult = Backup-DbaDatabase `
            -SqlInstance $SqlInstance `
            -Database $Database `
            -Path $ArchivePath `
            -Type Full `
            -CompressBackup `
            -Checksum `
            -Verify `
            -Initialize `
            -ErrorAction Stop

        $filePath = Get-DecomBackupResultPath -BackupResult $backupResult
        $verify = Test-DecomBackupArtifact -Path $ArchivePath -Database $Database -FilePath $filePath
        if (-not $verify.Ok) { throw $verify.Message }

        Write-Host "[BACKUP] $Database -> $($verify.File)"
        return [pscustomobject]@{ Ok = $true; Path = $verify.File; UsedFallback = $false }
    }
    catch {
        Write-Warning "[WARN] Archive backup failed for $Database : $($_.Exception.Message). Attempting local fallback."

        New-Item -Path $FallbackPath -ItemType Directory -Force -ErrorAction Stop | Out-Null

        try {
            $backupResult = Backup-DbaDatabase `
                -SqlInstance $SqlInstance `
                -Database $Database `
                -Path $FallbackPath `
                -Type Full `
                -CompressBackup `
                -Checksum `
                -Verify `
                -Initialize `
                -ErrorAction Stop

            $filePath = Get-DecomBackupResultPath -BackupResult $backupResult
            $verify = Test-DecomBackupArtifact -Path $FallbackPath -Database $Database -FilePath $filePath
            if (-not $verify.Ok) { throw $verify.Message }

            Write-Warning "[FALLBACK] $Database backed up locally to $($verify.File)"
            return [pscustomobject]@{ Ok = $true; Path = $verify.File; UsedFallback = $true }
        }
        catch {
            Write-Warning "[ERROR] Archive and fallback backup both failed for $Database : $($_.Exception.Message)"
            return [pscustomobject]@{ Ok = $false; Path = $null; UsedFallback = $true }
        }
    }
}

