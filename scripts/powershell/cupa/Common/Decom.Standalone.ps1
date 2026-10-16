# Branch A - standalone server pipeline (two-phase).
# Phase 1: inventory snapshot + backup/verify all eligible databases.
# Phase 2: rename only databases that verified BackedUp.

function Invoke-DecomStandalonePipeline {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Host "`n===== BRANCH: STANDALONE =====" -ForegroundColor Cyan

    if ($script:DecomResolvedStandalone.Count -eq 0) {
        Write-Host '[INFO] No standalone targets to process.'
        return
    }

    foreach ($srv in $script:DecomResolvedStandalone) {
        Invoke-DecomStandaloneServer -ServerName $srv
    }
}

function Invoke-DecomStandaloneServer {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$ServerName
    )

    Write-Host "`n----- Processing standalone server $ServerName -----" -ForegroundColor Cyan
    $serverOk = $true

    try {
        $SqlInstance = (Resolve-DecomSqlInstance -Name $ServerName).SqlInstance
        $destPath    = Get-DecomDestinationPath -Label $ServerName -FallbackHost $ServerName

        New-Item -Path $destPath -ItemType Directory -Force -ErrorAction Stop | Out-Null

        $databases  = @(Get-DbaDatabase -SqlInstance $SqlInstance -ExcludeSystem |
            Where-Object { -not (Test-DecomExcludedDatabase -Name $_.Name) })

        $serverInfo = Get-DecomServerInfoBlock -SqlInstance $SqlInstance -ServerName $ServerName
        Write-DecomInfoFile -Path (Join-Path $destPath 'ServerInfo.txt') -Blocks @($serverInfo) -Header 'SERVER INFO'

        $dbInfoBlocks = @(
            $databases | ForEach-Object {
                Get-DecomDatabaseInfoBlock -Database $_ -AgRole 'N/A (standalone)'
            }
        )
        if ($dbInfoBlocks.Count -gt 0) {
            Write-DecomInfoFile -Path (Join-Path $destPath 'ServerInfo.txt') -Blocks $dbInfoBlocks -Header 'DATABASES'
        }

        if ($databases.Count -eq 0) {
            Write-Host "[INFO] No eligible user databases on $ServerName - nothing to back up."
            $script:DecomProcessedServers.Add($ServerName) | Out-Null
            Write-Host "[DONE] $ServerName" -ForegroundColor Green
            return
        }

        # -------- Phase 1: backup + verify --------
        Write-Host "[PHASE 1] Backing up databases on $ServerName" -ForegroundColor Cyan
        $backedUp = [System.Collections.Generic.List[string]]::new()

        foreach ($db in $databases) {
            Set-DecomDbManifestState -Branch Standalone -OwnerKey $ServerName -DatabaseName $db.Name -State 'Pending'

            if ($PSCmdlet.ShouldProcess($db.Name, "Backup on $ServerName")) {
                try {
                    $fallbackPath = "\\$ServerName\N$\${ServerName}_RFC$($script:DecomRFCNumber)"
                    $backupResult = Invoke-DecomBackupWithFallback `
                        -SqlInstance $SqlInstance `
                        -Database $db.Name `
                        -ArchivePath $destPath `
                        -FallbackPath $fallbackPath

                    if (-not $backupResult.Ok) {
                        Set-DecomDbManifestState -Branch Standalone -OwnerKey $ServerName -DatabaseName $db.Name `
                            -State 'BackupFailed' -ErrorMessage 'Backup+verify failed'
                        Add-DecomFailure -FailureKey $ServerName -DatabaseName $db.Name
                        $serverOk = $false
                        continue
                    }

                    Set-DecomDbManifestState -Branch Standalone -OwnerKey $ServerName -DatabaseName $db.Name `
                        -State 'BackedUp' -BackupPath $backupResult.Path
                    $backedUp.Add($db.Name) | Out-Null
                }
                catch {
                    Write-Warning "[ERROR] Backup failed for $($db.Name) on $ServerName : $($_.Exception.Message)"
                    Set-DecomDbManifestState -Branch Standalone -OwnerKey $ServerName -DatabaseName $db.Name `
                        -State 'BackupFailed' -ErrorMessage $_.Exception.Message
                    Add-DecomFailure -FailureKey $ServerName -DatabaseName $db.Name
                    $serverOk = $false
                }
            }
        }

        if ($WhatIfPreference) {
            Write-Host "[WHATIF] Skipping rename phase for $ServerName (no mutations under -WhatIf)." -ForegroundColor Yellow
            return
        }

        if ($backedUp.Count -eq 0) {
            Write-Warning "[SKIP] No verified backups on $ServerName - rename phase skipped."
            $script:DecomFailedServers.Add($ServerName) | Out-Null
            return
        }

        if (-not $serverOk) {
            Write-Warning "[ABORT RENAME] $ServerName had backup failures - refusing rename phase for flawless-run safety. Fix failures and re-run."
            $script:DecomFailedServers.Add($ServerName) | Out-Null
            $script:DecomHadFailures = $true
            return
        }

        # -------- Phase 2: rename only verified backups --------
        Write-Host "[PHASE 2] Renaming backed-up databases on $ServerName" -ForegroundColor Cyan
        foreach ($dbName in $backedUp) {
            $ok = Invoke-DecomRenameDatabase `
                -SqlInstance $SqlInstance `
                -ServerName $ServerName `
                -OriginalName $dbName `
                -FailureKey $ServerName

            if ($ok) {
                Set-DecomDbManifestState -Branch Standalone -OwnerKey $ServerName -DatabaseName $dbName -State 'Renamed'
            }
            else {
                Set-DecomDbManifestState -Branch Standalone -OwnerKey $ServerName -DatabaseName $dbName `
                    -State 'RenameFailed' -ErrorMessage 'Rename failed'
                $serverOk = $false
            }
        }

        if ($serverOk) {
            $script:DecomProcessedServers.Add($ServerName) | Out-Null
            Write-Host "[DONE] $ServerName" -ForegroundColor Green
        }
        else {
            $script:DecomFailedServers.Add($ServerName) | Out-Null
            Write-Warning "[PARTIAL] $ServerName completed with rename failures - see above."
        }
    }
    catch {
        Write-Warning "[FAILED] $ServerName : $($_.Exception.Message)"
        $script:DecomFailedServers.Add($ServerName) | Out-Null
        $script:DecomHadFailures = $true
    }
}
