# Branch A - standalone server pipeline.
# Per server: inventory snapshot -> backup (archive with local fallback) -> rename.

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

        $databases  = Get-DbaDatabase -SqlInstance $SqlInstance -ExcludeSystem
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
            Write-Host "[INFO] No user databases on $ServerName - nothing to back up."
        }

        foreach ($db in $databases) {
            if ($db.Name -like '*_Decom_RFC*') { continue }

            if ($PSCmdlet.ShouldProcess($db.Name, "Backup on $ServerName")) {
                try {
                    $fallbackPath = "\\$ServerName\N$\${ServerName}_RFC$($script:DecomRFCNumber)"
                    $backupOk = Invoke-DecomBackupWithFallback `
                        -SqlInstance $SqlInstance `
                        -Database $db.Name `
                        -ArchivePath $destPath `
                        -FallbackPath $fallbackPath

                    if (-not $backupOk) {
                        Add-DecomFailure -FailureKey $ServerName -DatabaseName $db.Name
                        $serverOk = $false
                        continue
                    }
                }
                catch {
                    Write-Warning "[ERROR] Backup failed for $($db.Name) on $ServerName : $($_.Exception.Message)"
                    Add-DecomFailure -FailureKey $ServerName -DatabaseName $db.Name
                    $serverOk = $false
                    continue
                }
            }

            $ok = Invoke-DecomRenameDatabase `
                -SqlInstance $SqlInstance `
                -ServerName $ServerName `
                -OriginalName $db.Name `
                -FailureKey $ServerName
            if (-not $ok) { $serverOk = $false }
        }

        if ($serverOk) {
            $script:DecomProcessedServers.Add($ServerName) | Out-Null
            Write-Host "[DONE] $ServerName" -ForegroundColor Green
        }
        else {
            $script:DecomFailedServers.Add($ServerName) | Out-Null
            Write-Warning "[PARTIAL] $ServerName completed with some backup/rename failures - see above."
        }
    }
    catch {
        Write-Warning "[FAILED] $ServerName : $($_.Exception.Message)"
        $script:DecomFailedServers.Add($ServerName) | Out-Null
    }
}
