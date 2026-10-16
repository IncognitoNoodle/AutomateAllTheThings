# Branch B - Availability Group pipeline (two-phase).
# Phase 1: AG config backup (gated) + backup/verify ALL AG databases on primary.
# Phase 2 (only if Phase 1 fully succeeded): remove from AG -> drop secondary orphans -> rename.

function Invoke-DecomAvailabilityGroupPipeline {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Host "`n===== BRANCH: AVAILABILITY GROUPS =====" -ForegroundColor Cyan

    if ($script:DecomValidAgs.Count -eq 0) {
        Write-Host '[INFO] No Availability Group targets to process.'
        return
    }

    foreach ($agName in @($script:DecomValidAgs.Keys)) {
        Invoke-DecomAvailabilityGroup -AgName $agName
    }
}

function Invoke-DecomAvailabilityGroup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$AgName
    )

    Write-Host "`n----- Processing AG $AgName -----" -ForegroundColor Cyan

    try {
        $info = $script:DecomValidAgs[$AgName]

        $primaryResolved = Resolve-DecomSqlInstance -Name $info.Primary
        $primary         = $primaryResolved.HostName
        $primaryInstance = $primaryResolved.SqlInstance

        $secondaries = @(
            $info.Replicas | Where-Object {
                (Resolve-DecomSqlInstance -Name $_).HostName -ne $primary
            }
        )

        Write-Host "[INFO] AG '$AgName' nodes -> primary: $primary | secondaries: $($secondaries -join ', ')"

        $destPath = Get-DecomDestinationPath -Label $AgName -FallbackHost $primary
        New-Item -Path $destPath -ItemType Directory -Force -ErrorAction Stop | Out-Null

        # ---- AG configuration backup (hard gate) ----
        Write-Host "[PHASE 0] Exporting AG configuration for $AgName" -ForegroundColor Cyan
        $configOk = Export-DecomAgConfiguration `
            -PrimaryInstance $primaryInstance `
            -AgName $AgName `
            -OutputFolder $destPath

        if (-not $configOk) {
            Write-Warning "[ABORT] AG configuration backup failed for $AgName - no database mutations will run."
            $script:DecomFailedAgs.Add($AgName) | Out-Null
            $script:DecomHadFailures = $true
            return
        }

        $agDatabases = @(
            Get-DbaAgDatabase -SqlInstance $primaryInstance -AvailabilityGroup $AgName |
                Where-Object { -not (Test-DecomExcludedDatabase -Name $_.Name) }
        )

        # ---- Logging: every replica + every database, before touching anything ----
        $serverInfoBlocks = @(
            foreach ($r in $info.Replicas) {
                $rResolved = Resolve-DecomSqlInstance -Name $r
                $role = if ($rResolved.HostName -eq $primary) { 'Primary' } else { 'Secondary' }

                $b = Get-DecomServerInfoBlock -SqlInstance $rResolved.SqlInstance -ServerName $rResolved.HostName
                $b['AgRole'] = $role
                $b
            }
        )
        Write-DecomInfoFile `
            -Path (Join-Path $destPath 'ServerInfo.txt') `
            -Blocks $serverInfoBlocks `
            -Header "AVAILABILITY GROUP: $AgName (Primary: $primary)"

        $dbInfoBlocks = @(
            $agDatabases | ForEach-Object {
                $dbObj = Get-DbaDatabase -SqlInstance $primaryInstance -Database $_.Name
                Get-DecomDatabaseInfoBlock -Database $dbObj -AgRole "AG member ($AgName)"
            }
        )
        if ($dbInfoBlocks.Count -gt 0) {
            Write-DecomInfoFile -Path (Join-Path $destPath 'ServerInfo.txt') -Blocks $dbInfoBlocks -Header 'DATABASES'
        }

        if ($agDatabases.Count -eq 0) {
            Write-Host "[INFO] No eligible AG databases in $AgName."
            $script:DecomProcessedAgs.Add($AgName) | Out-Null
            return
        }

        # -------- Phase 1: backup + verify ALL databases (no AG mutations) --------
        Write-Host "[PHASE 1] Backing up all AG databases on primary $primary" -ForegroundColor Cyan
        $backedUp = [System.Collections.Generic.List[string]]::new()
        $phase1Ok = $true

        foreach ($agDb in $agDatabases) {
            $dbName = $agDb.Name
            Set-DecomDbManifestState -Branch AvailabilityGroup -OwnerKey $AgName -DatabaseName $dbName -State 'Pending'

            if ($PSCmdlet.ShouldProcess($dbName, "Backup on $primary (primary of $AgName)")) {
                $fallbackPath = "\\$primary\N$\${AgName}_RFC$($script:DecomRFCNumber)"
                $backupResult = Invoke-DecomBackupWithFallback `
                    -SqlInstance $primaryInstance `
                    -Database $dbName `
                    -ArchivePath $destPath `
                    -FallbackPath $fallbackPath

                if (-not $backupResult.Ok) {
                    Set-DecomDbManifestState -Branch AvailabilityGroup -OwnerKey $AgName -DatabaseName $dbName `
                        -State 'BackupFailed' -ErrorMessage 'Backup+verify failed'
                    Add-DecomFailure -FailureKey $AgName -DatabaseName $dbName
                    $phase1Ok = $false
                    continue
                }

                Set-DecomDbManifestState -Branch AvailabilityGroup -OwnerKey $AgName -DatabaseName $dbName `
                    -State 'BackedUp' -BackupPath $backupResult.Path
                $backedUp.Add($dbName) | Out-Null
            }
        }

        if ($WhatIfPreference) {
            Write-Host "[WHATIF] Skipping Phase 2 mutate for AG $AgName (no detach/rename under -WhatIf)." -ForegroundColor Yellow
            return
        }

        if (-not $phase1Ok -or $backedUp.Count -ne $agDatabases.Count) {
            Write-Warning "[ABORT] Phase 1 incomplete for AG $AgName ($($backedUp.Count)/$($agDatabases.Count) verified). Skipping detach/rename."
            $script:DecomFailedAgs.Add($AgName) | Out-Null
            $script:DecomHadFailures = $true
            return
        }

        # -------- Phase 2: detach / clean secondaries / rename --------
        Write-Host "[PHASE 2] Detaching and renaming databases in AG $AgName" -ForegroundColor Cyan
        $agOk = $true

        foreach ($dbName in $backedUp) {
            $dbOk = Invoke-DecomAgDatabaseMutate `
                -AgName $AgName `
                -DatabaseName $dbName `
                -PrimaryHost $primary `
                -PrimaryInstance $primaryInstance `
                -Secondaries $secondaries

            if (-not $dbOk) { $agOk = $false }
        }

        if ($agOk) {
            Write-Host "[SUCCESS] Databases removed from AG $AgName. AG and listener left intact." -ForegroundColor Green
            $script:DecomProcessedAgs.Add($AgName) | Out-Null
        }
        else {
            Write-Warning "[PARTIAL] $AgName had database-level failures during Phase 2."
            $script:DecomFailedAgs.Add($AgName) | Out-Null
            $script:DecomHadFailures = $true
        }
    }
    catch {
        Write-Warning "[ERROR] AG processing failed for $AgName : $($_.Exception.Message)"
        $script:DecomFailedAgs.Add($AgName) | Out-Null
        $script:DecomHadFailures = $true
    }
}

function Invoke-DecomAgDatabaseMutate {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$AgName,
        [Parameter(Mandatory)][string]$DatabaseName,
        [Parameter(Mandatory)][string]$PrimaryHost,
        [Parameter(Mandatory)][string]$PrimaryInstance,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Secondaries
    )

    try {
        if ($PSCmdlet.ShouldProcess($DatabaseName, "Remove from AG $AgName")) {
            Remove-DbaAgDatabase `
                -SqlInstance $PrimaryInstance `
                -AvailabilityGroup $AgName `
                -Database $DatabaseName `
                -Confirm:$false `
                -ErrorAction Stop

            $removed = $false
            for ($i = 1; $i -le $script:DecomAgRemovePollAttempts; $i++) {
                Start-Sleep -Seconds $script:DecomAgRemovePollSeconds

                $stillInAg = Get-DbaAgDatabase `
                    -SqlInstance $PrimaryInstance `
                    -AvailabilityGroup $AgName `
                    -ErrorAction SilentlyContinue |
                    Where-Object Name -eq $DatabaseName

                if (-not $stillInAg) {
                    $removed = $true
                    break
                }
            }

            if (-not $removed) {
                throw "Database '$DatabaseName' still appears to belong to AG '$AgName' after removal attempt."
            }

            Write-Host "[REMOVED] $DatabaseName removed from AG $AgName"
            Set-DecomDbManifestState -Branch AvailabilityGroup -OwnerKey $AgName -DatabaseName $DatabaseName -State 'RemovedFromAg'
        }

        $secondaryOk = $true
        foreach ($sec in $Secondaries) {
            $secInstance = (Resolve-DecomSqlInstance -Name $sec).SqlInstance
            try {
                $orphan = Get-DbaDatabase -SqlInstance $secInstance -Database $DatabaseName -ErrorAction SilentlyContinue
                if ($orphan -and $PSCmdlet.ShouldProcess($DatabaseName, "Drop orphaned secondary copy on $sec")) {
                    Remove-DbaDatabase -SqlInstance $secInstance -Database $DatabaseName -Confirm:$false -ErrorAction Stop
                    Write-Host "[CLEANED] Orphaned copy of $DatabaseName dropped on secondary $sec"
                }
            }
            catch {
                Write-Warning "[ERROR] Failed to drop orphaned copy of $DatabaseName on secondary ${sec}: $($_.Exception.Message)"
                $secondaryOk = $false
            }
        }

        if ($secondaryOk) {
            Set-DecomDbManifestState -Branch AvailabilityGroup -OwnerKey $AgName -DatabaseName $DatabaseName -State 'OrphansCleaned'
        }

        $renameOk = Invoke-DecomRenameDatabase `
            -SqlInstance $PrimaryInstance `
            -ServerName $PrimaryHost `
            -OriginalName $DatabaseName `
            -FailureKey $AgName

        if ($renameOk) {
            Set-DecomDbManifestState -Branch AvailabilityGroup -OwnerKey $AgName -DatabaseName $DatabaseName -State 'Renamed'
        }
        else {
            Set-DecomDbManifestState -Branch AvailabilityGroup -OwnerKey $AgName -DatabaseName $DatabaseName `
                -State 'RenameFailed' -ErrorMessage 'Rename failed'
        }

        return ($secondaryOk -and $renameOk)
    }
    catch {
        Write-Warning "[ERROR] Phase 2 failed for $DatabaseName in $AgName : $($_.Exception.Message)"
        Add-DecomFailure -FailureKey $AgName -DatabaseName $DatabaseName
        Set-DecomDbManifestState -Branch AvailabilityGroup -OwnerKey $AgName -DatabaseName $DatabaseName `
            -State 'MutateFailed' -ErrorMessage $_.Exception.Message
        return $false
    }
}
