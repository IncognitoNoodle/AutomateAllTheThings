# Branch B - Availability Group pipeline.
# Processed as a unit across discovered replica nodes:
#   backup (primary) -> remove from AG -> drop orphan on each secondary -> rename (primary)
# AG and listener are left intact after databases are cleared.

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
    $agOk = $true

    try {
        $info = $script:DecomValidAgs[$AgName]

        $primaryResolved = Resolve-DecomSqlInstance -Name $info.Primary
        $primary         = $primaryResolved.HostName
        $primaryInstance = $primaryResolved.SqlInstance

        # Compare by normalized hostname, not raw string, since
        # .PrimaryReplica and replica .Name values aren't guaranteed to be
        # formatted identically (one may be qualified, the other not).
        $secondaries = @(
            $info.Replicas | Where-Object {
                (Resolve-DecomSqlInstance -Name $_).HostName -ne $primary
            }
        )

        Write-Host "[INFO] AG '$AgName' nodes -> primary: $primary | secondaries: $($secondaries -join ', ')"

        $destPath = Get-DecomDestinationPath -Label $AgName -FallbackHost $primary
        New-Item -Path $destPath -ItemType Directory -Force -ErrorAction Stop | Out-Null

        Export-DecomAgRollbackPackage `
            -PrimaryInstance $primaryInstance `
            -AgName $AgName `
            -OutputFolder $destPath

        $agDatabases = Get-DbaAgDatabase -SqlInstance $primaryInstance -AvailabilityGroup $AgName

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

        # ---- Per-database: backup -> detach -> clean secondaries -> rename ----
        foreach ($agDb in $agDatabases) {
            $dbOk = Invoke-DecomAgDatabase `
                -AgName $AgName `
                -DatabaseName $agDb.Name `
                -PrimaryHost $primary `
                -PrimaryInstance $primaryInstance `
                -Secondaries $secondaries `
                -DestPath $destPath

            if (-not $dbOk) { $agOk = $false }
        }

        # ---- Leave AG and Listener intact ----
        if ($agOk) {
            Write-Host "[SUCCESS] Databases removed from AG $AgName. AG and listener left intact." -ForegroundColor Green
            $script:DecomProcessedAgs.Add($AgName) | Out-Null
        }
        else {
            Write-Warning "[PARTIAL] $AgName had database-level failures."
            $script:DecomFailedAgs.Add($AgName) | Out-Null
        }
    }
    catch {
        Write-Warning "[ERROR] AG processing failed for $AgName : $($_.Exception.Message)"
        $script:DecomFailedAgs.Add($AgName) | Out-Null
    }
}

function Invoke-DecomAgDatabase {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$AgName,
        [Parameter(Mandatory)][string]$DatabaseName,
        [Parameter(Mandatory)][string]$PrimaryHost,
        [Parameter(Mandatory)][string]$PrimaryInstance,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Secondaries,
        [Parameter(Mandatory)][string]$DestPath
    )

    try {
        if ($PSCmdlet.ShouldProcess($DatabaseName, "Backup on $PrimaryHost (primary of $AgName)")) {
            $fallbackPath = "\\$PrimaryHost\N$\${AgName}_RFC$($script:DecomRFCNumber)"

            $backupOk = Invoke-DecomBackupWithFallback `
                -SqlInstance $PrimaryInstance `
                -Database $DatabaseName `
                -ArchivePath $DestPath `
                -FallbackPath $fallbackPath

            if (-not $backupOk) {
                throw "Backup failed for $DatabaseName"
            }
        }

        if ($PSCmdlet.ShouldProcess($DatabaseName, "Remove from AG $AgName")) {
            Remove-DbaAgDatabase `
                -SqlInstance $PrimaryInstance `
                -AvailabilityGroup $AgName `
                -Database $DatabaseName `
                -Confirm:$false `
                -ErrorAction Stop

            # Verify database is no longer a member of the AG
            $removed = $false

            for ($i = 1; $i -le 30; $i++) {
                Start-Sleep -Seconds 2

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
        }

        # Detaching only happens on the primary - every secondary is
        # left holding a RESTORING orphan copy under the old name.
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

        $renameOk = Invoke-DecomRenameDatabase `
            -SqlInstance $PrimaryInstance `
            -ServerName $PrimaryHost `
            -OriginalName $DatabaseName `
            -FailureKey $AgName

        return ($secondaryOk -and $renameOk)
    }
    catch {
        Write-Warning "[ERROR] Processing failed for $DatabaseName in $AgName : $($_.Exception.Message)"
        Add-DecomFailure -FailureKey $AgName -DatabaseName $DatabaseName
        return $false
    }
}
