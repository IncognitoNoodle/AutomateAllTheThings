[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_-]+$')]   # blocks bracket/path-breaking chars
    [string]$RFCNumber,

    [Parameter(Mandatory = $true)]
    [string[]]$Targets
)

# ==========================================================
# CONFIGURATION
# ==========================================================
$instanceSuffix    = "\SQL01"
$basePath          = "\\ucles.internal\DBArchive"
$localBackupRoot = "N:\"
$inventoryInstance = "DBAPRDAG01\SQL01"

# Determine whether archive share is reachable
if (Test-Path $basePath) {
    $effectiveBasePath = $basePath
    Write-Host "[INFO] Using archive share: $basePath" -ForegroundColor Green
}
else {
    $effectiveBasePath = $null

    Write-Warning "[WARN] Archive share unavailable: $basePath"
    Write-Warning "[WARN] Backups will use target server N$ shares."
}

$logDir = "C:\Temp\DecomLogs"

# ==========================================================
# INITIALIZATION
# ==========================================================
New-Item $logDir -ItemType Directory -Force | Out-Null
$transcriptPath = Join-Path $logDir "Decom_RFC${RFCNumber}_$(Get-Date -Format yyyyMMdd_HHmmss).log"
Start-Transcript -Path $transcriptPath -Append | Out-Null

Write-Host "`n[INFO] Initializing for RFC $RFCNumber..." -ForegroundColor Cyan
Write-Host "[INFO] Targets as provided: $($Targets -join ', ')"

if (-not (Get-Module -ListAvailable -Name dbatools)) {
    Install-Module dbatools -Scope CurrentUser -Force
}
Import-Module dbatools

Set-DbatoolsConfig sql.connection.encrypt $true
Set-DbatoolsConfig sql.connection.trustcert $true

$dbatoolsVersion = (Get-Module dbatools).Version.ToString()
$psVersion       = $PSVersionTable.PSVersion.ToString()
$runBy           = "$env:USERDOMAIN\$env:USERNAME"

# Tracking collections used throughout the run
$unreachableOrUnresolved = @()
$resolvedAgs             = @{}   # AgName -> @{ Primary; Replicas; SeedInstance }
$resolvedStandalone      = @()
$processedServers        = @()
$processedAgs            = @()
$failedServers           = @()
$failedAgs               = @()
$renameFailures          = @{}   # key (server or AG) -> list of db names that failed

# ==========================================================
# HELPERS
# ==========================================================

function Resolve-SqlInstance {
    <#
    Normalizes a target name to a plain host name and a full SQL instance
    connection string. Accepts either a bare "server" (the configured
    $instanceSuffix is appended) or an already-qualified "server\instance"
    name (used as-is). Centralizing this avoids the same "$x$instanceSuffix"
    logic being duplicated - and getting out of sync - in multiple places.
    #>
    param([string]$Name)

    if ($Name -match '\\') {
        $hostName    = ($Name -split '\\')[0]
        $sqlInstance = $Name
    }
    else {
        $hostName    = $Name
        $sqlInstance = "$Name$instanceSuffix"
    }

    [pscustomobject]@{
        HostName    = $hostName
        SqlInstance = $sqlInstance
    }
}

function Get-ServerInfoBlock {
    <# Everything worth knowing about a server at decommission time. #>
    param([string]$SqlInstance, [string]$ServerName)

    $conn = Connect-DbaInstance -SqlInstance $SqlInstance

    [ordered]@{
        ServerName        = $ServerName
        FQDN              = $conn.ComputerNamePhysicalNetBIOS
        SqlInstance       = $SqlInstance
        SqlVersion        = $conn.Version.ToString()
        SqlEdition        = $conn.Edition
        SqlProductLevel   = $conn.ProductLevel
        SqlBuildNumber    = $conn.VersionString
        Collation         = $conn.Collation
        IsClustered       = $conn.IsClustered
        IsHadrEnabled     = $conn.IsHadrEnabled
        OsVersion         = (Get-DbaOperatingSystem -ComputerName $ServerName -ErrorAction SilentlyContinue).OSVersion
        TotalMemoryMB     = $conn.PhysicalMemory
        RFCNumber         = $RFCNumber
        RunBy             = $runBy
        PowerShellVersion = $psVersion
        DbatoolsVersion   = $dbatoolsVersion
        Timestamp         = (Get-Date -Format o)
    }
}

function Get-DatabaseInfoBlock {
    <# Per-database detail captured at decommission time. #>
    param($Database, [string]$AgRole)

    [ordered]@{
        Name              = $Database.Name
        SizeMB            = [math]::Round($Database.Size, 2)
        RecoveryModel     = $Database.RecoveryModel
        Owner             = $Database.Owner
        Collation         = $Database.Collation
        CreateDate        = $Database.CreateDate
        Status            = $Database.Status
        LastFullBackup    = $Database.LastBackupDate
        AvailabilityGroup = $Database.AvailabilityGroupName
        AgRole            = $AgRole
    }
}

function Write-InfoFile {
    param([string]$Path, [hashtable[]]$Blocks, [string]$Header)

    $lines = @("===== $Header =====")
    foreach ($b in $Blocks) {
        $name = if ($b.Contains('ServerName')) { $b.ServerName } else { $b.Name }
        $lines += "--- $name ---"
        foreach ($k in $b.Keys) {
            if ($k -ne 'ServerName' -and $k -ne 'Name') { $lines += "  $k`: $($b[$k])" }
        }
    }
    $lines | Add-Content $Path -ErrorAction Stop
}

function Invoke-RenameDatabase {
    param([string]$SqlInstance, [string]$ServerName, [string]$OriginalName, [string]$FailureKey)

    if ($OriginalName -like "*_Decom_RFC*") { return $true }
    $newName = "$OriginalName`_Decom_RFC${RFCNumber}"

    try {
        if ($PSCmdlet.ShouldProcess($OriginalName, "Rename to $newName on $ServerName")) {
            Invoke-DbaQuery -SqlInstance $SqlInstance -ErrorAction Stop -Query @"
ALTER DATABASE [$OriginalName] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
ALTER DATABASE [$OriginalName] MODIFY NAME = [$newName];
ALTER DATABASE [$newName] SET MULTI_USER;
"@
            Write-Host "[RENAMED] $OriginalName -> $newName ($ServerName)"
        }
        return $true
    }
    catch {
        Write-Warning "[ERROR] Rename failed for $OriginalName on $ServerName : $($_.Exception.Message)"
        if (-not $renameFailures.ContainsKey($FailureKey)) { $renameFailures[$FailureKey] = @() }
        $renameFailures[$FailureKey] += $OriginalName
        return $false
    }
}

function Invoke-BackupWithFallback {
    param(
        [string]$SqlInstance,
        [string]$Database,
        [string]$ArchivePath,
        [string]$FallbackPath
    )

    try {
        Backup-DbaDatabase `
            -SqlInstance $SqlInstance `
            -Database $Database `
            -Path $ArchivePath `
            -Type Full `
            -CompressBackup `
            -Checksum `
            -Verify `
            -Initialize `
            -ErrorAction Stop | Out-Null

        Write-Host "[BACKUP] $Database -> $ArchivePath"
        return $true
    }
    catch {
        Write-Warning "[WARN] Archive backup failed for $Database. Attempting local fallback."

        New-Item -Path $FallbackPath -ItemType Directory -Force -ErrorAction Stop | Out-Null

        try {
            Backup-DbaDatabase `
                -SqlInstance $SqlInstance `
                -Database $Database `
                -Path $FallbackPath `
                -Type Full `
                -CompressBackup `
                -Checksum `
                -Verify `
                -Initialize `
                -ErrorAction Stop | Out-Null

            Write-Warning "[FALLBACK] $Database backed up locally to $FallbackPath"
            return $true
        }
        catch {
            Write-Warning "[ERROR] Archive and fallback backup both failed for $Database"
            return $false
        }
    }
}

function Export-AgRollbackPackage {
    param(
        [string]$PrimaryInstance,
        [string]$AgName,
        [string]$OutputFolder
    )

    $txtFile = Join-Path $OutputFolder "AG_Config_${AgName}.txt"
    $sqlFile = Join-Path $OutputFolder "AG_Rollback_${AgName}.sql"

    $ag       = Get-DbaAvailabilityGroup -SqlInstance $PrimaryInstance -AvailabilityGroup $AgName
    $replicas = Get-DbaAgReplica -SqlInstance $PrimaryInstance -AvailabilityGroup $AgName

    $listenerQuery = @"
SELECT
    l.dns_name,
    l.port,
    ip.ip_address,
    ip.subnet_mask
FROM sys.availability_group_listeners l
INNER JOIN sys.availability_group_listener_ip_addresses ip
    ON l.listener_id = ip.listener_id
INNER JOIN sys.availability_groups ag
    ON ag.group_id = l.group_id
WHERE ag.name = '$AgName';
"@

    $listeners = Invoke-DbaQuery `
        -SqlInstance $PrimaryInstance `
        -Database master `
        -Query $listenerQuery

    @"
Availability Group : $AgName
Generated          : $(Get-Date)

===== REPLICAS =====

$($replicas | Format-Table -AutoSize | Out-String)

===== LISTENERS =====

$($listeners | Format-Table -AutoSize | Out-String)
"@ | Set-Content $txtFile

    $sql = New-Object System.Collections.Generic.List[string]

    $sql.Add("/*")
    $sql.Add("Rollback/Rebuild Script")
    $sql.Add("RFC: $RFCNumber")
    $sql.Add("Generated: $(Get-Date)")
    $sql.Add("*/")
    $sql.Add("")

    $sql.Add(@"
IF EXISTS (
    SELECT 1
    FROM sys.availability_groups
    WHERE name = '$AgName'
)
BEGIN
    DROP AVAILABILITY GROUP [$AgName];
END
GO
"@)

    $replicaDefinitions = @()

    foreach ($rep in $replicas) {
        $replicaDefinitions += @"
N'$($rep.Name)'
WITH (
    ENDPOINT_URL = N'$($rep.EndpointUrl)',
    FAILOVER_MODE = $($rep.FailoverMode),
    AVAILABILITY_MODE = $($rep.AvailabilityMode),
    BACKUP_PRIORITY = $($rep.BackupPriority)
)
"@
    }

    $sql.Add("CREATE AVAILABILITY GROUP [$AgName]")
    $sql.Add("FOR REPLICA ON")
    $sql.Add(($replicaDefinitions -join ",`r`n"))
    $sql.Add("GO")

    foreach ($listener in $listeners) {

        $sql.Add(@"

ALTER AVAILABILITY GROUP [$AgName]
ADD LISTENER N'$($listener.dns_name)'
(
    WITH IP
    (
        ('$($listener.ip_address)','$($listener.subnet_mask)')
    ),
    PORT=$($listener.port)
);
GO

"@)
    }

    $sql | Set-Content $sqlFile

    Write-Host "[INFO] AG rollback package created:"
    Write-Host "       $txtFile"
    Write-Host "       $sqlFile"
}

# ==========================================================
# RESOLVE EACH TARGET: AG vs STANDALONE, SELF-DISCOVERED
# ==========================================================
Write-Host "`n===== RESOLVING TARGETS =====" -ForegroundColor Cyan

foreach ($t in ($Targets | Select-Object -Unique)) {

    # Already resolved as part of another entry in this same list
    # (e.g. an AG's listener name AND one of its node names both present)?
    if ($resolvedAgs.Keys | Where-Object { $resolvedAgs[$_].Replicas -contains $t -or $_ -eq $t }) {
        Write-Host "[INFO] '$t' already covered by a previously resolved AG - skipping duplicate."
        continue
    }
    if ($t -in $resolvedStandalone) { continue }

    if (-not (Test-Connection $t -Count 1 -Quiet)) {
        Write-Warning "[WARN] '$t' is unreachable - skipping."
        $unreachableOrUnresolved += $t
        continue
    }

    try {
        $resolvedTarget = Resolve-SqlInstance $t
        $instance        = $resolvedTarget.SqlInstance

        try {
            Connect-DbaInstance -SqlInstance $instance -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Warning "[WARN] Cannot connect to SQL instance $instance"
            $unreachableOrUnresolved += $t
            continue
        }

        # Determine whether this target is a member of an Availability Group.
        $ag = Get-DbaAvailabilityGroup -SqlInstance $instance -ErrorAction SilentlyContinue | Select-Object -First 1

        if ($ag) {
            $agName = $ag.Name
            if ($resolvedAgs.ContainsKey($agName)) {
                Write-Host "[INFO] '$t' resolves to already-queued AG '$agName' - skipping duplicate."
                continue
            }
            $replicas = (Get-DbaAgReplica -SqlInstance $instance -AvailabilityGroup $agName).Name
            $resolvedAgs[$agName] = @{
                Primary      = $ag.PrimaryReplica
                Replicas     = $replicas
                SeedInstance = $instance
            }
            Write-Host "[AG] '$t' -> AG '$agName' (primary: $($ag.PrimaryReplica), replicas: $($replicas -join ', '))" -ForegroundColor Green
        }
        else {
            $resolvedStandalone += $t
            Write-Host "[STANDALONE] '$t'" -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "[WARN] Could not resolve '$t' (connection/query failed): $($_.Exception.Message)"
        $unreachableOrUnresolved += $t
    }
}

# Sanity-check every AG's replicas are reachable before touching anything.
$validAgs = @{}
foreach ($agName in $resolvedAgs.Keys) {
    $info = $resolvedAgs[$agName]
    $offline = $info.Replicas | Where-Object {
        $serverName = (Resolve-SqlInstance $_).HostName
        -not (Test-Connection $serverName -Count 1 -Quiet)
    }
    if ($offline) {
        Write-Warning "[SKIP] AG '$agName' has unreachable replica(s): $($offline -join ', ') - skipping for safety."
        $failedAgs += $agName
        continue
    }
    $validAgs[$agName] = $info
}

Write-Host "`n[INFO] Resolved -> AGs: $($validAgs.Keys -join ', ') | Standalone: $($resolvedStandalone -join ', ')"
if ($unreachableOrUnresolved) {
    Write-Warning "[INFO] Unreachable/unresolved entries (excluded): $($unreachableOrUnresolved -join ', ')"
}

# ==========================================================
# BRANCH A: STANDALONE SERVERS
# ==========================================================
Write-Host "`n===== BRANCH: STANDALONE =====" -ForegroundColor Cyan

foreach ($srv in $resolvedStandalone) {

    Write-Host "`n----- Processing standalone server $srv -----" -ForegroundColor Cyan
    $serverOk = $true

    try {
        $SqlInstance = (Resolve-SqlInstance $srv).SqlInstance
        if ($effectiveBasePath) {
            $destPath = Join-Path $effectiveBasePath "${srv}_RFC${RFCNumber}"
        }
        else {
            $destPath = "\\$srv\N$\${srv}_RFC${RFCNumber}"
        }

        New-Item -Path $destPath -ItemType Directory -Force -ErrorAction Stop | Out-Null

        $databases  = Get-DbaDatabase -SqlInstance $SqlInstance -ExcludeSystem
        $serverInfo = Get-ServerInfoBlock -SqlInstance $SqlInstance -ServerName $srv
        Write-InfoFile -Path (Join-Path $destPath "ServerInfo.txt") -Blocks @($serverInfo) -Header "SERVER INFO"

        $dbInfoBlocks = $databases | ForEach-Object { Get-DatabaseInfoBlock -Database $_ -AgRole "N/A (standalone)" }
        if ($dbInfoBlocks) {
            Write-InfoFile -Path (Join-Path $destPath "ServerInfo.txt") -Blocks $dbInfoBlocks -Header "DATABASES"
        }

        if ($databases.Count -eq 0) {
            Write-Host "[INFO] No user databases on $srv - nothing to back up."
        }

        foreach ($db in $databases) {
            if ($db.Name -like "*_Decom_RFC*") { continue }

            if ($PSCmdlet.ShouldProcess($db.Name, "Backup on $srv")) {
                try {
                    $fallbackPath = "\\$srv\N$\${srv}_RFC${RFCNumber}"
                    $backupOk = Invoke-BackupWithFallback `
                        -SqlInstance $SqlInstance `
                        -Database $db.Name `
                        -ArchivePath $destPath `
                        -FallbackPath $fallbackPath

                    if (-not $backupOk) {
                        if (-not $renameFailures.ContainsKey($srv)) { $renameFailures[$srv] = @() }
                        $renameFailures[$srv] += $db.Name
                        $serverOk = $false
                        continue
                    }
                }
                catch {
                    Write-Warning "[ERROR] Backup failed for $($db.Name) on $srv : $($_.Exception.Message)"
                    if (-not $renameFailures.ContainsKey($srv)) { $renameFailures[$srv] = @() }
                    $renameFailures[$srv] += $db.Name
                    $serverOk = $false
                    continue
                }
            }

            $ok = Invoke-RenameDatabase -SqlInstance $SqlInstance -ServerName $srv -OriginalName $db.Name -FailureKey $srv
            if (-not $ok) { $serverOk = $false }
        }

        if ($serverOk) {
            $processedServers += $srv
            Write-Host "[DONE] $srv" -ForegroundColor Green
        }
        else {
            $failedServers += $srv
            Write-Warning "[PARTIAL] $srv completed with some backup/rename failures - see above."
        }
    }
    catch {
        Write-Warning "[FAILED] $srv : $($_.Exception.Message)"
        $failedServers += $srv
    }
}

# ==========================================================
# BRANCH B: AVAILABILITY GROUPS
# Processed as a unit: backup -> detach from AG (primary) -> drop the
# orphaned copy left on every secondary -> rename (primary) -> once every
# database in the AG is clear, drop the (now empty) AG in one call.
# ==========================================================
Write-Host "`n===== BRANCH: AVAILABILITY GROUPS =====" -ForegroundColor Cyan

foreach ($agName in $validAgs.Keys) {

    Write-Host "`n----- Processing AG $agName -----" -ForegroundColor Cyan
    $agOk = $true

    try {
        $info = $validAgs[$agName]

        $primaryResolved = Resolve-SqlInstance $info.Primary
        $primary         = $primaryResolved.HostName
        $primaryInstance = $primaryResolved.SqlInstance

        # Compare by normalized hostname, not raw string, since
        # .PrimaryReplica and replica .Name values aren't guaranteed to be
        # formatted identically (one may be qualified, the other not).
        $secondaries = $info.Replicas | Where-Object {
            (Resolve-SqlInstance $_).HostName -ne $primary
        }

        if ($effectiveBasePath) {
            $destPath = Join-Path $effectiveBasePath "${agName}_RFC${RFCNumber}"
        }
        else {
            $destPath = "\\$primary\N$\${agName}_RFC${RFCNumber}"
        }

        New-Item -Path $destPath -ItemType Directory -Force -ErrorAction Stop | Out-Null

        Export-AgRollbackPackage `
            -PrimaryInstance $primaryInstance `
            -AgName $agName `
            -OutputFolder $destPath

        $agDatabases = Get-DbaAgDatabase -SqlInstance $primaryInstance -AvailabilityGroup $agName

        # ---- Logging: every replica + every database, before touching anything ----
        $serverInfoBlocks = foreach ($r in $info.Replicas) {
            $rResolved = Resolve-SqlInstance $r
            $role = if ($rResolved.HostName -eq $primary) { "Primary" } else { "Secondary" }

            $b = Get-ServerInfoBlock -SqlInstance $rResolved.SqlInstance -ServerName $rResolved.HostName
            $b["AgRole"] = $role
            $b
        }
        Write-InfoFile -Path (Join-Path $destPath "ServerInfo.txt") -Blocks $serverInfoBlocks -Header "AVAILABILITY GROUP: $agName (Primary: $primary)"

        $dbInfoBlocks = $agDatabases | ForEach-Object {
            $dbObj = Get-DbaDatabase -SqlInstance $primaryInstance -Database $_.Name
            Get-DatabaseInfoBlock -Database $dbObj -AgRole "AG member ($agName)"
        }
        if ($dbInfoBlocks) {
            Write-InfoFile -Path (Join-Path $destPath "ServerInfo.txt") -Blocks $dbInfoBlocks -Header "DATABASES"
        }

        # ---- Per-database: backup -> detach -> clean secondaries -> rename ----
        foreach ($agDb in $agDatabases) {

            $dbName = $agDb.Name

            try {
                if ($PSCmdlet.ShouldProcess($dbName, "Backup on $primary (primary of $agName)")) {
                    $fallbackPath = "\\$primary\N$\${agName}_RFC${RFCNumber}"

                    $backupOk = Invoke-BackupWithFallback `
                        -SqlInstance $primaryInstance `
                        -Database $dbName `
                        -ArchivePath $destPath `
                        -FallbackPath $fallbackPath

                    if (-not $backupOk) {
                        throw "Backup failed for $dbName"
                    }
                }

               if ($PSCmdlet.ShouldProcess($dbName, "Remove from AG $agName")) {
                    Remove-DbaAgDatabase `
                        -SqlInstance $primaryInstance `
                        -AvailabilityGroup $agName `
                        -Database $dbName `
                        -Confirm:$false `
                        -ErrorAction Stop

                    # Verify database is no longer a member of the AG
                    $removed = $false

                    for ($i = 1; $i -le 30; $i++) {

                        Start-Sleep -Seconds 2

                        $stillInAg = Get-DbaAgDatabase `
                            -SqlInstance $primaryInstance `
                            -AvailabilityGroup $agName `
                            -ErrorAction SilentlyContinue |
                            Where-Object Name -eq $dbName

                        if (-not $stillInAg) {
                            $removed = $true
                            break
                        }
                    }

                    if (-not $removed) {
                        throw "Database '$dbName' still appears to belong to AG '$agName' after removal attempt."
                    }

                    Write-Host "[REMOVED] $dbName removed from AG $agName"
                }

                # Detaching only happens on the primary - every secondary is
                # left holding a RESTORING orphan copy under the old name.
                foreach ($sec in $secondaries) {
                    $secInstance = (Resolve-SqlInstance $sec).SqlInstance
                    try {
                        $orphan = Get-DbaDatabase -SqlInstance $secInstance -Database $dbName -ErrorAction SilentlyContinue
                        if ($orphan -and $PSCmdlet.ShouldProcess($dbName, "Drop orphaned secondary copy on $sec")) {
                            Remove-DbaDatabase -SqlInstance $secInstance -Database $dbName -Confirm:$false -ErrorAction Stop
                            Write-Host "[CLEANED] Orphaned copy of $dbName dropped on secondary $sec"
                        }
                    }
                    catch {
                        Write-Warning "[ERROR] Failed to drop orphaned copy of $dbName on secondary ${sec}: $($_.Exception.Message)"
                        $agOk = $false
                    }
                }

                $ok = Invoke-RenameDatabase -SqlInstance $primaryInstance -ServerName $primary -OriginalName $dbName -FailureKey $agName
                if (-not $ok) { $agOk = $false }
            }
            catch {
                Write-Warning "[ERROR] Processing failed for $dbName in $agName : $($_.Exception.Message)"
                if (-not $renameFailures.ContainsKey($agName)) { $renameFailures[$agName] = @() }
                $renameFailures[$agName] += $dbName
                $agOk = $false
            }
        }

        # ---- Leave AG and Listener intact ----
        if ($agOk) {
            Write-Host "[SUCCESS] Databases removed from AG $agName. AG and listener left intact." -ForegroundColor Green
            $processedAgs += $agName
        }
        else {
            Write-Warning "[PARTIAL] $agName had database-level failures."
            $failedAgs += $agName
        }
    }
    catch {
        Write-Warning "[ERROR] AG processing failed for $agName : $($_.Exception.Message)"
        $failedAgs += $agName
    }
}

# ==========================================================
# INVENTORY UPDATE - only mark servers Active = 0 that actually
# completed processing (standalone done, or AG fully torn down).
# ==========================================================
Write-Host "`n===== INVENTORY UPDATE =====" -ForegroundColor Cyan

#$serversToMarkInactive = $processedServers + (
#    $processedAgs | ForEach-Object { $validAgs[$_].Replicas }
#)
$serversToMarkInactive = $processedServers

foreach ($srv in $serversToMarkInactive) {
    try {
        Invoke-DbaQuery -SqlInstance $inventoryInstance -Database dba_inv -SqlParameters @{ srv = $srv } -Query @"
DECLARE @id INT = (SELECT ServerID FROM dba_inv.dbo.Servers WHERE servername = @srv);
IF @id IS NOT NULL
BEGIN
    UPDATE dba_inv.dbo.Servers   SET Active = 0 WHERE ServerID = @id;
    UPDATE dba_inv.dbo.Instances SET Active = 0 WHERE ServerID = @id;
END
"@ -ErrorAction Stop
        Write-Host "[UPDATED] $srv marked inactive"
    }
    catch {
        Write-Warning "[FAILED INVENTORY] $srv : $($_.Exception.Message)"
    }
}

# ==========================================================
# SUMMARY
# ==========================================================
Write-Host "`n===== SUMMARY =====" -ForegroundColor Cyan
Write-Host "RFC                  : $RFCNumber"
Write-Host "Targets as provided  : $($Targets -join ', ')"
Write-Host "Unreachable/unresolved:"
if ($unreachableOrUnresolved) { $unreachableOrUnresolved | ForEach-Object { Write-Host "  - $_" } } else { Write-Host "  (none)" }
Write-Host "Standalone processed : $($processedServers.Count)"
if ($failedServers) { Write-Host "Standalone failed     :"; $failedServers | ForEach-Object { Write-Host "  - $_" } }
Write-Host "AG databases removed : $($processedAgs.Count) ($($processedAgs -join ', '))"
if ($failedAgs) { Write-Host "AGs left in place     :"; $failedAgs | ForEach-Object { Write-Host "  - $_" } }

$anyRenameFailures = $renameFailures.GetEnumerator() | Where-Object { $_.Value.Count -gt 0 }
if ($anyRenameFailures) {
    Write-Host "`nDatabases that failed (require manual follow-up):" -ForegroundColor Yellow
    foreach ($entry in $anyRenameFailures) {
        Write-Host "  $($entry.Key): $($entry.Value -join ', ')"
    }
}

Write-Host "`nTranscript saved to: $transcriptPath"
Stop-Transcript | Out-Null
