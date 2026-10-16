# Shared helpers and run-session state for CUPA SQL decommission.
# Dot-sourced by Decommission-SqlServer.ps1 (and any stage that needs helpers).

. (Join-Path $PSScriptRoot 'Config.ps1')

function Initialize-DecomSession {
    <#
    Sets run-scoped state used by resolve / standalone / AG / inventory modules.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RFCNumber,

        [Parameter(Mandatory)]
        [string[]]$Targets
    )

    $script:DecomRFCNumber = $RFCNumber
    $script:DecomTargets   = @($Targets | Select-Object -Unique)

    if (Test-Path $script:DecomArchiveBasePath) {
        $script:DecomEffectiveBasePath = $script:DecomArchiveBasePath
        Write-Host "[INFO] Using archive share: $($script:DecomArchiveBasePath)" -ForegroundColor Green
    }
    else {
        $script:DecomEffectiveBasePath = $null
        Write-Warning "[WARN] Archive share unavailable: $($script:DecomArchiveBasePath)"
        Write-Warning "[WARN] Backups will use target server N`$ shares."
    }

    New-Item $script:DecomLogDir -ItemType Directory -Force | Out-Null
    $script:DecomTranscriptPath = Join-Path $script:DecomLogDir (
        "Decom_RFC${RFCNumber}_$(Get-Date -Format yyyyMMdd_HHmmss).log"
    )
    Start-Transcript -Path $script:DecomTranscriptPath -Append | Out-Null

    Write-Host "`n[INFO] Initializing for RFC $RFCNumber..." -ForegroundColor Cyan
    Write-Host "[INFO] Targets as provided: $($script:DecomTargets -join ', ')"

    Import-DecomDependencies

    $script:DecomDbatoolsVersion = (Get-Module dbatools).Version.ToString()
    $script:DecomPsVersion       = $PSVersionTable.PSVersion.ToString()
    $script:DecomRunBy           = "$env:USERDOMAIN\$env:USERNAME"

    # Tracking collections used throughout the run
    $script:DecomUnreachableOrUnresolved = [System.Collections.Generic.List[string]]::new()
    $script:DecomResolvedAgs             = @{}   # AgName -> @{ Primary; Replicas; SeedInstance }
    $script:DecomResolvedStandalone      = [System.Collections.Generic.List[string]]::new()
    $script:DecomValidAgs                = @{}
    $script:DecomProcessedServers        = [System.Collections.Generic.List[string]]::new()
    $script:DecomProcessedAgs            = [System.Collections.Generic.List[string]]::new()
    $script:DecomFailedServers           = [System.Collections.Generic.List[string]]::new()
    $script:DecomFailedAgs               = [System.Collections.Generic.List[string]]::new()
    $script:DecomRenameFailures          = @{}   # key (server or AG) -> list of db names
}

function Import-DecomDependencies {
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name dbatools)) {
        Install-Module dbatools -Scope CurrentUser -Force
    }
    Import-Module dbatools

    Set-DbatoolsConfig sql.connection.encrypt $true
    Set-DbatoolsConfig sql.connection.trustcert $true
}

function Resolve-DecomSqlInstance {
    <#
    Normalizes a target name to a plain host name and a full SQL instance
    connection string. Accepts either a bare "server" (the configured
    instance suffix is appended) or an already-qualified "server\instance"
    name (used as-is).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    if ($Name -match '\\') {
        $hostName    = ($Name -split '\\')[0]
        $sqlInstance = $Name
    }
    else {
        $hostName    = $Name
        $sqlInstance = "$Name$($script:DecomInstanceSuffix)"
    }

    [pscustomobject]@{
        HostName    = $hostName
        SqlInstance = $sqlInstance
    }
}

function Get-DecomServerInfoBlock {
    <# Everything worth knowing about a server at decommission time. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SqlInstance,
        [Parameter(Mandatory)][string]$ServerName
    )

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
        RFCNumber         = $script:DecomRFCNumber
        RunBy             = $script:DecomRunBy
        PowerShellVersion = $script:DecomPsVersion
        DbatoolsVersion   = $script:DecomDbatoolsVersion
        Timestamp         = (Get-Date -Format o)
    }
}

function Get-DecomDatabaseInfoBlock {
    <# Per-database detail captured at decommission time. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)][string]$AgRole
    )

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

function Write-DecomInfoFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable[]]$Blocks,
        [Parameter(Mandatory)][string]$Header
    )

    $lines = @("===== $Header =====")
    foreach ($b in $Blocks) {
        $name = if ($b.Contains('ServerName')) { $b.ServerName } else { $b.Name }
        $lines += "--- $name ---"
        foreach ($k in $b.Keys) {
            if ($k -ne 'ServerName' -and $k -ne 'Name') {
                $lines += "  $k`: $($b[$k])"
            }
        }
    }
    $lines | Add-Content $Path -ErrorAction Stop
}

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
}

function Invoke-DecomRenameDatabase {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$SqlInstance,
        [Parameter(Mandatory)][string]$ServerName,
        [Parameter(Mandatory)][string]$OriginalName,
        [Parameter(Mandatory)][string]$FailureKey
    )

    if ($OriginalName -like '*_Decom_RFC*') { return $true }
    $newName = "$OriginalName`_Decom_RFC$($script:DecomRFCNumber)"

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
        Add-DecomFailure -FailureKey $FailureKey -DatabaseName $OriginalName
        return $false
    }
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

function Export-DecomAgRollbackPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrimaryInstance,
        [Parameter(Mandatory)][string]$AgName,
        [Parameter(Mandatory)][string]$OutputFolder
    )

    $txtFile = Join-Path $OutputFolder "AG_Config_${AgName}.txt"
    $sqlFile = Join-Path $OutputFolder "AG_Rollback_${AgName}.sql"

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

    $sql.Add('/*')
    $sql.Add('Rollback/Rebuild Script')
    $sql.Add("RFC: $($script:DecomRFCNumber)")
    $sql.Add("Generated: $(Get-Date)")
    $sql.Add('*/')
    $sql.Add('')

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
    $sql.Add('FOR REPLICA ON')
    $sql.Add(($replicaDefinitions -join ",`r`n"))
    $sql.Add('GO')

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

    Write-Host '[INFO] AG rollback package created:'
    Write-Host "       $txtFile"
    Write-Host "       $sqlFile"
}

function Write-DecomSummary {
    [CmdletBinding()]
    param()

    Write-Host "`n===== SUMMARY =====" -ForegroundColor Cyan
    Write-Host "RFC                  : $($script:DecomRFCNumber)"
    Write-Host "Targets as provided  : $($script:DecomTargets -join ', ')"
    Write-Host 'Unreachable/unresolved:'
    if ($script:DecomUnreachableOrUnresolved.Count -gt 0) {
        $script:DecomUnreachableOrUnresolved | ForEach-Object { Write-Host "  - $_" }
    }
    else {
        Write-Host '  (none)'
    }
    Write-Host "Standalone processed : $($script:DecomProcessedServers.Count)"
    if ($script:DecomFailedServers.Count -gt 0) {
        Write-Host 'Standalone failed     :'
        $script:DecomFailedServers | ForEach-Object { Write-Host "  - $_" }
    }
    Write-Host "AG databases removed : $($script:DecomProcessedAgs.Count) ($($script:DecomProcessedAgs -join ', '))"
    if ($script:DecomFailedAgs.Count -gt 0) {
        Write-Host 'AGs left in place     :'
        $script:DecomFailedAgs | ForEach-Object { Write-Host "  - $_" }
    }

    $anyRenameFailures = $script:DecomRenameFailures.GetEnumerator() | Where-Object { $_.Value.Count -gt 0 }
    if ($anyRenameFailures) {
        Write-Host "`nDatabases that failed (require manual follow-up):" -ForegroundColor Yellow
        foreach ($entry in $anyRenameFailures) {
            Write-Host "  $($entry.Key): $($entry.Value -join ', ')"
        }
    }

    Write-Host "`nTranscript saved to: $($script:DecomTranscriptPath)"
}

function Complete-DecomSession {
    [CmdletBinding()]
    param()

    if ($script:DecomTranscriptPath) {
        try { Stop-Transcript | Out-Null } catch { }
    }
}
