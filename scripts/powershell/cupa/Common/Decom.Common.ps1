# Shared helpers and run-session state for CUPA SQL decommission.
# Dot-sourced by Decommission-SqlServer.ps1 (and any stage that needs helpers).

. (Join-Path $PSScriptRoot 'Config.ps1')

function Initialize-DecomSession {
    <#
    Sets run-scoped state used by resolve / preflight / standalone / AG / inventory modules.

    Hosts are loaded entirely from -HostList (CSV or XLSX). There is no separate -Targets list.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RFCNumber,

        [Parameter(Mandatory)]
        [string]$HostList,

        [string[]]$AvailabilityGroup,
        [switch]$AllAvailabilityGroups,
        [string[]]$ExcludeDatabase,
        [switch]$PlanOnly,
        [switch]$SkipIpValidation,
        [switch]$RequireHostInventory,
        [switch]$ForceIpMismatch
    )

    $script:DecomRFCNumber               = $RFCNumber
    $script:DecomHostListPath            = $HostList
    $script:DecomAvailabilityGroupFilter = @($AvailabilityGroup | Where-Object { $_ })
    $script:DecomAllAvailabilityGroups   = [bool]$AllAvailabilityGroups
    $script:DecomPlanOnly                = [bool]$PlanOnly
    $script:DecomSkipIpValidation        = [bool]$SkipIpValidation
    $script:DecomRequireHostInventory    = [bool]$RequireHostInventory
    $script:DecomForceIpMismatch         = [bool]$ForceIpMismatch

    $script:DecomExcludeDatabases = @(
        $script:DecomExcludeDatabases + @($ExcludeDatabase | Where-Object { $_ }) |
            Select-Object -Unique
    )

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
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $script:DecomTranscriptPath = Join-Path $script:DecomLogDir "Decom_RFC${RFCNumber}_$stamp.log"
    $script:DecomPlanPath       = Join-Path $script:DecomLogDir "DecomPlan_RFC${RFCNumber}_$stamp.json"
    $script:DecomManifestPath   = Join-Path $script:DecomLogDir "DecomManifest_RFC${RFCNumber}_$stamp.json"
    $script:DecomSummaryPath    = Join-Path $script:DecomLogDir "DecomSummary_RFC${RFCNumber}_$stamp.json"

    Start-Transcript -Path $script:DecomTranscriptPath -Append | Out-Null

    Write-Host "`n[INFO] Initializing for RFC $RFCNumber..." -ForegroundColor Cyan
    Write-Host "[INFO] Host list file: $($script:DecomHostListPath)"
    if ($script:DecomPlanOnly) {
        Write-Host '[INFO] PlanOnly mode - no backups/renames/inventory updates will run.' -ForegroundColor Yellow
    }

    Import-DecomDependencies
    Import-DecomHostInventory

    $script:DecomTargets = @(
        $script:DecomHostInventory.Values |
            ForEach-Object { $_.ServerName } |
            Sort-Object -Unique
    )
    Write-Host "[INFO] Loaded $($script:DecomTargets.Count) host(s) from file: $($script:DecomTargets -join ', ')"

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
    $script:DecomIpValidationResults     = [System.Collections.Generic.List[object]]::new()
    $script:DecomPreflightHardFailures   = [System.Collections.Generic.List[string]]::new()
    $script:DecomPreflightWarnings       = [System.Collections.Generic.List[string]]::new()
    $script:DecomHadFailures             = $false

    $script:DecomManifest = [ordered]@{
        RFCNumber          = $RFCNumber
        StartedAt          = (Get-Date -Format o)
        RunBy              = $script:DecomRunBy
        HostList           = $script:DecomHostListPath
        Targets            = $script:DecomTargets
        PlanOnly           = $script:DecomPlanOnly
        ExcludeDatabases   = $script:DecomExcludeDatabases
        Standalone         = [ordered]@{}
        AvailabilityGroups = [ordered]@{}
        Steps              = [System.Collections.Generic.List[object]]::new()
    }
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

function Import-DecomHostListRows {
    <#
    Reads a decom host list from .csv or .xlsx.
    Required columns (aliases accepted):
      ServerName | Hostname | Server | Name
      ExpectedIP | IP | IPAddress | IpAddress
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Host list file not found: $Path"
    }

    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    switch ($ext) {
        '.csv' {
            return @(Import-Csv -LiteralPath $Path)
        }
        '.xlsx' {
            if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
                throw @"
Excel host list '$Path' requires the ImportExcel module.
Install with: Install-Module ImportExcel -Scope CurrentUser
Or save the sheet as CSV (columns ServerName, ExpectedIP) and pass that path to -HostList.
"@
            }
            Import-Module ImportExcel -ErrorAction Stop
            return @(Import-Excel -Path $Path)
        }
        '.xls' {
            throw "Unsupported .xls format. Save as .xlsx or .csv and pass that path to -HostList."
        }
        default {
            throw "Unsupported host list extension '$ext'. Use .csv or .xlsx."
        }
    }
}

function Get-DecomRowProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Row,
        [Parameter(Mandatory)][string[]]$Names
    )

    foreach ($name in $Names) {
        $prop = $Row.PSObject.Properties |
            Where-Object { $_.Name -eq $name -or $_.Name -ieq $name } |
            Select-Object -First 1
        if ($prop -and "$($prop.Value)".Trim()) {
            return "$($prop.Value)".Trim()
        }
    }
    return $null
}

function Import-DecomHostInventory {
    [CmdletBinding()]
    param()

    $script:DecomHostInventory = @{}

    $rows = Import-DecomHostListRows -Path $script:DecomHostListPath
    foreach ($row in $rows) {
        $name = Get-DecomRowProperty -Row $row -Names @('ServerName', 'Hostname', 'Server', 'Name')
        $ip   = Get-DecomRowProperty -Row $row -Names @('ExpectedIP', 'IPAddress', 'IpAddress', 'IP')
        if (-not $name -or -not $ip) { continue }
        $script:DecomHostInventory[$name.ToLowerInvariant()] = [pscustomobject]@{
            ServerName = $name
            ExpectedIP = $ip
        }
    }

    if ($script:DecomHostInventory.Count -eq 0) {
        throw "Host list is empty or missing ServerName/ExpectedIP columns: $($script:DecomHostListPath)"
    }

    Write-Host "[INFO] Loaded $($script:DecomHostInventory.Count) hosts from $($script:DecomHostListPath)"
}

function Get-DecomExpectedIp {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ServerName)

    $key = $ServerName.ToLowerInvariant()
    if ($script:DecomHostInventory.ContainsKey($key)) {
        return $script:DecomHostInventory[$key].ExpectedIP
    }

    # Bidirectional short/FQDN match:
    # - inventory short + lookup FQDN
    # - inventory FQDN + lookup short / different FQDN same host
    $short = ($ServerName -split '\.')[0].ToLowerInvariant()
    if ($script:DecomHostInventory.ContainsKey($short)) {
        return $script:DecomHostInventory[$short].ExpectedIP
    }

    foreach ($entry in $script:DecomHostInventory.GetEnumerator()) {
        $invShort = ($entry.Value.ServerName -split '\.')[0].ToLowerInvariant()
        if ($invShort -eq $short) {
            return $entry.Value.ExpectedIP
        }
    }

    return $null
}

function Test-DecomHostIpIdentity {
    <#
    Resolves ServerName via DNS and compares to ExpectedIP from the decom team inventory.
    Also attempts reverse lookup of the expected IP.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ServerName,
        [string]$ExpectedIP
    )

    $result = [ordered]@{
        ServerName     = $ServerName
        ExpectedIP     = $ExpectedIP
        ResolvedIPs    = @()
        ReverseNames   = @()
        ForwardMatch   = $false
        ReverseMatch   = $false
        InInventory    = [bool]$ExpectedIP
        Status         = 'Unknown'
        Message        = ''
    }

    if (-not $ExpectedIP) {
        $result.Status  = 'MissingInventory'
        $result.Message = "No ExpectedIP in host inventory for '$ServerName'"
        return [pscustomobject]$result
    }

    try {
        $entry = [System.Net.Dns]::GetHostEntry($ServerName)
        $result.ResolvedIPs = @(
            $entry.AddressList |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                ForEach-Object { $_.IPAddressToString }
        )
    }
    catch {
        $result.Status  = 'DnsFailed'
        $result.Message = "DNS forward lookup failed for '$ServerName': $($_.Exception.Message)"
        return [pscustomobject]$result
    }

    $result.ForwardMatch = ($ExpectedIP -in $result.ResolvedIPs)

    try {
        $rev = [System.Net.Dns]::GetHostEntry($ExpectedIP)
        $names = @($rev.HostName) + @($rev.Aliases)
        $result.ReverseNames = @($names | Where-Object { $_ } | Select-Object -Unique)
        $short = ($ServerName -split '\.')[0]
        $result.ReverseMatch = [bool](
            $result.ReverseNames | Where-Object {
                $_ -eq $ServerName -or
                $_ -like "$ServerName.*" -or
                $_ -eq $short -or
                $_ -like "$short.*"
            }
        )
    }
    catch {
        $result.ReverseNames = @()
        $result.ReverseMatch = $false
    }

    if ($result.ForwardMatch) {
        $result.Status = if ($result.ReverseMatch) { 'Ok' } else { 'OkForwardOnly' }
        $result.Message = "Forward DNS for '$ServerName' includes ExpectedIP $ExpectedIP"
        if (-not $result.ReverseMatch) {
            $result.Message += ' (reverse lookup did not confirm hostname)'
        }
    }
    else {
        $result.Status  = 'Mismatch'
        $resolved = if ($result.ResolvedIPs) { $result.ResolvedIPs -join ', ' } else { '(none)' }
        $result.Message = "IP mismatch for '$ServerName': expected $ExpectedIP, DNS has $resolved"
    }

    return [pscustomobject]$result
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

function Test-DecomSqlConnection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SqlInstance)

    try {
        Connect-DbaInstance -SqlInstance $SqlInstance -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        Write-Warning "[WARN] SQL connect failed for $SqlInstance : $($_.Exception.Message)"
        return $false
    }
}

function Test-DecomExcludedDatabase {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    if ($Name -like '*_Decom_RFC*') { return $true }
    foreach ($ex in $script:DecomExcludeDatabases) {
        if ($Name -eq $ex) { return $true }
    }
    return $false
}

function Get-DecomServerInfoBlock {
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
        ExpectedIP        = (Get-DecomExpectedIp -ServerName $ServerName)
        RFCNumber         = $script:DecomRFCNumber
        RunBy             = $script:DecomRunBy
        PowerShellVersion = $script:DecomPsVersion
        DbatoolsVersion   = $script:DecomDbatoolsVersion
        Timestamp         = (Get-Date -Format o)
    }
}

function Get-DecomDatabaseInfoBlock {
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

function Export-DecomAgConfiguration {
    <#
    Rich AG configuration backup (Approach A):
      - AG_Config_{Ag}.json  structured inventory
      - AG_Config_{Ag}.txt   human-readable
      - AG_Rollback_{Ag}.sql rebuild script with fuller replica options
    Returns $true only when all three artifacts exist and JSON parses.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrimaryInstance,
        [Parameter(Mandatory)][string]$AgName,
        [Parameter(Mandatory)][string]$OutputFolder
    )

    $configDir = Join-Path $OutputFolder 'AgConfig'
    New-Item -Path $configDir -ItemType Directory -Force | Out-Null

    $jsonFile = Join-Path $configDir "AG_Config_${AgName}.json"
    $txtFile  = Join-Path $configDir "AG_Config_${AgName}.txt"
    $sqlFile  = Join-Path $configDir "AG_Rollback_${AgName}.sql"

    $agObj    = Get-DbaAvailabilityGroup -SqlInstance $PrimaryInstance -AvailabilityGroup $AgName
    $replicas = @(Get-DbaAgReplica -SqlInstance $PrimaryInstance -AvailabilityGroup $AgName)
    $agDbs    = @(Get-DbaAgDatabase -SqlInstance $PrimaryInstance -AvailabilityGroup $AgName)
    $listeners = @(Get-DbaAgListener -SqlInstance $PrimaryInstance -AvailabilityGroup $AgName -ErrorAction SilentlyContinue)

    $listenerQuery = @"
SELECT
    l.dns_name,
    l.port,
    l.is_conformant,
    ip.ip_address,
    ip.ip_subnet_mask AS subnet_mask,
    ip.state_desc,
    ip.type_desc
FROM sys.availability_group_listeners l
INNER JOIN sys.availability_group_listener_ip_addresses ip
    ON l.listener_id = ip.listener_id
INNER JOIN sys.availability_groups ag
    ON ag.group_id = l.group_id
WHERE ag.name = @AgName;
"@

    $listenerRows = @(
        Invoke-DbaQuery `
            -SqlInstance $PrimaryInstance `
            -Database master `
            -Query $listenerQuery `
            -SqlParameters @{ AgName = $AgName }
    )

    # Prefer STRING_AGG (SQL 2017+); fall back to FOR XML PATH for older engines.
    $routingQueryModern = @"
SELECT
    ar.replica_server_name,
    ar.secondary_role_allow_connections_desc,
    ar.session_timeout,
    ar.seeding_mode_desc,
    ar.read_only_routing_url,
    (
        SELECT STRING_AGG(ror.routing_replica_server_name, ', ')
        WITHIN GROUP (ORDER BY ror.routing_priority)
        FROM sys.availability_read_only_routing_lists ror
        WHERE ror.replica_id = ar.replica_id
    ) AS read_only_routing_list
FROM sys.availability_replicas ar
INNER JOIN sys.availability_groups ag ON ag.group_id = ar.group_id
WHERE ag.name = @AgName;
"@

    $routingQueryLegacy = @"
SELECT
    ar.replica_server_name,
    ar.secondary_role_allow_connections_desc,
    ar.session_timeout,
    ar.seeding_mode_desc,
    ar.read_only_routing_url,
    STUFF((
        SELECT ', ' + ror.routing_replica_server_name
        FROM sys.availability_read_only_routing_lists ror
        WHERE ror.replica_id = ar.replica_id
        ORDER BY ror.routing_priority
        FOR XML PATH(''), TYPE
    ).value('.', 'nvarchar(max)'), 1, 2, '') AS read_only_routing_list
FROM sys.availability_replicas ar
INNER JOIN sys.availability_groups ag ON ag.group_id = ar.group_id
WHERE ag.name = @AgName;
"@

    $routingRows = @()
    try {
        $routingRows = @(
            Invoke-DbaQuery `
                -SqlInstance $PrimaryInstance `
                -Database master `
                -Query $routingQueryModern `
                -SqlParameters @{ AgName = $AgName }
        )
    }
    catch {
        try {
            $routingRows = @(
                Invoke-DbaQuery `
                    -SqlInstance $PrimaryInstance `
                    -Database master `
                    -Query $routingQueryLegacy `
                    -SqlParameters @{ AgName = $AgName }
            )
        }
        catch {
            Write-Warning "[WARN] Could not capture read-only routing details: $($_.Exception.Message)"
        }
    }

    $replicaConfigs = foreach ($rep in $replicas) {
        $route = $routingRows | Where-Object { $_.replica_server_name -eq $rep.Name } | Select-Object -First 1
        [ordered]@{
            Name                         = $rep.Name
            Role                         = "$($rep.Role)"
            AvailabilityMode             = "$($rep.AvailabilityMode)"
            FailoverMode                 = "$($rep.FailoverMode)"
            EndpointUrl                  = "$($rep.EndpointUrl)"
            BackupPriority               = $rep.BackupPriority
            SessionTimeout               = if ($route) { $route.session_timeout } else { $null }
            SeedingMode                  = if ($route) { "$($route.seeding_mode_desc)" } else { "$($rep.SeedingMode)" }
            SecondaryRoleAllowConnections = if ($route) { "$($route.secondary_role_allow_connections_desc)" } else { $null }
            ReadOnlyRoutingUrl           = if ($route) { "$($route.read_only_routing_url)" } else { $null }
            ReadOnlyRoutingList          = if ($route) { "$($route.read_only_routing_list)" } else { $null }
        }
    }

    $config = [ordered]@{
        AvailabilityGroup = $AgName
        CapturedAt        = (Get-Date -Format o)
        RFCNumber         = $script:DecomRFCNumber
        PrimaryInstance   = $PrimaryInstance
        PrimaryReplica    = "$($agObj.PrimaryReplica)"
        ClusterType       = "$($agObj.ClusterType)"
        BasicAvailabilityGroup = "$($agObj.BasicAvailabilityGroup)"
        Replicas          = @($replicaConfigs)
        Databases         = @(
            $agDbs | ForEach-Object {
                [ordered]@{
                    Name                 = $_.Name
                    SynchronizationState = "$($_.SynchronizationState)"
                    IsSuspended          = $_.IsSuspended
                }
            }
        )
        Listeners         = @(
            $listenerRows | ForEach-Object {
                [ordered]@{
                    DnsName    = $_.dns_name
                    Port       = $_.port
                    IpAddress  = $_.ip_address
                    SubnetMask = $_.subnet_mask
                    State      = $_.state_desc
                    Type       = $_.type_desc
                }
            }
        )
        DbatoolsListeners = @(
            $listeners | ForEach-Object {
                [ordered]@{
                    Name = $_.Name
                    Port = $_.PortNumber
                }
            }
        )
    }

    $config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonFile -Encoding UTF8

    @"
Availability Group : $AgName
Generated          : $(Get-Date)
Primary            : $($agObj.PrimaryReplica)
ClusterType        : $($agObj.ClusterType)

===== REPLICAS =====

$($replicaConfigs | ForEach-Object { $_ | Out-String } | Out-String)

===== DATABASES =====

$($agDbs | Format-Table Name, SynchronizationState, IsSuspended -AutoSize | Out-String)

===== LISTENERS =====

$($listenerRows | Format-Table -AutoSize | Out-String)
"@ | Set-Content -LiteralPath $txtFile -Encoding UTF8

    $sql = New-Object System.Collections.Generic.List[string]
    $sql.Add('/*')
    $sql.Add('AG configuration rebuild script (review before use)')
    $sql.Add("RFC: $($script:DecomRFCNumber)")
    $sql.Add("Generated: $(Get-Date)")
    $sql.Add('NOTE: Endpoints, certificates, permissions, and database data movement are NOT included.')
    $sql.Add('*/')
    $sql.Add('')
    $sql.Add(@"
IF EXISTS (SELECT 1 FROM sys.availability_groups WHERE name = N'$AgName')
BEGIN
    DROP AVAILABILITY GROUP [$AgName];
END
GO
"@)

    $replicaDefinitions = foreach ($rep in $replicaConfigs) {
        $seed = if ($rep.SeedingMode) { ",`r`n    SEEDING_MODE = $($rep.SeedingMode)" } else { '' }
        $session = if ($rep.SessionTimeout) { ",`r`n    SESSION_TIMEOUT = $($rep.SessionTimeout)" } else { '' }
        $secondaryConn = if ($rep.SecondaryRoleAllowConnections) {
            ",`r`n    SECONDARY_ROLE (ALLOW_CONNECTIONS = $($rep.SecondaryRoleAllowConnections))"
        } else { '' }

        @"
N'$($rep.Name)'
WITH (
    ENDPOINT_URL = N'$($rep.EndpointUrl)',
    FAILOVER_MODE = $($rep.FailoverMode),
    AVAILABILITY_MODE = $($rep.AvailabilityMode),
    BACKUP_PRIORITY = $($rep.BackupPriority)$session$seed$secondaryConn
)
"@
    }

    $sql.Add("CREATE AVAILABILITY GROUP [$AgName]")
    $sql.Add('FOR REPLICA ON')
    $sql.Add(($replicaDefinitions -join ",`r`n"))
    $sql.Add('GO')

    foreach ($listener in $listenerRows) {
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

    $sql.Add('')
    $sql.Add('/* Re-add databases after restoring data to every replica:')
    foreach ($db in $agDbs) {
        $sql.Add("ALTER AVAILABILITY GROUP [$AgName] ADD DATABASE [$($db.Name)];")
    }
    $sql.Add('*/')

    $sql | Set-Content -LiteralPath $sqlFile -Encoding UTF8

    # Gate: all artifacts must exist and JSON must parse
    foreach ($f in @($jsonFile, $txtFile, $sqlFile)) {
        if (-not (Test-Path -LiteralPath $f) -or (Get-Item -LiteralPath $f).Length -le 0) {
            Write-Warning "[ERROR] AG config artifact missing/empty: $f"
            return $false
        }
    }

    try {
        Get-Content -LiteralPath $jsonFile -Raw | ConvertFrom-Json | Out-Null
    }
    catch {
        Write-Warning "[ERROR] AG config JSON failed to parse: $jsonFile"
        return $false
    }

    Write-Host '[INFO] AG configuration backup created:'
    Write-Host "       $jsonFile"
    Write-Host "       $txtFile"
    Write-Host "       $sqlFile"
    return $true
}

# Back-compat alias used by older call sites
function Export-DecomAgRollbackPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrimaryInstance,
        [Parameter(Mandatory)][string]$AgName,
        [Parameter(Mandatory)][string]$OutputFolder
    )

    Export-DecomAgConfiguration -PrimaryInstance $PrimaryInstance -AgName $AgName -OutputFolder $OutputFolder
}

function Write-DecomSummary {
    [CmdletBinding()]
    param()

    Write-Host "`n===== SUMMARY =====" -ForegroundColor Cyan
    Write-Host "RFC                  : $($script:DecomRFCNumber)"
    Write-Host "Host list file       : $($script:DecomHostListPath)"
    Write-Host "Hosts from file      : $($script:DecomTargets -join ', ')"
    Write-Host "PlanOnly             : $($script:DecomPlanOnly)"
    Write-Host 'Unreachable/unresolved:'
    if ($script:DecomUnreachableOrUnresolved.Count -gt 0) {
        $script:DecomUnreachableOrUnresolved | ForEach-Object { Write-Host "  - $_" }
    }
    else {
        Write-Host '  (none)'
    }

    Write-Host 'IP validation:'
    if ($script:DecomIpValidationResults.Count -eq 0) {
        Write-Host '  (not run / skipped)'
    }
    else {
        foreach ($r in $script:DecomIpValidationResults) {
            $color = switch ($r.Status) {
                'Ok'             { 'Green' }
                'OkForwardOnly'  { 'Yellow' }
                default          { 'Red' }
            }
            Write-Host "  [$($r.Status)] $($r.ServerName) expected=$($r.ExpectedIP) dns=$($r.ResolvedIPs -join '|')" -ForegroundColor $color
        }
    }

    if ($script:DecomPreflightHardFailures.Count -gt 0) {
        Write-Host 'Preflight hard failures:' -ForegroundColor Red
        $script:DecomPreflightHardFailures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    }

    Write-Host "Standalone processed : $($script:DecomProcessedServers.Count)"
    if ($script:DecomFailedServers.Count -gt 0) {
        Write-Host 'Standalone failed     :'
        $script:DecomFailedServers | ForEach-Object { Write-Host "  - $_" }
    }
    Write-Host "AG databases removed : $($script:DecomProcessedAgs.Count) ($($script:DecomProcessedAgs -join ', '))"
    if ($script:DecomFailedAgs.Count -gt 0) {
        Write-Host 'AGs failed / skipped  :'
        $script:DecomFailedAgs | ForEach-Object { Write-Host "  - $_" }
    }

    $anyRenameFailures = $script:DecomRenameFailures.GetEnumerator() | Where-Object { $_.Value.Count -gt 0 }
    if ($anyRenameFailures) {
        Write-Host "`nDatabases that failed (require manual follow-up):" -ForegroundColor Yellow
        foreach ($entry in $anyRenameFailures) {
            Write-Host "  $($entry.Key): $($entry.Value -join ', ')"
        }
    }

    $summary = [ordered]@{
        RFCNumber            = $script:DecomRFCNumber
        PlanOnly             = $script:DecomPlanOnly
        HadFailures          = [bool]$script:DecomHadFailures
        Unreachable          = @($script:DecomUnreachableOrUnresolved)
        IpValidation         = @($script:DecomIpValidationResults)
        PreflightHardFailures = @($script:DecomPreflightHardFailures)
        ProcessedServers     = @($script:DecomProcessedServers)
        FailedServers        = @($script:DecomFailedServers)
        ProcessedAgs         = @($script:DecomProcessedAgs)
        FailedAgs            = @($script:DecomFailedAgs)
        RenameFailures       = $script:DecomRenameFailures
        PlanPath             = $script:DecomPlanPath
        ManifestPath         = $script:DecomManifestPath
        TranscriptPath       = $script:DecomTranscriptPath
        FinishedAt           = (Get-Date -Format o)
    }

    $summary | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $script:DecomSummaryPath -Encoding UTF8

    Write-Host "`nPlan      : $($script:DecomPlanPath)"
    Write-Host "Manifest  : $($script:DecomManifestPath)"
    Write-Host "Summary   : $($script:DecomSummaryPath)"
    Write-Host "Transcript: $($script:DecomTranscriptPath)"
}

function Complete-DecomSession {
    [CmdletBinding()]
    param()

    if ($script:DecomTranscriptPath) {
        try { Stop-Transcript | Out-Null } catch { }
    }
}

function Get-DecomExitCode {
    [CmdletBinding()]
    param()

    # Preflight aborts first (documented exit 2), even though those also set HadFailures.
    if ($script:DecomPreflightHardFailures.Count -gt 0) { return 2 }
    if ($script:DecomHadFailures) { return 1 }
    if ($script:DecomFailedServers.Count -gt 0 -or $script:DecomFailedAgs.Count -gt 0) { return 1 }
    if ($script:DecomUnreachableOrUnresolved.Count -gt 0) { return 3 }
    return 0
}
