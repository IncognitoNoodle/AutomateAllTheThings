<#
.SYNOPSIS
    Shared helpers for the SQL service-account password playbook (dot-source .ps1).

.DESCRIPTION
    Learned from production ApplySqlServiceAccountPassword / RotateSqlServiceAccount:
    topology discovery (standalone + AG), domain account detection, AD unlock /
    never-expire, slow ValidateCredentials waits (mgmt + per-node), SPN listing,
    Update-DbaServiceAccount -NoRestart, AG sync wait, and graceful restart order.

    Dot-source from each stage (not Import-Module):
      . (Join-Path $PSScriptRoot 'Common\SqlServiceAccount.Common.ps1')
#>

$script:SsaCommonRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $script:SsaCommonRoot 'Config.ps1')

$script:ServiceTypes = @($script:SsaServiceTypes)
$script:DomainDnsSuffixCache = $null
$script:SqlHostDnsCache = @{}

function Get-SsaServiceTypes {
    return @($script:ServiceTypes)
}

function Resolve-SsaOutputFolder {
    param([string]$OutputFolder)
    if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
        $OutputFolder = $script:SsaDefaultOutputFolder
    }
    Initialize-SsaOutputFolder -OutputFolder $OutputFolder
}

function Add-SsaFinding {
    param(
        [Parameter(Mandatory)][System.Collections.IList]$Findings,
        [Parameter(Mandatory)][ValidateSet('Critical', 'Warning', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Item,
        [Parameter(Mandatory)][string]$Detail,
        [Parameter(Mandatory)][string]$Action
    )
    $Findings.Add([pscustomobject]@{
            Severity = $Severity
            Area     = $Area
            Item     = $Item
            Detail   = $Detail
            Action   = $Action
        }) | Out-Null
}

function Show-SsaFindings {
    param(
        [Parameter(Mandatory)][System.Collections.IList]$Findings,
        [string]$EmptyMessage = 'No issues found.'
    )
    if ($Findings.Count -eq 0) {
        Write-Host $EmptyMessage -ForegroundColor Green
        return 0
    }
    # Out-Host: Format-* must not enter the success stream. Assigning Format-Table
    # to $critCount then doing $critCount -gt 0 throws NotIcomparable (FormatStartData).
    $Findings |
        Sort-Object @{ Expression = { switch ($_.Severity) { 'Critical' { 0 } 'Warning' { 1 } default { 2 } } } }, Area, Item |
        Format-Table Severity, Area, Item, Detail, Action -Wrap -AutoSize |
        Out-Host
    return [int](@($Findings | Where-Object Severity -eq 'Critical').Count)
}

function Resolve-SsaNodeList {
    param(
        [string[]]$ComputerName,
        [string]$OutputFolder,
        [string]$SqlInstance,
        [string[]]$AvailabilityGroup,
        [PSCredential]$Credential,
        [PSCredential]$SqlCredential
    )

    $nodes = @($ComputerName | Where-Object { $_ } | Sort-Object -Unique)
    if ($nodes) { return $nodes }

    if ($OutputFolder) {
        $disc = Read-SsaDiscovery -OutputFolder $OutputFolder
        if ($disc -and $disc.Nodes) {
            $nodes = @($disc.Nodes.ComputerName | Sort-Object -Unique)
            if ($nodes) {
                Write-Host "Using nodes from discovery-latest.json: $($nodes -join ', ')" -ForegroundColor DarkCyan
                return $nodes
            }
        }
    }

    if ($SqlInstance) {
        $topo = Get-TargetTopology -SqlInstance $SqlInstance -AvailabilityGroup $AvailabilityGroup `
            -SqlCredential $SqlCredential -Credential $Credential
        $nodes = @($topo.Nodes.ComputerName | Sort-Object -Unique)
        Write-Host "Using nodes from topology ($($topo.Mode)): $($nodes -join ', ')" -ForegroundColor DarkCyan
        return $nodes
    }

    @()
}

function Save-SsaStageState {
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Stage,
        [Parameter(Mandatory)]$State
    )
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $latest = Join-Path $OutputFolder ("{0}-latest.json" -f $Stage)
    $archive = Join-Path $OutputFolder ("{0}-{1}.json" -f $Stage, $stamp)
    $json = ($State | ConvertTo-Json -Depth 8)
    Set-Content -LiteralPath $latest -Value $json -Encoding UTF8
    Set-Content -LiteralPath $archive -Value $json -Encoding UTF8
    Write-Host "  State saved: $latest" -ForegroundColor DarkCyan
    return $latest
}

function Read-SsaStageState {
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][string]$Stage
    )
    $latest = Join-Path $OutputFolder ("{0}-latest.json" -f $Stage)
    if (-not (Test-Path -LiteralPath $latest)) { return $null }
    Get-Content -LiteralPath $latest -Raw | ConvertFrom-Json
}

function Invoke-SsaAgFailover {
    param(
        [Parameter(Mandatory)][string]$TargetSqlInstance,
        [Parameter(Mandatory)][string[]]$AgNames,
        [PSCredential]$SqlCredential
    )
    $fo = @{
        SqlInstance       = $TargetSqlInstance
        AvailabilityGroup = $AgNames
        Confirm           = $false
        EnableException   = $true
    }
    if ($SqlCredential) { $fo.SqlCredential = $SqlCredential }
    Invoke-DbaAgFailover @fo | Out-Null
}

function Invoke-SsaGracefulAgRestart {
    param(
        [Parameter(Mandatory)][object[]]$Nodes,
        [Parameter(Mandatory)][string[]]$AgNames,
        [Parameter(Mandatory)][string]$OriginalPrimary,
        [Parameter(Mandatory)][string[]]$ServiceType,
        [PSCredential]$Credential,
        [PSCredential]$SqlCredential,
        [int]$SyncTimeoutSeconds = 300,
        [string[]]$Account,
        [hashtable]$AccountPassword,
        [switch]$Failback
    )

    $bySql = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $Nodes) { $bySql[$n.SqlInstance] = $n }

    $primarySql = $OriginalPrimary
    if (-not $bySql.ContainsKey($primarySql)) {
        $mapped = $Nodes | Where-Object {
            (Test-ReplicaMatch -ReplicaName $primarySql -SqlInstance $_.SqlInstance) -or
            (Test-ComputerNameMatch -Left $_.ComputerName -Right ($primarySql.Split('\')[0]))
        } | Select-Object -First 1
        if (-not $mapped) { throw "Could not map primary '$primarySql' to discovered nodes." }
        $primarySql = $mapped.SqlInstance
    }
    $primary = $bySql[$primarySql]
    $secondary = $Nodes | Where-Object { $_.SqlInstance -ne $primarySql } | Select-Object -First 1
    if (-not $secondary) { throw 'AG mode requires at least two replicas.' }

    Write-Host "`n=== AG graceful restart (failback default: OFF) ===" -ForegroundColor Cyan
    Write-Host "Primary:   $($primary.SqlInstance) [$($primary.ComputerName)]" -ForegroundColor Cyan
    Write-Host "Secondary: $($secondary.SqlInstance) [$($secondary.ComputerName)]" -ForegroundColor Cyan
    Write-Host 'Order: secondary restart -> sync -> failover -> former primary restart -> sync' -ForegroundColor Yellow

    Restart-SqlTargetService -Computer $secondary.ComputerName -SqlInstance $secondary.SqlInstance -Type $ServiceType `
        -Credential (Get-RemoteCredential -Computer $secondary.ComputerName -Credential $Credential) `
        -SqlCredential $SqlCredential -Account $Account -AccountPassword $AccountPassword
    Wait-SqlTargetServiceRunning -Computer $secondary.ComputerName -SqlInstance $secondary.SqlInstance -Type $ServiceType `
        -Credential (Get-RemoteCredential -Computer $secondary.ComputerName -Credential $Credential) `
        -SqlCredential $SqlCredential -TimeoutSeconds ([Math]::Min(180, $SyncTimeoutSeconds))
    Wait-AgReady -SqlInstance $primary.SqlInstance -AgNames $AgNames -SecondarySqlInstance $secondary.SqlInstance `
        -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds

    Write-Host "  Failover -> $($secondary.SqlInstance)" -ForegroundColor Cyan
    Invoke-SsaAgFailover -TargetSqlInstance $secondary.SqlInstance -AgNames $AgNames -SqlCredential $SqlCredential
    Start-Sleep -Seconds 3
    Wait-AgReady -SqlInstance $secondary.SqlInstance -AgNames $AgNames -SecondarySqlInstance $primary.SqlInstance `
        -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds

    Restart-SqlTargetService -Computer $primary.ComputerName -SqlInstance $primary.SqlInstance -Type $ServiceType `
        -Credential (Get-RemoteCredential -Computer $primary.ComputerName -Credential $Credential) `
        -SqlCredential $SqlCredential -Account $Account -AccountPassword $AccountPassword
    Wait-SqlTargetServiceRunning -Computer $primary.ComputerName -SqlInstance $primary.SqlInstance -Type $ServiceType `
        -Credential (Get-RemoteCredential -Computer $primary.ComputerName -Credential $Credential) `
        -SqlCredential $SqlCredential -TimeoutSeconds ([Math]::Min(180, $SyncTimeoutSeconds))
    Wait-AgReady -SqlInstance $secondary.SqlInstance -AgNames $AgNames -SecondarySqlInstance $primary.SqlInstance `
        -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds

    $currentPrimary = $secondary.SqlInstance
    if ($Failback) {
        Write-Host "  Failback -> $($primary.SqlInstance)" -ForegroundColor Cyan
        Invoke-SsaAgFailover -TargetSqlInstance $primary.SqlInstance -AgNames $AgNames -SqlCredential $SqlCredential
        Wait-AgReady -SqlInstance $primary.SqlInstance -AgNames $AgNames -SecondarySqlInstance $secondary.SqlInstance `
            -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds
        $currentPrimary = $primary.SqlInstance
        Write-Host "  Primary restored on $($primary.SqlInstance)." -ForegroundColor Green
    } else {
        Write-Host "  Done. Primary is now on $($secondary.SqlInstance) (no failback)." -ForegroundColor Green
    }

    [pscustomobject]@{
        OriginalPrimary = $primary.SqlInstance
        CurrentPrimary  = $currentPrimary
        Secondary       = $secondary.SqlInstance
        FailedBack      = [bool]$Failback
    }
}

function Write-SsaBanner {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor Cyan
}

function Initialize-SsaOutputFolder {
    param([Parameter(Mandatory)][string]$OutputFolder)
    if ($OutputFolder -match 'SERVERNAME' -or [string]::IsNullOrWhiteSpace($OutputFolder)) {
        throw @"
OutputFolder is not configured.
Pass -OutputFolder or edit CONFIG, e.g.:
  -OutputFolder '\\YourFileServer\Share\SqlServiceAccountRotation\'
Current value: $OutputFolder
"@
    }
    if (-not (Test-Path -LiteralPath $OutputFolder)) {
        New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
    }
    return (Resolve-Path -LiteralPath $OutputFolder).Path
}

function Import-SsaDependencies {
    param(
        [switch]$InstallModule,
        [switch]$NeedActiveDirectory,
        [switch]$PreferActiveDirectory
    )

    if (-not (Get-Module -ListAvailable -Name dbatools)) {
        if (-not $InstallModule) { throw 'dbatools missing. Install it or pass -InstallModule.' }
        Install-Module dbatools -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module dbatools -ErrorAction Stop
    Set-DbatoolsConfig -FullName sql.connection.encrypt -Value $true
    Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true

    $wantAd = $NeedActiveDirectory -or $PreferActiveDirectory
    if ($wantAd) {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            if ($NeedActiveDirectory) {
                throw 'ActiveDirectory module (RSAT) is required for this stage.'
            }
            Write-Warning 'ActiveDirectory module not available; AD unlock/status checks will be skipped.'
            return
        }
        Import-Module ActiveDirectory -ErrorAction Stop
    }
}

function Test-IsLocalComputerName {
    param([string]$ComputerName)
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return $true }
    $short = ($ComputerName -split '\.')[0]
    $local = @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
    return ($ComputerName -in $local) -or ($short -eq $env:COMPUTERNAME)
}

function Test-ComputerNameMatch {
    param([string]$Left, [string]$Right)
    if (-not $Left -or -not $Right) { return $false }
    if ($Left -eq $Right) { return $true }
    (($Left -split '\.')[0] -eq ($Right -split '\.')[0])
}

function Test-IsDomainServiceAccount {
    param([string]$StartName, [string]$ForComputer)

    if ([string]::IsNullOrWhiteSpace($StartName)) { return @{ Ok = $false; Reason = 'empty' } }
    if ($StartName -match '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\)') {
        return @{ Ok = $false; Reason = 'built-in' }
    }
    if ($StartName -match '\$$') { return @{ Ok = $false; Reason = 'gMSA' } }
    if ($StartName -match '^[^\\]+@[^\\]+$') { return @{ Ok = $true; Reason = $null } }
    if ($StartName -notmatch '\\') { return @{ Ok = $false; Reason = 'local/bare name' } }

    $local = $StartName -match "^$([regex]::Escape($ForComputer))\\|^\.\\"
    if ($local) { return @{ Ok = $false; Reason = 'local user' } }
    @{ Ok = $true; Reason = $null }
}

function Get-RemoteCredential {
    param([string]$Computer, [PSCredential]$Credential)
    if ($Credential -and -not (Test-IsLocalComputerName $Computer)) { return $Credential }
    $null
}

function Test-DnsNameResolve {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    try {
        $null = [System.Net.Dns]::GetHostAddresses($Name)
        return $true
    } catch {
        return $false
    }
}

function Get-DomainDnsSuffixCandidate {
    if ($null -ne $script:DomainDnsSuffixCache) { return @($script:DomainDnsSuffixCache) }

    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $suffixes = [System.Collections.Generic.List[string]]::new()
    $addSuffix = {
        param($s)
        if ([string]::IsNullOrWhiteSpace($s)) { return }
        $t = $s.Trim().TrimStart('.').TrimEnd('.')
        if ($t -and $seen.Add($t)) { [void]$suffixes.Add($t) }
    }

    try {
        $ipProps = [System.Net.FAKESECRET_o2p3q4r5s6t7u8v9w0x1]::GetIPGlobalProperties()
        & $addSuffix $ipProps.DomainName
    } catch { $null = $_ }

    try {
        $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        & $addSuffix $dom.Name
        foreach ($t in @($dom.GetAllTrustRelationships())) { & $addSuffix $t.TargetName }
        $forest = $dom.Forest
        & $addSuffix $forest.Name
        foreach ($t in @($forest.GetAllTrustRelationships())) { & $addSuffix $t.TargetName }
        foreach ($d in @($forest.Domains)) { & $addSuffix $d.Name }
    } catch { $null = $_ }

    try {
        if (Get-Command Get-ADForest -ErrorAction SilentlyContinue) {
            $f = Get-ADForest -ErrorAction Stop
            & $addSuffix $f.Name
            foreach ($d in @($f.Domains)) { & $addSuffix $d }
            foreach ($u in @($f.UPNSuffixes)) { & $addSuffix $u }
        }
    } catch { $null = $_ }

    $script:DomainDnsSuffixCache = @($suffixes)
    return @($script:DomainDnsSuffixCache)
}

function Get-SqlHostFqdn {
    param([string]$SqlInstance, [PSCredential]$SqlCredential)
    if ([string]::IsNullOrWhiteSpace($SqlInstance)) { return $null }
    if ($script:SqlHostDnsCache.ContainsKey($SqlInstance)) {
        return $script:SqlHostDnsCache[$SqlInstance]
    }
    if (-not (Get-Command Invoke-DbaQuery -ErrorAction SilentlyContinue)) { return $null }

    $fqdn = $null
    try {
        $q = @'
DECLARE @domain nvarchar(256);
EXEC master.dbo.xp_regread
    N'HKEY_LOCAL_MACHINE',
    N'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
    N'Domain',
    @domain OUTPUT;
SELECT
    CAST(SERVERPROPERTY('MachineName') AS nvarchar(128)) AS MachineName,
    @domain AS DnsDomain;
'@
        $p = @{
            SqlInstance     = $SqlInstance
            Query           = $q
            EnableException = $true
            ErrorAction     = 'Stop'
        }
        if ($SqlCredential) { $p.SqlCredential = $SqlCredential }
        $row = @(Invoke-DbaQuery @p) | Select-Object -First 1
        if ($row -and $row.MachineName -and $row.DnsDomain) {
            $fqdn = '{0}.{1}' -f ([string]$row.MachineName).Trim(), ([string]$row.DnsDomain).Trim().TrimStart('.')
        }
    } catch {
        $null = $_
    }

    $script:SqlHostDnsCache[$SqlInstance] = $fqdn
    return $fqdn
}

function Resolve-RemoteComputerTarget {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [string]$SqlInstance,
        [PSCredential]$SqlCredential,
        [PSCredential]$Credential
    )

    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $names = [System.Collections.Generic.List[string]]::new()
    $add = {
        param($n, $requireDns)
        if ([string]::IsNullOrWhiteSpace($n)) { return }
        $t = $n.Trim().TrimEnd('.')
        if (-not $t) { return }
        if ($requireDns -and ($t -match '\.') -and -not (Test-DnsNameResolve $t)) { return }
        if ($seen.Add($t)) { [void]$names.Add($t) }
    }

    $raw = $ComputerName.Trim()
    $short = ($raw -split '\.')[0]

    if ($SqlInstance) {
        $sqlFqdn = Get-SqlHostFqdn -SqlInstance $SqlInstance -SqlCredential $SqlCredential
        if ($sqlFqdn) { & $add $sqlFqdn $true }
    }

    if (Get-Command Resolve-DbaNetworkName -ErrorAction SilentlyContinue) {
        try {
            $rp = @{ ComputerName = $raw; ErrorAction = 'Stop' }
            if ($Credential) { $rp.Credential = $Credential }
            $resolved = Resolve-DbaNetworkName @rp
            foreach ($item in @($resolved)) {
                foreach ($prop in @('FQDN', 'DNSHostEntry', 'FullComputerName')) {
                    $v = [string]$item.$prop
                    if ($v -match '\.') { & $add $v $true }
                }
                $dnsHost = [string]$item.DNSHostName
                $dnsDom = [string]$item.DNSDomain
                if (-not $dnsDom) { $dnsDom = [string]$item.Domain }
                if ($dnsHost -and $dnsDom -and ($dnsDom -match '\.')) {
                    & $add ('{0}.{1}' -f $dnsHost, $dnsDom.TrimStart('.')) $true
                }
            }
        } catch { $null = $_ }
    }

    try {
        $entry = [System.Net.Dns]::GetHostEntry($raw)
        if ($entry.HostName -match '\.') { & $add $entry.HostName $false }
    } catch { $null = $_ }

    if ($short -notmatch '\.') {
        foreach ($suffix in @(Get-DomainDnsSuffixCandidate)) {
            & $add ('{0}.{1}' -f $short, $suffix) $true
        }
    }

    & $add $raw $false
    if ($short -and ($short -ne $raw)) { & $add $short $false }

    $fqdns = @($names | Where-Object { $_ -match '\.' })
    $rest = @($names | Where-Object { $_ -notmatch '\.' })
    return @($fqdns + $rest)
}

function Test-WinRmComputerNameFailure {
    param([string]$Message)
    [bool]($Message -match 'WinRM|unknown to Kerberos|Cannot find the computer|is unknown to Kerberos|SPN with the format HTTP/')
}

function Initialize-DbaCmWinRm {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [string]$SqlInstance,
        [PSCredential]$SqlCredential
    )
    if (Test-IsLocalComputerName $ComputerName) { return }
    if (-not (Get-Command New-DbaCmConnection -ErrorAction SilentlyContinue)) { return }
    if (-not (Get-Command New-CimSessionOption -ErrorAction SilentlyContinue)) { return }

    foreach ($t in @(Resolve-RemoteComputerTarget -ComputerName $ComputerName -SqlInstance $SqlInstance -SqlCredential $SqlCredential -Credential $Credential)) {
        try {
            $opt = New-CimSessionOption -Protocol WSMan -Authentication Negotiate
            $p = @{
                ComputerName    = $t
                CimWinRMOptions = $opt
                EnableException = $true
                Confirm         = $false
            }
            if ($Credential) { $p.Credential = $Credential }
            else { $p.UseWindowsCredentials = $true }
            $null = New-DbaCmConnection @p
        } catch {
            $null = $_
        }
    }
}

function Get-NodeComputer {
    param(
        [string]$Instance,
        [PSCredential]$Credential,
        [PSCredential]$SqlCredential
    )
    $targets = @(Resolve-RemoteComputerTarget -ComputerName (($Instance -split '\\')[0]) `
            -SqlInstance $Instance -SqlCredential $SqlCredential -Credential $Credential)
    $preferred = @($targets | Where-Object { $_ -match '\.' } | Select-Object -First 1)
    if ($preferred) { return $preferred[0] }
    if ($targets) { return $targets[0] }
    throw "Could not resolve computer name for $Instance"
}

function Test-SqlOfflineMessage {
    param([string]$Message)
    # Includes dbatools ConnectionError: "The remote computer refused the network connection"
    [bool]($Message -match
        'cannot connect|connection.*failed|network.?related|timeout|timed out|error: 40|error: 53|error: 2|' +
        'not allow remote|login failed|unable to complete login|server is not found|does not exist|' +
        'No connection could be made|actively refused|refused the network connection|connection refused|' +
        'The wait operation timed out|Failed to connect|ConnectionError|physical connection is not usable|' +
        'A network-related|Named Pipes Provider|TCP Provider|error: 0|dbatools_Get-DbaAvailabilityGroup|' +
        'The target principal name is incorrect|Cannot generate SSPI|Login timeout expired|' +
        'SQL Server does not exist|error 26|error 40|could not open a connection')
}

function New-SsaOfflineTopology {
    param(
        [string]$SqlInstance,
        [string[]]$ComputerName,
        [string[]]$AvailabilityGroup,
        [string]$Reason
    )

    $computers = @($ComputerName | Where-Object { $_ } | ForEach-Object { $_.Trim() } | Sort-Object -Unique)
    if (-not $computers -and $SqlInstance) {
        $computers = @(($SqlInstance.Split('\')[0]).Trim())
    }
    if (-not $computers) {
        throw 'Offline topology needs -ComputerName and/or -SqlInstance (host).'
    }

    $instPart = $null
    if ($SqlInstance -and $SqlInstance -match '\\') {
        $instPart = $SqlInstance.Split('\')[1]
    }

    $nodes = foreach ($c in $computers) {
        $sqlLabel = if ($instPart) {
            '{0}\{1}' -f $c, $instPart
        } elseif ($SqlInstance -and (Test-ComputerNameMatch -Left $c -Right ($SqlInstance.Split('\')[0]))) {
            $SqlInstance
        } else {
            $c
        }
        [pscustomobject]@{
            ComputerName = $c
            SqlInstance  = $sqlLabel
            Role         = 'Offline'
        }
    }

    $agNames = @($AvailabilityGroup | Where-Object { $_ } | Sort-Object -Unique)
    $mode = if ($agNames -or $nodes.Count -gt 1) { 'AvailabilityGroup' } else { 'Standalone' }
    $primary = if ($SqlInstance) { $SqlInstance } else { [string]$nodes[0].SqlInstance }

    Write-Warning ("SQL offline topology ({0}). Mode={1}; nodes={2}. Services need not be Running; WinRM/CIM used for account discovery/apply." -f `
            $Reason, $mode, (($nodes.ComputerName) -join ', '))
    if ($mode -eq 'AvailabilityGroup' -and $nodes.Count -lt 2) {
        Write-Warning 'Offline AG path has fewer than 2 nodes. Pass every replica with -ComputerName so stage 03 updates all service caches.'
    }

    [pscustomobject]@{
        Mode            = $mode
        Nodes           = @($nodes)
        AgNames         = $agNames
        OriginalPrimary = $primary
        Offline         = $true
        OfflineReason   = $Reason
    }
}

function Get-TargetTopology {
    param(
        [string]$SqlInstance,
        [string[]]$AvailabilityGroup,
        [string[]]$ComputerName,
        [string]$OutputFolder,
        [PSCredential]$SqlCredential,
        [PSCredential]$Credential,
        # When SQL Engine is stopped (expired password RTS), inventory via WinRM.
        [switch]$AllowOffline
    )

    $explicitComputers = @($ComputerName | Where-Object { $_ } | Sort-Object -Unique)
    # -ComputerName means WinRM-only inventory (SQL may be stopped / password expired).
    if ($explicitComputers.Count -gt 0) {
        return New-SsaOfflineTopology -SqlInstance $SqlInstance -ComputerName $explicitComputers `
            -AvailabilityGroup $AvailabilityGroup -Reason 'explicit -ComputerName (SQL need not be Running)'
    }

    if (-not $SqlInstance) {
        if ($OutputFolder) {
            $disc = Read-SsaDiscovery -OutputFolder $OutputFolder
            if ($disc -and $disc.Nodes) {
                return New-SsaOfflineTopology -SqlInstance ([string]$disc.OriginalPrimary) `
                    -ComputerName @($disc.Nodes.ComputerName) `
                    -AvailabilityGroup $(if ($AvailabilityGroup) { $AvailabilityGroup } else { @($disc.AgNames) }) `
                    -Reason 'discovery-latest.json (no -SqlInstance)'
            }
        }
        throw 'Get-TargetTopology requires -SqlInstance and/or -ComputerName.'
    }

    $agParams = @{
        SqlInstance     = $SqlInstance
        EnableException = $true
        WarningAction   = 'SilentlyContinue'
        ErrorAction     = 'Stop'
    }
    if ($SqlCredential) { $agParams.SqlCredential = $SqlCredential }
    if ($AvailabilityGroup) { $agParams.AvailabilityGroup = $AvailabilityGroup }

    $ags = @()
    try {
        $ags = @(Get-DbaAvailabilityGroup @agParams)
    } catch {
        $msg = [string]$_
        if ($msg -match 'HADR|Availability Group|not configured|is not enabled') {
            if ($AvailabilityGroup) {
                throw "Instance $SqlInstance has no HADR/AG configured, but -AvailabilityGroup was specified."
            }
            $ags = @()
        } elseif (Test-SqlOfflineMessage $msg) {
            # Engine stopped / expired logon / network - normal return-to-service path.
            $offlineNodes = $explicitComputers
            if (-not $offlineNodes -and $OutputFolder) {
                $disc = Read-SsaDiscovery -OutputFolder $OutputFolder
                if ($disc -and $disc.Nodes) {
                    $offlineNodes = @($disc.Nodes.ComputerName | Sort-Object -Unique)
                    if (-not $AvailabilityGroup -and $disc.AgNames) {
                        $AvailabilityGroup = @($disc.AgNames)
                    }
                }
            }
            if (-not $offlineNodes) { $offlineNodes = @(($SqlInstance.Split('\')[0])) }
            return New-SsaOfflineTopology -SqlInstance $SqlInstance -ComputerName $offlineNodes `
                -AvailabilityGroup $AvailabilityGroup -Reason ("SQL unreachable: " + $msg.Split("`n")[0])
        } else {
            throw
        }
    }

    if (-not $ags) {
        $computer = $null
        try {
            $computer = Get-NodeComputer -Instance $SqlInstance -Credential $Credential -SqlCredential $SqlCredential
        } catch {
            if (Test-SqlOfflineMessage ([string]$_) -or $AllowOffline -or $explicitComputers) {
                $fallback = if ($explicitComputers) { $explicitComputers } else { @(($SqlInstance.Split('\')[0])) }
                return New-SsaOfflineTopology -SqlInstance $SqlInstance -ComputerName $fallback `
                    -AvailabilityGroup $AvailabilityGroup -Reason 'standalone host resolve failed; WinRM-only'
            }
            throw
        }
        return [pscustomobject]@{
            Mode            = 'Standalone'
            Nodes           = @([pscustomobject]@{ ComputerName = $computer; SqlInstance = $SqlInstance; Role = 'Standalone' })
            AgNames         = @()
            OriginalPrimary = $SqlInstance
            Offline         = $false
        }
    }

    $agNames = @($ags.Name | Select-Object -Unique)
    $primaryName = [string]$ags[0].PrimaryReplicaServerName
    $replicaSql = @($ags | ForEach-Object { $_.AvailabilityReplicas.Name } | Select-Object -Unique)
    if ($replicaSql.Count -lt 1) { throw "AGs found ($($agNames -join ', ')) but no replicas." }

    $nodes = foreach ($rep in $replicaSql) {
        $role = if (Test-ReplicaMatch -ReplicaName $rep -SqlInstance $primaryName) { 'Primary' } else { 'Secondary' }
        [pscustomobject]@{
            ComputerName = (Get-NodeComputer -Instance $rep -Credential $Credential -SqlCredential $SqlCredential)
            SqlInstance  = $rep
            Role         = $role
        }
    }
    $nodes = @($nodes | Group-Object ComputerName | ForEach-Object { $_.Group | Select-Object -First 1 })

    [pscustomobject]@{
        Mode            = 'AvailabilityGroup'
        Nodes           = $nodes
        AgNames         = $agNames
        OriginalPrimary = $primaryName
        Offline         = $false
    }
}

function Test-ReplicaMatch {
    param([string]$ReplicaName, [string]$SqlInstance)
    if (-not $ReplicaName -or -not $SqlInstance) { return $false }
    if ($ReplicaName -eq $SqlInstance) { return $true }
    $r = $ReplicaName.Split('\'); $s = $SqlInstance.Split('\')
    if ($r[0] -ne $s[0]) { return $false }
    if ($r.Count -eq 1 -and $s.Count -eq 1) { return $true }
    if ($r.Count -gt 1 -and $s.Count -gt 1) { return $r[1] -eq $s[1] }
    $true
}

function Get-SqlTargetService {
    param(
        [object[]]$Nodes,
        [string[]]$InstanceName,
        [string[]]$Type = $script:ServiceTypes,
        [PSCredential]$Credential,
        [PSCredential]$SqlCredential
    )

    $all = foreach ($node in $Nodes) {
        $svcCred = Get-RemoteCredential -Computer $node.ComputerName -Credential $Credential
        Initialize-DbaCmWinRm -ComputerName $node.ComputerName -Credential $svcCred `
            -SqlInstance $node.SqlInstance -SqlCredential $SqlCredential
        $got = $null
        $lastErr = $null
        foreach ($t in @(Resolve-RemoteComputerTarget -ComputerName $node.ComputerName `
                    -SqlInstance $node.SqlInstance -SqlCredential $SqlCredential -Credential $svcCred)) {
            try {
                $gp = @{
                    ComputerName    = $t
                    Type            = $Type
                    EnableException = $true
                }
                if ($svcCred) { $gp.Credential = $svcCred }
                $got = @(Get-DbaService @gp)
                # Normalize ComputerName to our topology name
                foreach ($s in $got) {
                    if (-not $s.ComputerName) { $s | Add-Member -NotePropertyName ComputerName -NotePropertyValue $node.ComputerName -Force }
                    else { $s.ComputerName = $node.ComputerName }
                }
                break
            } catch {
                $lastErr = $_
                if (Test-WinRmComputerNameFailure ([string]$_)) {
                    Write-Host ("  Get-DbaService WinRM failed on {0}; trying next name..." -f $t) -ForegroundColor DarkYellow
                    continue
                }
                throw
            }
        }
        if ($null -eq $got) {
            if ($lastErr) { throw $lastErr }
            continue
        }
        $got
    }
    $all = @($all)
    if (-not $InstanceName) { return $all }

    $all | Where-Object {
        $svcType = [string]$_.ServiceType
        ($svcType -in @('SSRS', 'SSIS')) -or ($_.InstanceName -in $InstanceName)
    }
}

function Get-DomainSqlServiceAccount {
    param([object[]]$Services)

    $domainServices = foreach ($svc in @($Services)) {
        $check = Test-IsDomainServiceAccount -StartName $svc.StartName -ForComputer $svc.ComputerName
        if (-not $check.Ok) {
            Write-Host ("Skip {0}\{1} ({2}): {3}" -f $svc.ComputerName, $svc.ServiceName, $svc.StartName, $check.Reason) -ForegroundColor Yellow
            continue
        }
        $svc
    }

    @($domainServices) | Group-Object StartName | ForEach-Object {
        [pscustomobject]@{
            Account      = $_.Name
            ServiceCount = $_.Count
            Computers    = (@($_.Group.ComputerName | Sort-Object -Unique) -join ', ')
            Services     = (@($_.Group | ForEach-Object { "$($_.ComputerName)\$($_.ServiceName)[$($_.ServiceType)]" } | Sort-Object) -join ', ')
            ServiceTypes = (@($_.Group | ForEach-Object { [string]$_.ServiceType } | Sort-Object -Unique) -join ', ')
            Group        = $_.Group
        }
    } | Sort-Object Account
}

function Get-AccountSam {
    param([string]$Account)
    $sam = $Account.Split('\')[-1]
    if ($sam -match '@') { $sam = $sam.Split('@')[0] }
    $sam
}

function Get-ServiceAccountSpn {
    param([Parameter(Mandatory)][string]$Account)

    $sam = Get-AccountSam -Account $Account
    $setspnTarget = if ($Account -match '\\') { $Account } else { $sam }
    $spns = @()
    $raw = $null
    $method = 'none'

    # Preferred: setspn -L (matches ops runbook)
    try {
        $raw = & setspn.exe -L $setspnTarget 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -or ($raw -and $raw -notmatch 'failed|error|cannot')) {
            $spns = @(
                $raw -split "`r?`n" |
                    ForEach-Object { $_.Trim() } |
                    Where-Object { $_ -and $_ -notmatch '^(Registered|The domain|Finding|CN=)' -and $_ -match '/' }
            )
            $method = 'setspn'
        }
    } catch {
        $raw = [string]$_
    }

    if (-not $spns -and (Get-Module -ListAvailable -Name ActiveDirectory)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $u = Get-ADUser -Identity $sam -Properties servicePrincipalName -ErrorAction Stop
            $spns = @($u.servicePrincipalName | Where-Object { $_ })
            $method = 'Get-ADUser'
            $raw = ($spns -join "`n")
        } catch {
            if (-not $raw) { $raw = [string]$_ }
        }
    }

    [pscustomobject]@{
        Account     = $Account
        SamAccount  = $sam
        Method      = $method
        SpnCount    = $spns.Count
        Spns        = $spns
        RawOutput   = $raw
        HasMssqlSpn = [bool]($spns | Where-Object { $_ -match '^MSSQLSvc/' })
        HasHttpSpn  = [bool]($spns | Where-Object { $_ -match '^HTTP/' })
    }
}

function Get-AdServiceAccountStatus {
    param([Parameter(Mandatory)][string]$Account)

    $sam = Get-AccountSam -Account $Account
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        return [pscustomobject]@{
            Account = $Account; SamAccount = $sam; Available = $false
            Message = 'ActiveDirectory module not available'
        }
    }

    Import-Module ActiveDirectory -ErrorAction Stop
    $u = Get-ADUser -Identity $sam -Properties LockedOut, PasswordExpired, PasswordNeverExpires,
        AccountExpirationDate, Enabled, PasswordLastSet, LastBadPasswordAttempt, badPwdCount,
        TrustedForDelegation, ServicePrincipalName -ErrorAction Stop

    [pscustomobject]@{
        Account                 = $Account
        SamAccount              = $sam
        Available               = $true
        Enabled                 = [bool]$u.Enabled
        LockedOut               = [bool]$u.LockedOut
        PasswordExpired         = [bool]$u.PasswordExpired
        PasswordNeverExpires    = [bool]$u.PasswordNeverExpires
        AccountExpirationDate   = $u.AccountExpirationDate
        PasswordLastSet         = $u.PasswordLastSet
        LastBadPasswordAttempt  = $u.LastBadPasswordAttempt
        BadPwdCount             = $u.badPwdCount
        DistinguishedName       = $u.DistinguishedName
    }
}

function Clear-AdServiceAccountExpiration {
    param([string]$Account)
    $sam = Get-AccountSam -Account $Account
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { return }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adUser = Get-ADUser -Identity $sam -Properties AccountExpirationDate -ErrorAction Stop
        $exp = $adUser.AccountExpirationDate
        if ($exp) {
            Write-Warning "  AD account $sam has AccountExpirationDate=$exp - Clear-ADAccountExpiration"
            Clear-ADAccountExpiration -Identity $sam -ErrorAction Stop
            Start-Sleep -Seconds 2
        }
    } catch {
        $null = $_
    }
}

function Unlock-AdServiceAccount {
    param([string]$Account)
    $sam = Get-AccountSam -Account $Account
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { return }
    Clear-AdServiceAccountExpiration -Account $Account
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adUser = Get-ADUser -Identity $sam -Properties LockedOut -ErrorAction Stop
        if ($adUser.LockedOut) {
            Write-Warning "  AD account $sam is locked out - unlocking"
            Unlock-ADAccount -Identity $sam -ErrorAction Stop
            Start-Sleep -Seconds 2
        }
    } catch {
        $null = $_
    }
}

function Set-AdServiceAccountPasswordPolicy {
    param(
        [Parameter(Mandatory)][string]$Account,
        [switch]$PasswordNeverExpires
    )
    $sam = Get-AccountSam -Account $Account
    Import-Module ActiveDirectory -ErrorAction Stop
    Clear-AdServiceAccountExpiration -Account $Account
    if ($PasswordNeverExpires) {
        Write-Host "  AD: Set-ADUser $sam -PasswordNeverExpires `$true" -ForegroundColor DarkCyan
        Set-ADUser -Identity $sam -PasswordNeverExpires $true -ErrorAction Stop
    }
}

function Reset-DomainAccountPassword {
    param(
        [Parameter(Mandatory)][string]$Account,
        [Parameter(Mandatory)][securestring]$SecurePassword
    )
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "Domain account '$Account' needs Set-ADAccountPassword, but ActiveDirectory module is missing."
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    $sam = Get-AccountSam -Account $Account
    Unlock-AdServiceAccount -Account $Account
    Write-Host "  AD: Set-ADAccountPassword $sam -Reset" -ForegroundColor DarkCyan
    Set-ADAccountPassword -Identity $sam -NewPassword $SecurePassword -Reset -ErrorAction Stop
}

function Resolve-AdAuthDomain {
    param([string]$Account)
    if ($Account -match '@') { return $Account.Split('@')[-1] }
    $netbios = if ($Account -match '\\') { $Account.Split('\')[0] } else { $env:USERDOMAIN }
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $d = Get-ADDomain -Identity $netbios -ErrorAction Stop
            if ($d.DNSRoot) { return [string]$d.DNSRoot }
        } catch {
            $null = $_
        }
    }
    return $netbios
}

function Test-AdCredentialHere {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PlainPassword')]
    param([string]$Domain, [string]$SamAccountName, [string]$PlainPassword)
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop

    $opts = [DirectoryServices.AccountManagement.ContextOptions]::Negotiate -bor
        [DirectoryServices.AccountManagement.ContextOptions]::Signing -bor
        [DirectoryServices.AccountManagement.ContextOptions]::Sealing

    $users = [System.Collections.Generic.List[string]]::new()
    [void]$users.Add($SamAccountName)
    if ($SamAccountName -notmatch '\\|@') {
        [void]$users.Add(('{0}\{1}' -f $Domain, $SamAccountName))
    }

    foreach ($user in $users) {
        $ctx = [DirectoryServices.AccountManagement.PrincipalContext]::new(
            [DirectoryServices.AccountManagement.ContextType]::Domain,
            $Domain
        )
        try {
            if ($ctx.ValidateCredentials($user, $PlainPassword, $opts)) { return $true }
            if ($ctx.ValidateCredentials($user, $PlainPassword)) { return $true }
        } catch {
            $null = $_
        } finally {
            $ctx.Dispose()
        }
    }
    return $false
}

function Wait-AdCredentialReady {
    param(
        [string]$Account,
        [securestring]$SecurePassword,
        [int]$TimeoutSeconds = 180,
        [int]$RequiredSuccesses = 2,
        [int]$PollSeconds = 5
    )

    $sam = Get-AccountSam -Account $Account
    $domain = Resolve-AdAuthDomain -Account $Account
    $plain = [Net.NetworkCredential]::new('', $SecurePassword).Password
    $started = Get-Date
    $deadline = $started.AddSeconds($TimeoutSeconds)
    $successes = 0
    $attempt = 0
    Write-Host "  AD (mgmt host): waiting for $Account via ValidateCredentials ($domain\$sam) (up to ${TimeoutSeconds}s)" -ForegroundColor DarkCyan

    do {
        $attempt++
        $elapsed = [int]((Get-Date) - $started).TotalSeconds
        $left = [Math]::Max(0, $TimeoutSeconds - $elapsed)
        try {
            Unlock-AdServiceAccount -Account $Account
            if (Test-AdCredentialHere -Domain $domain -SamAccountName $sam -PlainPassword $plain) {
                $successes++
                Write-Host "  AD (mgmt host): OK for $Account ($successes/$RequiredSuccesses) after ${elapsed}s" -ForegroundColor Green
                if ($successes -ge $RequiredSuccesses) { return }
            } else {
                $successes = 0
                Write-Host "  AD (mgmt host): not ready for $Account (attempt $attempt, ${elapsed}s elapsed, ${left}s left)" -ForegroundColor DarkYellow
            }
        } catch {
            $successes = 0
            Write-Host ("  AD (mgmt host) wait error for {0} (attempt {1}, {2}s): {3}" -f $Account, $attempt, $elapsed, $_) -ForegroundColor DarkYellow
        }
        Start-Sleep -Seconds $PollSeconds
    } while ((Get-Date) -lt $deadline)

    throw @"
AD password for '$Account' not accepted on management host within ${TimeoutSeconds}s ($attempt attempts).
Check: account lockout, wrong domain NETBIOS vs DNS, jump-box DC lag, or password mismatch.
"@
}

function Test-AdCredentialOnComputer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PlainPassword')]
    param(
        [string]$Computer,
        [string]$Account,
        [string]$PlainPassword,
        [PSCredential]$Credential
    )

    $sam = Get-AccountSam -Account $Account
    $domain = Resolve-AdAuthDomain -Account $Account
    if (Test-IsLocalComputerName $Computer) {
        return Test-AdCredentialHere -Domain $domain -SamAccountName $sam -PlainPassword $PlainPassword
    }

    $sb = {
        param($Domain, $Sam, $SecretText)
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        $opts = [System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate -bor
            [System.DirectoryServices.AccountManagement.ContextOptions]::Signing -bor
            [System.DirectoryServices.AccountManagement.ContextOptions]::Sealing
        $users = @($Sam)
        if ($Sam -notmatch '\\|@') { $users += ('{0}\{1}' -f $Domain, $Sam) }
        foreach ($user in $users) {
            $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
                [System.DirectoryServices.AccountManagement.ContextType]::Domain,
                $Domain
            )
            try {
                if ($ctx.ValidateCredentials($user, $SecretText, $opts)) { return $true }
                if ($ctx.ValidateCredentials($user, $SecretText)) { return $true }
            } catch {
                $null = $_
            } finally {
                $ctx.Dispose()
            }
        }
        return $false
    }

    $targets = @(Resolve-RemoteComputerTarget -ComputerName $Computer)
    $lastErr = $null
    foreach ($target in $targets) {
        try {
            $ic = @{
                ComputerName   = $target
                ScriptBlock    = $sb
                ArgumentList   = @($domain, $sam, $PlainPassword)
                ErrorAction    = 'Stop'
                Authentication = 'Negotiate'
            }
            if ($Credential) { $ic.Credential = $Credential }
            return [bool](Invoke-Command @ic)
        } catch {
            $lastErr = $_
            if (Test-WinRmComputerNameFailure ([string]$_)) {
                Write-Host "  WinRM AD check via $target failed; trying next name..." -ForegroundColor DarkYellow
            }
        }
    }
    if ($lastErr) { throw $lastErr }
    return $false
}

function Wait-AdCredentialReadyOnNode {
    param(
        [string]$Account,
        [securestring]$SecurePassword,
        [string[]]$ComputerName,
        [PSCredential]$Credential,
        [int]$TimeoutSeconds = 3600,
        [int]$PollSeconds = 300
    )

    $nodes = @($ComputerName | Where-Object { $_ } | Sort-Object -Unique)
    if ($nodes.Count -eq 0) { return }

    $plain = [Net.NetworkCredential]::new('', $SecurePassword).Password
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    Write-Host ("  AD (SQL nodes): waiting for {0} on {1} (up to {2}s, poll every {3}s)" -f $Account, ($nodes -join ', '), $TimeoutSeconds, $PollSeconds) -ForegroundColor DarkCyan

    $pending = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $nodes) { [void]$pending.Add($n) }

    do {
        Unlock-AdServiceAccount -Account $Account
        foreach ($node in @($pending)) {
            try {
                $svcCred = Get-RemoteCredential -Computer $node -Credential $Credential
                if (Test-AdCredentialOnComputer -Computer $node -Account $Account -PlainPassword $plain -Credential $svcCred) {
                    Write-Host "  AD (SQL node): OK for $Account @ $node" -ForegroundColor Green
                    [void]$pending.Remove($node)
                } else {
                    Write-Host "  AD (SQL node): not ready for $Account @ $node" -ForegroundColor DarkYellow
                }
            } catch {
                Write-Host ("  AD (SQL node) wait @ {0}: {1}" -f $node, $_) -ForegroundColor DarkYellow
            }
        }
        if ($pending.Count -eq 0) { return }
        $left = [Math]::Max(0, [int]($deadline - (Get-Date)).TotalSeconds)
        if ($left -le 0) { break }
        $sleepFor = [Math]::Min($PollSeconds, $left)
        Write-Host ("  AD (SQL nodes): sleeping {0}s before next check ({1}s left)" -f $sleepFor, $left) -ForegroundColor DarkYellow
        Start-Sleep -Seconds $sleepFor
    } while ((Get-Date) -lt $deadline)

    throw @"
AD password for '$Account' not accepted on SQL node(s): $($pending -join ', ') within ${TimeoutSeconds}s.
Site DC may not have replicated yet. Unlock if locked, wait, re-run stage 02 -WaitOnly.
Do not restart SQL until node checks pass.
"@
}

function Resolve-AccountPasswordMap {
    param([string[]]$Account, [SecureString[]]$SecurePassword)

    if ($Account.Count -ne $SecurePassword.Count) {
        throw "-Account count ($($Account.Count)) must match -SecurePassword count ($($SecurePassword.Count))."
    }

    $map = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
    for ($i = 0; $i -lt $Account.Count; $i++) {
        $name = $Account[$i]
        if ([string]::IsNullOrWhiteSpace($name)) { throw "-Account[$i] is empty." }
        if (-not $SecurePassword[$i] -or $SecurePassword[$i].Length -lt 1) {
            throw "-SecurePassword for '$name' is empty."
        }
        if ($map.ContainsKey($name)) { throw "Duplicate -Account entry: $name" }
        $map[$name] = $SecurePassword[$i]
    }
    $map
}

function Get-SsaServiceTypeRank {
    param([string]$ServiceType)
    switch ([string]$ServiceType) {
        'Engine' { 0 }
        'Agent' { 1 }
        'SSRS' { 2 }
        'SSIS' { 3 }
        default { 9 }
    }
}

function Get-SsaRestartTypeOrder {
    param([string[]]$Type)
    $Type = @($Type | Where-Object { $_ } | Sort-Object -Unique)
    $preferred = @('Engine', 'Agent', 'SSRS', 'SSIS')
    $ordered = @($preferred | Where-Object { $_ -in $Type })
    $ordered += @($Type | Where-Object { $_ -notin $preferred })
    return $ordered
}

function Update-NodeServicePassword {
    param(
        [object[]]$Services,
        [securestring]$SecurePassword,
        [PSCredential]$Credential,
        [string]$SqlInstance,
        [PSCredential]$SqlCredential
    )
    # One service at a time, Engine before Agent - bulk Update-DbaServiceAccount
    # can return empty/partial results and leave SQL Agent on the old password.
    $ordered = @(
        $Services | Sort-Object @{ Expression = { Get-SsaServiceTypeRank $_.ServiceType } }, ServiceName
    )
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($svc in $ordered) {
        $computer = [string]$svc.ComputerName
        $svcName = [string]$svc.ServiceName
        $svcType = [string]$svc.ServiceType
        Initialize-DbaCmWinRm -ComputerName $computer -Credential $Credential `
            -SqlInstance $SqlInstance -SqlCredential $SqlCredential

        $updated = $false
        $lastErr = $null
        foreach ($t in @(Resolve-RemoteComputerTarget -ComputerName $computer `
                    -SqlInstance $SqlInstance -SqlCredential $SqlCredential -Credential $Credential)) {
            try {
                # Prefer the resolved name for WinRM; keep topology ComputerName on the object.
                $svc.ComputerName = $t
                $p = @{
                    InputObject     = $svc
                    SecurePassword  = $SecurePassword
                    NoRestart       = $true
                    Confirm         = $false
                    EnableException = $true
                }
                if ($Credential) { $p.Credential = $Credential }
                $chunk = @(Update-DbaServiceAccount @p)
                $svc.ComputerName = $computer
                if ($chunk.Count -eq 0) {
                    $lastErr = "Update-DbaServiceAccount returned no result for $svcName"
                    Write-Host "  Update empty @ ${t}\${svcName}; trying next name..." -ForegroundColor DarkYellow
                    continue
                }
                foreach ($row in $chunk) {
                    if (-not $row.ComputerName) {
                        $row | Add-Member -NotePropertyName ComputerName -NotePropertyValue $computer -Force
                    } else {
                        $row.ComputerName = $computer
                    }
                    $results.Add($row)
                }
                $updated = $true
                Write-Host ("  Updated {0}\{1} [{2}] via {3}" -f $computer, $svcName, $svcType, $t) -ForegroundColor DarkCyan
                break
            } catch {
                $svc.ComputerName = $computer
                $lastErr = $_
                if (Test-WinRmComputerNameFailure ([string]$_)) {
                    Write-Host ("  Update-DbaServiceAccount WinRM failed on {0}\{1}; trying next name..." -f $t, $svcName) -ForegroundColor DarkYellow
                    continue
                }
                throw
            }
        }

        if (-not $updated) {
            $msg = if ($lastErr) { [string]$lastErr } else { "No WinRM target worked for $computer\$svcName" }
            $results.Add([pscustomobject]@{
                    ComputerName = $computer
                    ServiceName  = $svcName
                    ServiceType  = $svcType
                    Status       = 'Failed'
                    Message      = $msg
                })
        }
    }

    return @($results)
}

function Test-RestartAuthFailure {
    param([object[]]$Results)
    $text = @(
        $Results | ForEach-Object {
            @($_.Status, $_.State, $_.Message, $_.ServiceName) -join ' '
        }
    ) -join ' | '
    # "dependent service" is Engine-not-ready timing (Agent), not a bad password.
    return [bool]($text -match 'authentication|logon failure|correct authentication|password|credentials')
}

function Test-RestartDependencyFailure {
    param([object[]]$Results, [string]$ErrorText)
    $text = @(
        $Results | ForEach-Object {
            @($_.Status, $_.State, $_.Message, $_.ServiceName) -join ' '
        }
    ) -join ' | '
    if ($ErrorText) { $text = "$text | $ErrorText" }
    return [bool]($text -match 'dependent service|dependency|cannot start|start pending|marked for deletion')
}

function Wait-AdAfterAuthFailure {
    param(
        [string[]]$Account,
        [hashtable]$AccountPassword,
        [string]$Computer,
        [PSCredential]$Credential
    )
    Write-Warning "  Auth/logon failure suspected - unlock, re-check AD on node, retry"
    foreach ($acct in @($Account)) {
        if (-not $acct) { continue }
        Unlock-AdServiceAccount -Account $acct
        if ($AccountPassword -and $AccountPassword.ContainsKey($acct)) {
            Wait-AdCredentialReadyOnNode -Account $acct -SecurePassword $AccountPassword[$acct] `
                -ComputerName $Computer -Credential $Credential -TimeoutSeconds 600 -PollSeconds 300
        }
    }
}

function Get-SsaInstanceNameFromSqlInstance {
    param([string]$SqlInstance)
    if ([string]::IsNullOrWhiteSpace($SqlInstance)) { return $null }
    if ($SqlInstance -notmatch '\\') { return $null }
    $name = $SqlInstance.Split('\')[-1]
    if ([string]::IsNullOrWhiteSpace($name) -or $name -eq '.') { return $null }
    return $name
}

function Get-SsaServiceSnapshot {
    param(
        [string[]]$Targets,
        [string]$Type,
        [string]$InstanceName,
        [PSCredential]$Credential
    )
    foreach ($t in $Targets) {
        try {
            $gp = @{
                ComputerName    = $t
                Type            = $Type
                EnableException = $true
                ErrorAction     = 'Stop'
            }
            if ($InstanceName) { $gp.InstanceName = $InstanceName }
            if ($Credential) { $gp.Credential = $Credential }
            $svcs = @(Get-DbaService @gp)
            return [pscustomobject]@{ Target = $t; Services = $svcs }
        } catch {
            if (Test-WinRmComputerNameFailure ([string]$_)) { continue }
            throw
        }
    }
    return [pscustomobject]@{ Target = $null; Services = @() }
}

function Invoke-SsaServiceStartOrRestart {
    param(
        [string]$ComputerTarget,
        [string]$Type,
        [string]$InstanceName,
        [string]$Action, # Start | Restart
        [PSCredential]$Credential
    )
    $p = @{
        ComputerName    = $ComputerTarget
        Type            = $Type
        Force           = $true
        Confirm         = $false
        EnableException = $true
    }
    if ($InstanceName) { $p.InstanceName = $InstanceName }
    if ($Credential) { $p.Credential = $Credential }

    if ($Action -eq 'Start') {
        if (-not (Get-Command Start-DbaService -ErrorAction SilentlyContinue)) {
            throw 'Start-DbaService not found (dbatools). Cannot start Stopped SQL services.'
        }
        return @(Start-DbaService @p)
    }
    return @(Restart-DbaService @p)
}

function Restart-SqlTargetService {
    param(
        [string]$Computer,
        [string]$SqlInstance,
        [string[]]$Type = $script:ServiceTypes,
        [PSCredential]$Credential,
        [PSCredential]$SqlCredential,
        [string[]]$Account,
        [hashtable]$AccountPassword,
        [int]$RetryCount = 5,
        [int]$RetryDelaySeconds = 20
    )
    # Engine before Agent - Agent start fails while Engine is down ("dependent service").
    $Type = @(Get-SsaRestartTypeOrder -Type $Type)
    $instanceName = Get-SsaInstanceNameFromSqlInstance -SqlInstance $SqlInstance
    $targets = @(Resolve-RemoteComputerTarget -ComputerName $Computer -SqlInstance $SqlInstance `
            -SqlCredential $SqlCredential -Credential $Credential)
    Initialize-DbaCmWinRm -ComputerName $Computer -Credential $Credential `
        -SqlInstance $SqlInstance -SqlCredential $SqlCredential

    foreach ($oneType in $Type) {
        $typeDone = $false
        for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
            $snap = Get-SsaServiceSnapshot -Targets $targets -Type $oneType -InstanceName $instanceName -Credential $Credential
            $states = @($snap.Services | ForEach-Object { "$($_.ServiceName)=$($_.State)" }) -join ', '
            # Restart-DbaService on an already-Stopped service often leaves it Stopped (manual Start works).
            # Return-to-service path must Start when Stopped; Restart only when Running.
            $anyRunning = @($snap.Services | Where-Object { [string]$_.State -eq 'Running' }).Count -gt 0
            $action = if ($anyRunning) { 'Restart' } else { 'Start' }
            Write-Host ("  {0} {1} on {2} (attempt {3}/{4}; state: {5}; targets: {6})" -f `
                    $action, $oneType, $Computer, $attempt, $RetryCount, $(if ($states) { $states } else { 'unknown' }), ($targets -join ', ')) -ForegroundColor Cyan

            $result = $null
            $lastErr = $null
            $winRmOnlyFailures = $true
            $actionUsed = $action
            foreach ($t in $targets) {
                try {
                    $result = @(Invoke-SsaServiceStartOrRestart -ComputerTarget $t -Type $oneType `
                            -InstanceName $instanceName -Action $action -Credential $Credential)
                    # If Restart reported OK but services are still Stopped, force Start once (RTS).
                    if ($action -eq 'Restart' -and $result.Count -gt 0) {
                        $stillStopped = @($result | Where-Object {
                                $_.Status -ne 'Failed' -and [string]$_.State -eq 'Stopped'
                            })
                        if ($stillStopped.Count -gt 0) {
                            Write-Warning ("  Restart left {0} Stopped - falling back to Start-DbaService" -f (($stillStopped.ServiceName) -join ', '))
                            $result = @(Invoke-SsaServiceStartOrRestart -ComputerTarget $t -Type $oneType `
                                    -InstanceName $instanceName -Action 'Start' -Credential $Credential)
                            $actionUsed = 'Start'
                        }
                    }
                    if ($result.Count -eq 0) {
                        Write-Warning ("  {0}-DbaService returned no result on {1}; trying next name / Start fallback" -f $actionUsed, $t)
                        if ($actionUsed -eq 'Restart') {
                            $result = @(Invoke-SsaServiceStartOrRestart -ComputerTarget $t -Type $oneType `
                                    -InstanceName $instanceName -Action 'Start' -Credential $Credential)
                            $actionUsed = 'Start'
                        }
                        if ($result.Count -eq 0) { continue }
                    }
                    $winRmOnlyFailures = $false
                    Write-Host ("  {0} result: {1}" -f $actionUsed, (($result | ForEach-Object { "$($_.ServiceName)=$($_.Status)/$($_.State)" }) -join ', ')) -ForegroundColor DarkCyan
                    break
                } catch {
                    $lastErr = $_
                    $err = [string]$_
                    if (Test-WinRmComputerNameFailure $err) {
                        Write-Warning ("  {0}-DbaService WinRM failed on {1}: {2}" -f $actionUsed, $t, $err.Split("`n")[0])
                        continue
                    }
                    $winRmOnlyFailures = $false
                    Write-Warning ("  {0}-DbaService threw on {1}: {2}" -f $actionUsed, $t, $err)
                    # If Restart threw because service was Stopped, retry Start on same target.
                    if ($actionUsed -eq 'Restart' -and ($err -match 'cannot start|not started|stopped|pending')) {
                        try {
                            Write-Warning "  Retrying with Start-DbaService on $t"
                            $result = @(Invoke-SsaServiceStartOrRestart -ComputerTarget $t -Type $oneType `
                                    -InstanceName $instanceName -Action 'Start' -Credential $Credential)
                            $actionUsed = 'Start'
                            $winRmOnlyFailures = $false
                            break
                        } catch {
                            $lastErr = $_
                            $err = [string]$_
                        }
                    }
                    if (Test-RestartDependencyFailure -Results @() -ErrorText $err) {
                        if ($attempt -ge $RetryCount) { throw }
                        Write-Warning "  Dependency/timing failure for $oneType - waiting before retry (not AD unlock)"
                        Start-Sleep -Seconds $RetryDelaySeconds
                        $result = $null
                        break
                    }
                    $authFail = $err -match 'authentication|logon|password|credential'
                    if (-not $authFail -or $attempt -ge $RetryCount) { throw }
                    Wait-AdAfterAuthFailure -Account $Account -AccountPassword $AccountPassword `
                        -Computer $Computer -Credential $Credential
                    Start-Sleep -Seconds $RetryDelaySeconds
                    $result = $null
                    break
                }
            }

            if ($null -eq $result) {
                if ($winRmOnlyFailures -and $lastErr) { throw $lastErr }
                if ($lastErr -and $attempt -ge $RetryCount) { throw $lastErr }
                continue
            }

            $bad = @($result | Where-Object {
                    $_.Status -eq 'Failed' -or [string]$_.State -eq 'Stopped'
                })
            if (-not $bad) {
                Wait-SqlTargetServiceRunning -Computer $Computer -SqlInstance $SqlInstance -Type $oneType `
                    -Credential $Credential -SqlCredential $SqlCredential `
                    -TimeoutSeconds ([Math]::Max(180, $RetryDelaySeconds * 6))
                $typeDone = $true
                break
            }

            $names = ($bad.ServiceName) -join ', '
            Write-Warning ("  {0} failed on {1}: {2} ({3}) -> {4}" -f $actionUsed, $Computer, $names, $oneType, `
                    (($bad | ForEach-Object { "$($_.Status)/$($_.State)" }) -join ', '))
            if (Test-RestartDependencyFailure -Results $bad) {
                if ($attempt -ge $RetryCount) {
                    throw "$actionUsed failed on ${Computer}: $names ($oneType) - dependency/timing"
                }
                Write-Warning "  Dependency/timing failure for $oneType - waiting before retry (not AD unlock)"
                Start-Sleep -Seconds $RetryDelaySeconds
                continue
            }
            if (-not (Test-RestartAuthFailure -Results $bad) -or $attempt -ge $RetryCount) {
                throw "$actionUsed failed on ${Computer}: $names ($oneType)"
            }

            Wait-AdAfterAuthFailure -Account $Account -AccountPassword $AccountPassword `
                -Computer $Computer -Credential $Credential
            Start-Sleep -Seconds $RetryDelaySeconds
        }
        if (-not $typeDone) {
            throw "Start/Restart did not complete for $oneType on $Computer after $RetryCount attempt(s)."
        }
    }
}

function Wait-SqlTargetServiceRunning {
    param(
        [string]$Computer,
        [string]$SqlInstance,
        [string[]]$Type = $script:ServiceTypes,
        [PSCredential]$Credential,
        [PSCredential]$SqlCredential,
        [int]$TimeoutSeconds = 180
    )
    if ([string]::IsNullOrWhiteSpace($Computer)) { return }
    $Type = @($Type | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $Type) { return }
    $instanceName = Get-SsaInstanceNameFromSqlInstance -SqlInstance $SqlInstance

    $label = $Type -join '/'
    $targets = @(Resolve-RemoteComputerTarget -ComputerName $Computer -SqlInstance $SqlInstance `
            -SqlCredential $SqlCredential -Credential $Credential)
    Initialize-DbaCmWinRm -ComputerName $Computer -Credential $Credential `
        -SqlInstance $SqlInstance -SqlCredential $SqlCredential
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt = 0
    Write-Host "  Waiting for $label Running on $Computer (up to ${TimeoutSeconds}s)" -ForegroundColor DarkCyan
    do {
        $attempt++
        $probed = $false
        foreach ($t in $targets) {
            try {
                $gp = @{
                    ComputerName    = $t
                    Type            = $Type
                    EnableException = $true
                    ErrorAction     = 'Stop'
                }
                if ($instanceName) { $gp.InstanceName = $instanceName }
                if ($Credential) { $gp.Credential = $Credential }
                $svcs = @(Get-DbaService @gp)
                $probed = $true
                if (-not $svcs) {
                    Write-Host "  No $label services on $t (nothing to wait for)" -ForegroundColor DarkYellow
                    return
                }
                $notRunning = @($svcs | Where-Object { [string]$_.State -ne 'Running' })
                if (-not $notRunning) {
                    Write-Host ("  {0} Running on {1} ({2})" -f $label, $t, (($svcs.ServiceName) -join ', ')) -ForegroundColor Green
                    return
                }
                $states = ($notRunning | ForEach-Object { "$($_.ServiceName)=$($_.State)" }) -join '; '
                Write-Host "  Not ready on $t (attempt $attempt): $states" -ForegroundColor DarkYellow
                break
            } catch {
                if (Test-WinRmComputerNameFailure ([string]$_)) {
                    Write-Host ("  Service check WinRM failed on {0}: {1}" -f $t, ([string]$_).Split("`n")[0]) -ForegroundColor DarkYellow
                    continue
                }
                Write-Host ("  Service check failed on {0} (attempt {1}): {2}" -f $t, $attempt, $_) -ForegroundColor DarkYellow
                $probed = $true
                break
            }
        }
        if (-not $probed) {
            Write-Host ("  Service check: no WinRM target worked for {0} (attempt {1})" -f $Computer, $attempt) -ForegroundColor DarkYellow
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    throw "$label not Running on $Computer within ${TimeoutSeconds}s."
}

function Wait-AgReady {
    param(
        [string]$SqlInstance,
        [string[]]$AgNames,
        [string]$SecondarySqlInstance,
        [PSCredential]$SqlCredential,
        [int]$TimeoutSeconds
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt = 0
    do {
        $attempt++
        try {
            $p = @{
                SqlInstance       = $SqlInstance
                AvailabilityGroup = $AgNames
                EnableException   = $true
                WarningAction     = 'SilentlyContinue'
                ErrorAction       = 'Stop'
            }
            if ($SqlCredential) { $p.SqlCredential = $SqlCredential }
            $ags = @(Get-DbaAvailabilityGroup @p)
        } catch {
            Write-Host ("  Wait sync: {0} - {1}" -f $SqlInstance, ([string]$_).Split("`n")[0]) -ForegroundColor DarkYellow
            Start-Sleep -Seconds 5
            continue
        }

        if ($ags.Count -eq 0) {
            Write-Host "  Wait sync: no AG data from $SqlInstance yet" -ForegroundColor DarkYellow
            Start-Sleep -Seconds 5
            continue
        }

        $pending = foreach ($ag in $ags) {
            $target = $ag.AvailabilityReplicas | Where-Object { Test-ReplicaMatch $_.Name $SecondarySqlInstance } | Select-Object -First 1
            if (-not $target) {
                [pscustomobject]@{ Ag = $ag.Name; Why = "missing $SecondarySqlInstance" }
                continue
            }
            $sync = [string]$target.RollupSynchronizationState
            $conn = [string]$target.ConnectionState
            $mode = [string]$target.AvailabilityMode
            $ok = ($conn -eq 'Connected') -and (
                $sync -eq 'Synchronized' -or
                ($mode -match 'Asynchronous' -and $sync -eq 'Synchronizing')
            )
            if (-not $ok) {
                [pscustomobject]@{ Ag = $ag.Name; Why = "$($target.Name) $conn/$sync" }
            }
        }
        if (-not $pending) { return }
        Write-Host ("  Wait sync: " + (($pending | ForEach-Object { "$($_.Ag)=$($_.Why)" }) -join '; ')) -ForegroundColor DarkYellow
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    throw "AG sync timeout (${TimeoutSeconds}s) waiting on $SecondarySqlInstance"
}

function Get-AgDatabaseSyncStatus {
    param(
        [string]$SqlInstance,
        [string[]]$AgNames,
        [PSCredential]$SqlCredential
    )

    $p = @{
        SqlInstance     = $SqlInstance
        EnableException = $true
        WarningAction   = 'SilentlyContinue'
        ErrorAction     = 'Stop'
    }
    if ($SqlCredential) { $p.SqlCredential = $SqlCredential }
    if ($AgNames) { $p.AvailabilityGroup = $AgNames }

    $ags = @(Get-DbaAvailabilityGroup @p)
    foreach ($ag in $ags) {
        foreach ($db in @($ag.DatabaseReplicas)) {
            [pscustomobject]@{
                AvailabilityGroup     = $ag.Name
                PrimaryReplica        = $ag.PrimaryReplicaServerName
                DatabaseName          = $db.Name
                Replica               = $db.AvailabilityReplicaServerName
                SynchronizationState  = [string]$db.SynchronizationState
                SynchronizationHealth = [string]$db.SynchronizationHealth
                IsFailoverReady       = $db.IsFailoverReady
                IsSuspended           = $db.IsSuspended
            }
        }
    }
}

function Save-SsaDiscovery {
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)]$Topology,
        [Parameter(Mandatory)]$Services,
        [Parameter(Mandatory)]$DomainAccounts,
        [object[]]$Findings,
        [object[]]$SpnReports
    )

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $latest = Join-Path $OutputFolder 'discovery-latest.json'
    $archive = Join-Path $OutputFolder "discovery-$stamp.json"

    $payload = [pscustomobject]@{
        GeneratedAt     = (Get-Date).ToString('o')
        Mode            = $Topology.Mode
        Offline         = [bool]$Topology.Offline
        OfflineReason   = [string]$Topology.OfflineReason
        AgNames         = @($Topology.AgNames)
        OriginalPrimary = $Topology.OriginalPrimary
        Nodes           = @($Topology.Nodes | Select-Object ComputerName, SqlInstance, Role)
        Services        = @($Services | Select-Object ComputerName, ServiceName, ServiceType, InstanceName, State, StartName, StartMode)
        DomainAccounts  = @($DomainAccounts | Select-Object Account, ServiceTypes, ServiceCount, Computers, Services)
        SpnReports      = @($SpnReports)
        Findings        = @($Findings)
    }

    $json = $payload | ConvertTo-Json -Depth 8
    Set-Content -LiteralPath $latest -Value $json -Encoding UTF8
    Set-Content -LiteralPath $archive -Value $json -Encoding UTF8
    Write-Host "  Discovery saved: $latest" -ForegroundColor Green
    return $latest
}

function Read-SsaDiscovery {
    param([Parameter(Mandatory)][string]$OutputFolder)
    $latest = Join-Path $OutputFolder 'discovery-latest.json'
    if (-not (Test-Path -LiteralPath $latest)) { return $null }
    Get-Content -LiteralPath $latest -Raw | ConvertFrom-Json
}
