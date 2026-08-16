<#
.SYNOPSIS
    Apply SecOps-provided passwords to domain AD SQL service accounts (no AD change).

.DESCRIPTION
    Discovers domain AD service accounts for Engine/Agent/SSRS/SSIS (not local users).
    Applies SecOps passwords, waits for AD readiness on SQL nodes, then restarts
    (standalone or AG failover/failback). No AD change. No vault.

    Optional -SqlCredential uses SQL authentication for AG discovery/sync/failover
    (avoids Kerberos/SSPI). If omitted, Windows auth is used like Rotate.

.EXAMPLE
    .\ApplySqlServiceAccountPassword.ps1 -SqlInstance 'HOST\SQL01' -ListAccounts

.EXAMPLE
    $p1 = ConvertTo-SecureString 'PwForSql' -AsPlainText -Force
    $p2 = ConvertTo-SecureString 'PwForSsrs' -AsPlainText -Force
    .\ApplySqlServiceAccountPassword.ps1 -SqlInstance 'HOST\SQL01' `
        -Account 'DOMAIN\svcSql','DOMAIN\svcSsrs' -SecurePassword $p1,$p2

.EXAMPLE
    $p1 = ConvertTo-SecureString 'PwForSql' -AsPlainText -Force
    $sql = Get-Credential -Message 'SQL login for AG'
    .\ApplySqlServiceAccountPassword.ps1 -SqlInstance 'HOST\SQL01' `
        -AvailabilityGroup 'AgName' -Account 'DOMAIN\svcSql' -SecurePassword $p1 `
        -SqlCredential $sql
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
[CmdletBinding(DefaultParameterSetName = 'Apply')]
param(
    [Parameter(Mandatory)]
    [string]$SqlInstance,

    [string[]]$AvailabilityGroup,

    [string[]]$InstanceName,

    [PSCredential]$Credential,

    [PSCredential]$SqlCredential,

    [Parameter(Mandatory, ParameterSetName = 'Apply')]
    [string[]]$Account,

    [Parameter(Mandatory, ParameterSetName = 'Apply')]
    [SecureString[]]$SecurePassword,

    [Parameter(Mandatory, ParameterSetName = 'ListAccounts')]
    [switch]$ListAccounts,

    [switch]$InstallModule,

    [ValidateRange(30, 3600)]
    [int]$SyncTimeoutSeconds = 300
)

# === CONFIG (edit here) ===
$script:OutputFolder = '\\SERVERNAME\C$\Temp\'
$script:ServiceTypes = @('Engine', 'Agent', 'SSRS', 'SSIS')

$ErrorActionPreference = 'Stop'
$script:DomainDnsSuffixCache = $null
$script:SqlHostDnsCache = @{}
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

function Test-IsDomainServiceAccount {
    param([string]$StartName, [string]$ForComputer)

    if ([string]::IsNullOrWhiteSpace($StartName)) { return @{ Ok = $false; Reason = 'empty' } }
    if ($StartName -match '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\)') {
        return @{ Ok = $false; Reason = 'built-in' }
    }
    if ($StartName -match '\$$') { return @{ Ok = $false; Reason = 'gMSA' } }
    if ($StartName -match '^[^\\]+@[^\\]+$') { return @{ Ok = $true; Reason = $null } } # UPN
    if ($StartName -notmatch '\\') { return @{ Ok = $false; Reason = 'local/bare name' } }

    $local = $StartName -match "^$([regex]::Escape($ForComputer))\\|^\.\\"
    if ($local) { return @{ Ok = $false; Reason = 'local user' } }
    @{ Ok = $true; Reason = $null }
}

function Get-RemoteCredential {
    param([string]$Computer, [PSCredential]$Credential)
    if ($Credential -and -not (Test-IsLocalComputerName $Computer)) {
        return $Credential
    }
    $null
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
        if (Get-Command Get-ADTrust -ErrorAction SilentlyContinue) {
            foreach ($t in @(Get-ADTrust -Filter * -ErrorAction SilentlyContinue)) {
                & $addSuffix $t.Name
                & $addSuffix $t.Target
            }
        }
    } catch { $null = $_ }

    $script:DomainDnsSuffixCache = @($suffixes)
    return @($script:DomainDnsSuffixCache)
}

function Get-SqlHostFqdn {
    param(
        [string]$SqlInstance,
        [PSCredential]$SqlCredential
    )
    if ([string]::IsNullOrWhiteSpace($SqlInstance)) { return $null }
    if ($script:SqlHostDnsCache.ContainsKey($SqlInstance)) {
        return $script:SqlHostDnsCache[$SqlInstance]
    }
    if (-not (Get-Command Invoke-DbaQuery -ErrorAction SilentlyContinue)) { return $null }

    $fqdn = $null
    try {
        # Machine DNS domain (not service-account DEFAULT_DOMAIN()).
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

    # 1) SQL host TCP/IP DNS domain (best for cross-domain: machine domain != service account domain)
    if ($SqlInstance) {
        $sqlFqdn = Get-SqlHostFqdn -SqlInstance $SqlInstance -SqlCredential $SqlCredential
        if ($sqlFqdn) { & $add $sqlFqdn $true }
    }

    # 2) dbatools name resolution (FQDN / DNSHostEntry / DNSDomain)
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

    # 3) Forward + reverse DNS
    try {
        $entry = [System.Net.Dns]::GetHostEntry($raw)
        if ($entry.HostName -match '\.') { & $add $entry.HostName $false }
        foreach ($ip in @($entry.AddressList)) {
            try {
                $rev = [System.Net.Dns]::GetHostEntry($ip)
                if ($rev.HostName -match '\.') { & $add $rev.HostName $false }
            } catch { $null = $_ }
        }
    } catch { $null = $_ }

    try {
        foreach ($ip in @([System.Net.Dns]::GetHostAddresses($short))) {
            try {
                $rev = [System.Net.Dns]::GetHostEntry($ip)
                if ($rev.HostName -match '\.') { & $add $rev.HostName $false }
            } catch { $null = $_ }
        }
    } catch { $null = $_ }

    # 4) Trusted / forest DNS suffixes (e.g. ucles.external while jump box is ucles.internal)
    if ($short -notmatch '\.') {
        foreach ($suffix in @(Get-DomainDnsSuffixCandidate)) {
            & $add ('{0}.{1}' -f $short, $suffix) $true
        }
    }

    & $add $raw $false
    if ($short -and ($short -ne $raw)) { & $add $short $false }

    # Prefer FQDNs first for Kerberos/WinRM.
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

function Test-SqlAuthFailureMessage {
    param([string]$Message)
    $Message -match 'SSPI|Kerberos|login failed|Login failed|principal name|Cannot generate SSPI|A network-related|timeout|timed out|connection|Connection'
}

function Get-TargetTopology {
    param(
        [string]$SqlInstance,
        [string[]]$AvailabilityGroup,
        [PSCredential]$SqlCredential,
        [PSCredential]$Credential
    )

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
        if ($msg -notmatch 'HADR|Availability Group|not configured|is not enabled') { throw }
        if ($AvailabilityGroup) {
            throw "Instance $SqlInstance has no HADR/AG configured, but -AvailabilityGroup was specified."
        }
        $ags = @()
    }

    if (-not $ags) {
        $computer = Get-NodeComputer -Instance $SqlInstance -Credential $Credential -SqlCredential $SqlCredential
        return [pscustomobject]@{
            Mode            = 'Standalone'
            Nodes           = @([pscustomobject]@{ ComputerName = $computer; SqlInstance = $SqlInstance })
            AgNames         = @()
            OriginalPrimary = $SqlInstance
        }
    }

    $agNames = @($ags.Name | Select-Object -Unique)
    $replicaSql = @($ags | ForEach-Object { $_.AvailabilityReplicas.Name } | Select-Object -Unique)
    if ($replicaSql.Count -lt 1) { throw "AGs found ($($agNames -join ', ')) but no replicas." }

    $nodes = foreach ($rep in $replicaSql) {
        [pscustomobject]@{
            ComputerName = (Get-NodeComputer -Instance $rep -Credential $Credential -SqlCredential $SqlCredential)
            SqlInstance  = $rep
        }
    }
    $nodes = @($nodes | Group-Object ComputerName | ForEach-Object { $_.Group | Select-Object -First 1 })

    [pscustomobject]@{
        Mode            = 'AvailabilityGroup'
        Nodes           = $nodes
        AgNames         = $agNames
        OriginalPrimary = $ags[0].PrimaryReplicaServerName
    }
}

function Get-SqlTargetService {
    param(
        [object[]]$Nodes,
        [string[]]$InstanceName,
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
                    Type            = $script:ServiceTypes
                    EnableException = $true
                }
                if ($svcCred) { $gp.Credential = $svcCred }
                $got = @(Get-DbaService @gp)
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
        $type = [string]$_.ServiceType
        ($type -in @('SSRS', 'SSIS')) -or ($_.InstanceName -in $InstanceName)
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

function Update-NodeServicePassword {
    param([object[]]$Services, [securestring]$SecurePassword, [PSCredential]$Credential)
    $p = @{
        InputObject     = $Services
        SecurePassword  = $SecurePassword
        NoRestart       = $true
        Confirm         = $false
        EnableException = $true
    }
    if ($Credential) { $p.Credential = $Credential }
    Update-DbaServiceAccount @p
}

function Clear-AdServiceAccountExpiration {
    param([string]$Account)
    $sam = $Account.Split('\')[-1]
    if ($sam -match '@') { $sam = $sam.Split('@')[0] }
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { return }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adUser = Get-ADUser -Identity $sam -Properties AccountExpirationDate -ErrorAction Stop
        $exp = $adUser.AccountExpirationDate
        if ($exp -and ($exp -le (Get-Date))) {
            Write-Warning "  AD account $sam is expired (AccountExpirationDate=$exp) - Clear-ADAccountExpiration"
            Clear-ADAccountExpiration -Identity $sam -ErrorAction Stop
            Start-Sleep -Seconds 2
        }
    } catch {
        $null = $_
    }
}

function Unlock-AdServiceAccount {
    param([string]$Account)
    $sam = $Account.Split('\')[-1]
    if ($sam -match '@') { $sam = $sam.Split('@')[0] }
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
        [int]$RequiredSuccesses = 2
    )

    $sam = $Account.Split('\')[-1]
    if ($sam -match '@') { $sam = $sam.Split('@')[0] }
    $domain = Resolve-AdAuthDomain -Account $Account
    $plain = [Net.NetworkCredential]::new('', $SecurePassword).Password
    $started = Get-Date
    $deadline = $started.AddSeconds($TimeoutSeconds)
    $successes = 0
    $attempt = 0
    Write-Host "  AD (mgmt host): waiting for $Account via ValidateCredentials($domain\$sam) (up to ${TimeoutSeconds}s)" -ForegroundColor DarkCyan

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
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)

    throw @"
AD password for '$Account' not accepted on management host within ${TimeoutSeconds}s ($attempt attempts).
SecOps password may be correct in AD elsewhere, but ValidateCredentials still fails from this host.
Check: account lockout, wrong domain NETBIOS vs DNS, jump-box DC lag, or that the supplied password matches what SecOps set.
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

    $sam = $Account.Split('\')[-1]
    if ($sam -match '@') { $sam = $sam.Split('@')[0] }
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

    # FQDN first + Negotiate (not Kerberos-only) for cross-domain WinRM.
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
SecOps may have reset AD on a DC that SQL site DCs have not replicated from yet.
Requires WinRM to the SQL nodes for per-node ValidateCredentials. Unlock if locked, wait for replication, re-run.
Do not restart SQL until node checks pass.
"@
}

function Test-RestartAuthFailure {
    param([object[]]$Results)
    $text = @(
        $Results | ForEach-Object {
            @($_.Status, $_.State, $_.Message, $_.ServiceName) -join ' '
        }
    ) -join ' | '
    return [bool]($text -match 'authentication|logon failure|correct authentication|password|credentials|dependent service')
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
            # Bound retry wait: do not stack the full 1h node timeout on every restart attempt.
            Wait-AdCredentialReadyOnNode -Account $acct -SecurePassword $AccountPassword[$acct] `
                -ComputerName $Computer -Credential $Credential -TimeoutSeconds 600 -PollSeconds 300
        }
    }
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
    $Type = @($Type | Sort-Object -Unique)
    $targets = @(Resolve-RemoteComputerTarget -ComputerName $Computer -SqlInstance $SqlInstance `
            -SqlCredential $SqlCredential -Credential $Credential)
    Initialize-DbaCmWinRm -ComputerName $Computer -Credential $Credential `
        -SqlInstance $SqlInstance -SqlCredential $SqlCredential

    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        Write-Host ("  Restart {0} on {1} (attempt {2}/{3}; targets: {4})" -f ($Type -join '/'), $Computer, $attempt, $RetryCount, ($targets -join ', ')) -ForegroundColor Cyan
        $result = $null
        $lastErr = $null
        $winRmOnlyFailures = $true
        foreach ($t in $targets) {
            try {
                $p = @{
                    ComputerName    = $t
                    Type            = $Type
                    Force           = $true
                    Confirm         = $false
                    EnableException = $true
                }
                if ($Credential) { $p.Credential = $Credential }
                $result = @(Restart-DbaService @p)
                $winRmOnlyFailures = $false
                break
            } catch {
                $lastErr = $_
                $err = [string]$_
                if (Test-WinRmComputerNameFailure $err) {
                    Write-Warning ("  Restart-DbaService WinRM failed on {0}: {1}" -f $t, $err.Split("`n")[0])
                    continue
                }
                $winRmOnlyFailures = $false
                Write-Warning "  Restart-DbaService threw on ${t}: $err"
                $authFail = $err -match 'authentication|logon|password|credential|dependent service'
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
                $_.Status -eq 'Failed' -or [string]$_.State -ne 'Running'
            })
        if (-not $bad) { return }

        $names = ($bad.ServiceName) -join ', '
        Write-Warning "  Restart failed on ${Computer}: $names"
        if (-not (Test-RestartAuthFailure -Results $bad) -or $attempt -ge $RetryCount) {
            throw "Restart failed on ${Computer}: $names"
        }

        Wait-AdAfterAuthFailure -Account $Account -AccountPassword $AccountPassword `
            -Computer $Computer -Credential $Credential
        Start-Sleep -Seconds $RetryDelaySeconds
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
    $authWarned = $false
    do {
        $attempt++
        try {
            $p = @{
                SqlInstance         = $SqlInstance
                AvailabilityGroup   = $AgNames
                EnableException     = $true
                WarningAction       = 'SilentlyContinue'
                ErrorAction         = 'Stop'
            }
            if ($SqlCredential) { $p.SqlCredential = $SqlCredential }
            $ags = @(Get-DbaAvailabilityGroup @p)
        } catch {
            $msg = [string]$_
            if ((Test-SqlAuthFailureMessage $msg)) {
                if (-not $authWarned -or ($attempt % 6) -eq 0) {
                    Write-Host "  Wait sync: $SqlInstance not accepting SQL login yet (retrying)" -ForegroundColor DarkYellow
                    $authWarned = $true
                }
            } else {
                Write-Host ("  Wait sync: {0} - {1}" -f $SqlInstance, $msg.Split("`n")[0]) -ForegroundColor DarkYellow
            }
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

function Invoke-GracefulAgApply {
    param(
        [object[]]$Nodes,
        [string[]]$AgNames,
        [string]$OriginalPrimary,
        [string[]]$ServiceType,
        [PSCredential]$Credential,
        [PSCredential]$SqlCredential,
        [int]$SyncTimeoutSeconds,
        [string[]]$Account,
        [hashtable]$AccountPassword
    )

    if (-not $ServiceType) { $ServiceType = $script:ServiceTypes }

    $bySql = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $Nodes) { $bySql[$n.SqlInstance] = $n }

    $primarySql = $OriginalPrimary
    if (-not $bySql.ContainsKey($primarySql)) {
        $mapped = $Nodes | Where-Object {
            (Test-ReplicaMatch -ReplicaName $OriginalPrimary -SqlInstance $_.SqlInstance) -or
            (Test-ComputerNameMatch -Left $_.ComputerName -Right ($OriginalPrimary.Split('\')[0]))
        } | Select-Object -First 1
        if (-not $mapped) { throw "Could not map primary '$OriginalPrimary' to discovered nodes." }
        $primarySql = $mapped.SqlInstance
    }
    if (-not $primarySql -or -not $bySql.ContainsKey($primarySql)) {
        throw "Could not map primary '$OriginalPrimary' to discovered nodes."
    }

    $secondary = $Nodes | Where-Object { $_.SqlInstance -ne $primarySql } | Select-Object -First 1
    if (-not $secondary) { throw 'AG mode requires at least two replicas.' }
    $primary = $bySql[$primarySql]

    Write-Host "`n=== AG apply ===" -ForegroundColor Cyan
    Write-Host "AGs: $($AgNames -join ', ')" -ForegroundColor Cyan
    Write-Host "Primary:   $($primary.SqlInstance) [$($primary.ComputerName)]" -ForegroundColor Cyan
    Write-Host "Secondary: $($secondary.SqlInstance) [$($secondary.ComputerName)]" -ForegroundColor Cyan

    Restart-SqlTargetService -Computer $secondary.ComputerName -SqlInstance $secondary.SqlInstance -Type $ServiceType `
        -Credential (Get-RemoteCredential $secondary.ComputerName $Credential) -SqlCredential $SqlCredential `
        -Account $Account -AccountPassword $AccountPassword
    Wait-SqlTargetServiceRunning -Computer $secondary.ComputerName -SqlInstance $secondary.SqlInstance -Type $ServiceType `
        -Credential (Get-RemoteCredential $secondary.ComputerName $Credential) -SqlCredential $SqlCredential `
        -TimeoutSeconds ([Math]::Min(180, $SyncTimeoutSeconds))
    Wait-AgReady -SqlInstance $primary.SqlInstance -AgNames $AgNames -SecondarySqlInstance $secondary.SqlInstance `
        -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds

    Write-Host "  Failover -> $($secondary.SqlInstance)" -ForegroundColor Cyan
    $fo = @{
        SqlInstance = $secondary.SqlInstance; AvailabilityGroup = $AgNames
        Confirm = $false; EnableException = $true
    }
    if ($SqlCredential) { $fo.SqlCredential = $SqlCredential }
    Invoke-DbaAgFailover @fo | Out-Null
    Start-Sleep -Seconds 3
    Wait-AgReady -SqlInstance $secondary.SqlInstance -AgNames $AgNames -SecondarySqlInstance $primary.SqlInstance `
        -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds

    Restart-SqlTargetService -Computer $primary.ComputerName -SqlInstance $primary.SqlInstance -Type $ServiceType `
        -Credential (Get-RemoteCredential $primary.ComputerName $Credential) -SqlCredential $SqlCredential `
        -Account $Account -AccountPassword $AccountPassword
    Wait-SqlTargetServiceRunning -Computer $primary.ComputerName -SqlInstance $primary.SqlInstance -Type $ServiceType `
        -Credential (Get-RemoteCredential $primary.ComputerName $Credential) -SqlCredential $SqlCredential `
        -TimeoutSeconds ([Math]::Min(180, $SyncTimeoutSeconds))
    Wait-AgReady -SqlInstance $secondary.SqlInstance -AgNames $AgNames -SecondarySqlInstance $primary.SqlInstance `
        -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds

    Write-Host "  Failback -> $($primary.SqlInstance)" -ForegroundColor Cyan
    $fb = @{
        SqlInstance = $primary.SqlInstance; AvailabilityGroup = $AgNames
        Confirm = $false; EnableException = $true
    }
    if ($SqlCredential) { $fb.SqlCredential = $SqlCredential }
    Invoke-DbaAgFailover @fb | Out-Null
    Wait-AgReady -SqlInstance $primary.SqlInstance -AgNames $AgNames -SecondarySqlInstance $secondary.SqlInstance `
        -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds
    Write-Host "  Done. Primary restored on $($primary.SqlInstance)." -ForegroundColor Green
}

if ($script:OutputFolder -match 'SERVERNAME' -or [string]::IsNullOrWhiteSpace($script:OutputFolder)) {
    throw @"
OutputFolder is not configured.
Edit CONFIG in this script and set a real shared path, for example:
  `$script:OutputFolder = '\\YourFileServer\Share\SqlServiceAccountRotation\'
Current value: $($script:OutputFolder)
"@
}
if (-not (Test-Path $script:OutputFolder)) {
    try {
        New-Item $script:OutputFolder -ItemType Directory -Force | Out-Null
    } catch {
        throw "Cannot create/access OutputFolder '$($script:OutputFolder)'. Check the UNC path and share permissions. $_"
    }
}

$passwordMap = $null
if ($PSCmdlet.ParameterSetName -eq 'Apply') {
    $passwordMap = Resolve-AccountPasswordMap -Account $Account -SecurePassword $SecurePassword
}

Start-Transcript -Path (Join-Path $script:OutputFolder "ApplySqlServiceAccountPassword_$timestamp.log") -NoClobber | Out-Null

try {
    if (-not (Get-Module -ListAvailable -Name dbatools)) {
        if (-not $InstallModule) { throw 'dbatools missing. Install it or pass -InstallModule.' }
        Install-Module dbatools -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module dbatools -ErrorAction Stop
    Set-DbatoolsConfig -FullName sql.connection.encrypt -Value $true
    Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true

    # -SqlCredential is optional (Windows auth by default; pass SQL auth to avoid Kerberos/SSPI).
    $topo = Get-TargetTopology -SqlInstance $SqlInstance -AvailabilityGroup $AvailabilityGroup `
        -SqlCredential $SqlCredential -Credential $Credential

    if ($SqlCredential -and $topo.Mode -eq 'AvailabilityGroup' -and -not $ListAccounts) {
        Write-Host "AG SQL login: $($SqlCredential.UserName)" -ForegroundColor DarkCyan
    }

    Write-Host "`nMode: $($topo.Mode)" -ForegroundColor Cyan
    $topo.Nodes | Format-Table ComputerName, SqlInstance -AutoSize
    if ($topo.AgNames) { Write-Host "AGs: $($topo.AgNames -join ', ')" -ForegroundColor Cyan }

    $computers = @($topo.Nodes.ComputerName | Select-Object -Unique)
    $allServices = @(Get-SqlTargetService -Nodes $topo.Nodes -InstanceName $InstanceName -Credential $Credential -SqlCredential $SqlCredential)
    if (-not $allServices) {
        throw "No $($script:ServiceTypes -join '/') services on: $($computers -join ', ')"
    }

    Write-Host "`nServices:" -ForegroundColor Cyan
    $allServices | Select-Object ComputerName, ServiceName, ServiceType, State, StartName | Format-Table -AutoSize

    $domainAccounts = @(Get-DomainSqlServiceAccount -Services $allServices)

    if ($ListAccounts) {
        Write-Host "`nDomain AD service accounts (Engine/Agent/SSRS/SSIS):" -ForegroundColor Cyan
        if (-not $domainAccounts) {
            Write-Warning 'No domain AD service accounts found.'
            return
        }
        $listView = @($domainAccounts | Select-Object Account, ServiceTypes, ServiceCount, Computers, Services)
        $listView | Format-Table -AutoSize
        $listView | Write-Output
        return
    }

    if (-not $domainAccounts) { Write-Warning 'No domain AD service accounts found.'; return }

    $targets = @(
        foreach ($row in $domainAccounts) {
            if ($passwordMap.ContainsKey($row.Account)) { $row }
            else { Write-Host "Skip $($row.Account): no password supplied" -ForegroundColor Yellow }
        }
    )

    foreach ($name in @($passwordMap.Keys)) {
        if (-not ($domainAccounts | Where-Object Account -eq $name)) {
            Write-Warning "Password supplied for '$name' but that AD service account was not found on this topology."
        }
    }

    if (-not $targets) {
        throw 'No matching domain AD service accounts to update. Use -ListAccounts, then pass matching -Account/-SecurePassword pairs.'
    }

    Write-Host "`nPlan: apply SecOps password(s) to $($targets.Count) account(s), then restart once" -ForegroundColor Cyan
    Write-Host 'No AD password change will be performed. Passwords are not stored in a vault.' -ForegroundColor Yellow

    $anyFailures = $false
    $updatedAccounts = [System.Collections.Generic.List[string]]::new()

    foreach ($row in $targets) {
        $acct = $row.Account
        $securePwd = $passwordMap[$acct]
        Write-Host "`nApplying password: $acct" -ForegroundColor Green
        $ok = $true

        foreach ($computer in @($row.Group.ComputerName | Select-Object -Unique)) {
            if (-not $ok) { break }
            $nodeServices = @($row.Group | Where-Object ComputerName -eq $computer)
            $svcCred = Get-RemoteCredential -Computer $computer -Credential $Credential
            try {
                Write-Host "  Update-DbaServiceAccount -NoRestart @ $computer ($(($nodeServices.ServiceName) -join ', '))" -ForegroundColor DarkCyan
                $result = @(Update-NodeServicePassword -Services $nodeServices -SecurePassword $securePwd -Credential $svcCred)
                $failed = @($result | Where-Object { $_.Status -eq 'Failed' })
                if ($failed.Count -gt 0) {
                    Write-Host "  FAILED @ ${computer}: $((($failed).Message) -join '; ')" -ForegroundColor Red
                    $ok = $false; $anyFailures = $true
                } elseif ($result.Count -eq 0) {
                    Write-Host "  FAILED @ ${computer}: Update-DbaServiceAccount returned no result" -ForegroundColor Red
                    $ok = $false; $anyFailures = $true
                }
            } catch {
                Write-Host "  FAILED @ ${computer}: $_" -ForegroundColor Red
                $ok = $false; $anyFailures = $true
            }
        }

        if ($ok) {
            try {
                $accountNodes = @($row.Group.ComputerName | Sort-Object -Unique)
                Wait-AdCredentialReady -Account $acct -SecurePassword $securePwd -TimeoutSeconds $SyncTimeoutSeconds
                Wait-AdCredentialReadyOnNode -Account $acct -SecurePassword $securePwd `
                    -ComputerName $accountNodes -Credential $Credential
                $updatedAccounts.Add($acct)
                Write-Host '  Service password updated; AD ready on SQL nodes (not restarted yet).' -ForegroundColor Green
            } catch {
                Write-Host "  FAILED (AD wait): $_" -ForegroundColor Red
                $ok = $false; $anyFailures = $true
            }
        }
    }

    if (-not $anyFailures) {
        $sqlNodes = @($topo.Nodes.ComputerName | Sort-Object -Unique)
        $restartAccounts = @($updatedAccounts)
        $restartPasswords = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($acct in $restartAccounts) {
            $restartPasswords[$acct] = $passwordMap[$acct]
            Write-Host "`nPre-restart AD check on SQL nodes: $acct" -ForegroundColor Cyan
            Wait-AdCredentialReadyOnNode -Account $acct -SecurePassword $restartPasswords[$acct] `
                -ComputerName $sqlNodes -Credential $Credential
        }

        $typesToRestart = @(
            $targets |
                ForEach-Object { $_.Group } |
                ForEach-Object { [string]$_.ServiceType } |
                Sort-Object -Unique
        )
        if (-not $typesToRestart) { $typesToRestart = $script:ServiceTypes }

        $needsAgFailover = @($typesToRestart | Where-Object { $_ -in @('Engine', 'Agent') }).Count -gt 0
        if ($topo.Mode -eq 'AvailabilityGroup' -and $needsAgFailover) {
            Invoke-GracefulAgApply `
                -Nodes $topo.Nodes `
                -AgNames $topo.AgNames `
                -OriginalPrimary $topo.OriginalPrimary `
                -ServiceType $typesToRestart `
                -Credential $Credential `
                -SqlCredential $SqlCredential `
                -SyncTimeoutSeconds $SyncTimeoutSeconds `
                -Account $restartAccounts `
                -AccountPassword $restartPasswords
        } else {
            if ($topo.Mode -eq 'AvailabilityGroup' -and -not $needsAgFailover) {
                Write-Host 'SSRS/SSIS only: restarting on all nodes (no AG failover).' -ForegroundColor Cyan
            }
            foreach ($node in $topo.Nodes) {
                Restart-SqlTargetService -Computer $node.ComputerName -SqlInstance $node.SqlInstance -Type $typesToRestart `
                    -Credential (Get-RemoteCredential $node.ComputerName $Credential) -SqlCredential $SqlCredential `
                    -Account $restartAccounts -AccountPassword $restartPasswords
                Wait-SqlTargetServiceRunning -Computer $node.ComputerName -SqlInstance $node.SqlInstance -Type $typesToRestart `
                    -Credential (Get-RemoteCredential $node.ComputerName $Credential) -SqlCredential $SqlCredential `
                    -TimeoutSeconds ([Math]::Min(180, $SyncTimeoutSeconds))
            }
        }
    }

    if ($updatedAccounts.Count) {
        Write-Host "`nUpdated account(s): $($updatedAccounts -join ', ')" -ForegroundColor Green
    }

    if ($anyFailures) { Write-Warning 'One or more updates failed.'; exit 1 }
} finally {
    Stop-Transcript | Out-Null
}
