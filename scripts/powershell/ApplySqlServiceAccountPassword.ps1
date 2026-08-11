<#
.SYNOPSIS
    Apply SecOps-provided passwords to domain AD SQL service accounts (no AD change).

.DESCRIPTION
    Discovers domain AD service accounts for Engine/Agent/SSRS/SSIS (not local users).
    Applies one or more SecOps passwords in a single pass, then restarts once
    (standalone) or AG secondary-restart / failover / former-primary-restart / failback.

.EXAMPLE
    # List domain AD service accounts on a SQL instance
    .\ApplySqlServiceAccountPassword.ps1 -SqlInstance 'HOST\SQL01' -ListAccounts

.EXAMPLE
    # Standalone: update one or more service account passwords, then restart once
    $p1 = ConvertTo-SecureString 'PwForSql' -AsPlainText -Force
    $p2 = ConvertTo-SecureString 'PwForSsrs' -AsPlainText -Force
    .\ApplySqlServiceAccountPassword.ps1 -SqlInstance 'HOST\SQL01' `
        -Account 'DOMAIN\svcSql','DOMAIN\svcSsrs' -SecurePassword $p1,$p2

.EXAMPLE
    # Availability Group: same params; script discovers replicas and does failover/failback
    $p1 = ConvertTo-SecureString 'PwForSql' -AsPlainText -Force
    .\ApplySqlServiceAccountPassword.ps1 -SqlInstance 'HOST\SQL01' `
        -AvailabilityGroup 'AgName' -Account 'DOMAIN\svcSql' -SecurePassword $p1
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

    [switch]$Unattended,

    [switch]$InstallModule,

    [ValidateRange(30, 3600)]
    [int]$SyncTimeoutSeconds = 300,

    [SecureString]$VaultPassword
)

# === CONFIG (edit here) ===
$script:OutputFolder = '\\SERVERNAME\C$\Temp\'
$script:ServiceTypes = @('Engine', 'Agent', 'SSRS', 'SSIS')

$ErrorActionPreference = 'Stop'
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$vaultPath = Join-Path $script:OutputFolder 'SqlServiceAccountVault.xml'
$mutexName = 'Global\SqlServiceAccountVault'
$vaultCanary = 'SqlServiceAccountVault.v2'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Set-RestrictedAcl {
    param([string]$Path, [switch]$Container)
    try {
        $acl = Get-Acl -Path $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($id in 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM') {
            $rule = if ($Container) {
                [Security.AccessControl.FileSystemAccessRule]::new(
                    $id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            } else {
                [Security.AccessControl.FileSystemAccessRule]::new($id, 'FullControl', 'Allow')
            }
            $acl.AddAccessRule($rule)
        }
        Set-Acl -Path $Path -AclObject $acl
    } catch {
        Write-Warning "Could not harden ACLs on $Path : $_"
    }
}

function Get-VaultPasswordInput {
    param([SecureString]$VaultPassword, [switch]$ConfirmNew, [switch]$Unattended)
    if ($VaultPassword -and $VaultPassword.Length -gt 0) { return $VaultPassword }
    if ($Unattended) { throw 'Unattended requires -VaultPassword.' }

    $p1 = Read-Host 'Vault password' -AsSecureString
    if ($p1.Length -lt 12) { throw 'Vault password must be at least 12 characters.' }
    if ($ConfirmNew) {
        $p2 = Read-Host 'Confirm vault password' -AsSecureString
        $a = [Net.NetworkCredential]::new('', $p1).Password
        $b = [Net.NetworkCredential]::new('', $p2).Password
        if ($a -ne $b) { throw 'Vault passwords do not match.' }
    }
    return $p1
}

function Get-VaultAesKey {
    param([SecureString]$VaultPassword, [string]$SaltBase64)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($VaultPassword)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        if ([string]::IsNullOrWhiteSpace($plain)) { throw 'Vault password is empty.' }
        if ($plain.Length -lt 12) { throw 'Vault password must be at least 12 characters.' }

        $pwdBytes = [Text.Encoding]::UTF8.GetBytes($plain)
        $saltBytes = [Convert]::FromBase64String($SaltBase64)
        $combined = New-Object byte[] ($pwdBytes.Length + $saltBytes.Length)
        [Array]::Copy($pwdBytes, 0, $combined, 0, $pwdBytes.Length)
        [Array]::Copy($saltBytes, 0, $combined, $pwdBytes.Length, $saltBytes.Length)

        $sha = [Security.Cryptography.SHA256]::Create()
        try { return $sha.ComputeHash($combined) }
        finally { $sha.Dispose() }
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function New-VaultSalt {
    $bytes = New-Object byte[] 16
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    [Convert]::ToBase64String($bytes)
}

function Protect-Secret {
    param([SecureString]$Secret, [byte[]]$Key)
    ConvertFrom-SecureString -SecureString $Secret -Key $Key
}

function Unprotect-Secret {
    param([string]$CipherText, [byte[]]$Key)
    ConvertTo-SecureString -String $CipherText -Key $Key
}

function Open-PasswordVault {
    param(
        [string]$Path,
        [SecureString]$VaultPassword,
        [switch]$Unattended
    )

    $legacyKey = Join-Path (Split-Path $Path -Parent) 'vault.key'
    if ((Test-Path $Path) -and (Test-Path $legacyKey)) {
        throw 'Found legacy DPAPI vault.key. Delete it and recreate the vault (password-only).'
    }

    if (-not (Test-Path $Path)) {
        Write-Host 'No vault yet - creating a new password-protected vault.' -ForegroundColor Cyan
        $vaultPwd = Get-VaultPasswordInput -VaultPassword $VaultPassword -ConfirmNew -Unattended:$Unattended
        $salt = New-VaultSalt
        $key = Get-VaultAesKey -VaultPassword $vaultPwd -SaltBase64 $salt
        $checkSecret = [System.Security.SecureString]::new()
        foreach ($ch in $vaultCanary.ToCharArray()) { $checkSecret.AppendChar($ch) }
        $checkSecret.MakeReadOnly()
        $doc = @{
            Version  = 2
            Salt     = $salt
            Check    = (Protect-Secret -Secret $checkSecret -Key $key)
            Accounts = @{}
        }
        return @{ Doc = $doc; Key = $key; IsNew = $true }
    }

    $raw = Import-Clixml -Path $Path
    if ($raw -isnot [hashtable]) { $raw = @{} + $raw }

    if (-not $raw.Version -or -not $raw.Salt -or -not $raw.Check) {
        throw "Vault at $Path is not password-protected. Back it up, remove it, and recreate."
    }
    if (-not $raw.Accounts) { $raw.Accounts = @{} }
    if ($raw.Accounts -isnot [hashtable]) { $raw.Accounts = @{} + $raw.Accounts }

    $vaultPwd = Get-VaultPasswordInput -VaultPassword $VaultPassword -Unattended:$Unattended
    $key = Get-VaultAesKey -VaultPassword $vaultPwd -SaltBase64 $raw.Salt
    try {
        $probe = Unprotect-Secret -CipherText $raw.Check -Key $key
        $probePlain = [Net.NetworkCredential]::new('', $probe).Password
        if ($probePlain -ne $vaultCanary) { throw 'Vault password check failed.' }
    } catch {
        throw 'Wrong vault password (or vault is corrupt).'
    }

    return @{ Doc = $raw; Key = $key; IsNew = $false }
}

function Write-VaultAtomic {
    param([hashtable]$Doc, [string]$Path)
    $temp = "$Path.tmp"
    $Doc | Export-Clixml -Path $temp -Force
    $round = Import-Clixml -Path $temp
    if (-not $round.Accounts -or -not $round.Check -or -not $round.Salt) {
        Remove-Item $temp -Force -ErrorAction SilentlyContinue
        throw 'Vault integrity check failed - previous vault untouched.'
    }
    if (Test-Path $Path) { Copy-Item $Path "$Path.bak" -Force }
    Move-Item $temp $Path -Force
    Set-RestrictedAcl -Path $Path
}

function Test-IsDomainServiceAccount {
    # Domain AD service accounts only. Rejects built-ins, gMSA, local MACHINE\user, .\user, bare names.
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
    if ($Credential -and $Computer -notin @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')) {
        return $Credential
    }
    $null
}

function Get-NodeComputer {
    param([string]$Instance, [PSCredential]$Credential)
    $p = @{ ComputerName = $Instance }
    if ($Credential) { $p.Credential = $Credential }
    $resolved = Resolve-DbaNetworkName @p
    if (-not $resolved.FullComputerName) { throw "Could not resolve computer name for $Instance" }
    $resolved.FullComputerName
}

function Get-TargetTopology {
    param(
        [string]$SqlInstance,
        [string[]]$AvailabilityGroup,
        [PSCredential]$SqlCredential,
        [PSCredential]$Credential
    )

    $agParams = @{ SqlInstance = $SqlInstance; EnableException = $true }
    if ($SqlCredential) { $agParams.SqlCredential = $SqlCredential }
    if ($AvailabilityGroup) { $agParams.AvailabilityGroup = $AvailabilityGroup }

    # Standalone throws "HADR is not configured" - treat as Mode=Standalone.
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
        $computer = Get-NodeComputer -Instance $SqlInstance -Credential $Credential
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
            ComputerName = (Get-NodeComputer -Instance $rep -Credential $Credential)
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
        [PSCredential]$Credential
    )

    $all = foreach ($node in $Nodes) {
        $gp = @{
            ComputerName    = $node.ComputerName
            Type            = $script:ServiceTypes
            EnableException = $true
        }
        $svcCred = Get-RemoteCredential -Computer $node.ComputerName -Credential $Credential
        if ($svcCred) { $gp.Credential = $svcCred }
        Get-DbaService @gp
    }
    $all = @($all)
    if (-not $InstanceName) { return $all }

    # Engine/Agent honor -InstanceName; keep host-level SSRS/SSIS.
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

function Restart-SqlTargetService {
    param([string]$Computer, [PSCredential]$Credential)
    $p = @{
        ComputerName    = $Computer
        Type            = $script:ServiceTypes
        Force           = $true
        Confirm         = $false
        EnableException = $true
    }
    if ($Credential) { $p.Credential = $Credential }
    Write-Host "  Restart $($script:ServiceTypes -join '/') on $Computer" -ForegroundColor Cyan
    $result = Restart-DbaService @p
    $bad = @($result | Where-Object { $_.Status -eq 'Failed' -or $_.State -ne 'Running' })
    if ($bad) { throw "Restart failed on ${Computer}: $(($bad.ServiceName) -join ', ')" }
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

function Wait-AgReady {
    param(
        [string]$SqlInstance,
        [string[]]$AgNames,
        [string]$SecondarySqlInstance,
        [PSCredential]$SqlCredential,
        [int]$TimeoutSeconds
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $p = @{ SqlInstance = $SqlInstance; AvailabilityGroup = $AgNames; EnableException = $true }
        if ($SqlCredential) { $p.SqlCredential = $SqlCredential }
        $ags = @(Get-DbaAvailabilityGroup @p)
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
        [PSCredential]$Credential,
        [PSCredential]$SqlCredential,
        [int]$SyncTimeoutSeconds
    )

    $bySql = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $Nodes) { $bySql[$n.SqlInstance] = $n }

    $primarySql = $OriginalPrimary
    if (-not $bySql.ContainsKey($primarySql)) {
        $mapped = $Nodes | Where-Object {
            (Test-ReplicaMatch -ReplicaName $OriginalPrimary -SqlInstance $_.SqlInstance) -or
            ($_.ComputerName -eq $OriginalPrimary.Split('\')[0])
        } | Select-Object -First 1
        $primarySql = $mapped.SqlInstance
    }
    if (-not $primarySql) { throw "Could not map primary '$OriginalPrimary' to discovered nodes." }

    $secondary = $Nodes | Where-Object { $_.SqlInstance -ne $primarySql } | Select-Object -First 1
    if (-not $secondary) { throw 'AG mode requires at least two replicas.' }
    $primary = $bySql[$primarySql]

    Write-Host "`n=== AG apply ===" -ForegroundColor Cyan
    Write-Host "AGs: $($AgNames -join ', ')" -ForegroundColor Cyan
    Write-Host "Primary:   $($primary.SqlInstance) [$($primary.ComputerName)]" -ForegroundColor Cyan
    Write-Host "Secondary: $($secondary.SqlInstance) [$($secondary.ComputerName)]" -ForegroundColor Cyan

    Restart-SqlTargetService -Computer $secondary.ComputerName -Credential (Get-RemoteCredential $secondary.ComputerName $Credential)
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

    Restart-SqlTargetService -Computer $primary.ComputerName -Credential (Get-RemoteCredential $primary.ComputerName $Credential)
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

function Write-VaultHistoryCsv {
    param([hashtable]$Doc, [string]$Path)
    $Doc.Accounts.Keys | ForEach-Object {
        $e = $Doc.Accounts[$_]
        [pscustomobject]@{
            Account          = $_
            LastComputerName = $e.LastComputerName
            LastTopology     = $e.LastTopology
            LastNodes        = $e.LastNodes
            LastServices     = $e.LastServices
            LastRotatedUtc   = $e.LastRotatedUtc
            LastRotatedBy    = $e.LastRotatedBy
            Source           = $e.Source
        }
    } | Sort-Object Account | Export-Csv -Path $Path -NoTypeInformation -Force
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if (-not (Test-Path $script:OutputFolder)) {
    New-Item $script:OutputFolder -ItemType Directory -Force | Out-Null
    Set-RestrictedAcl -Path $script:OutputFolder -Container
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

    $topo = Get-TargetTopology -SqlInstance $SqlInstance -AvailabilityGroup $AvailabilityGroup `
        -SqlCredential $SqlCredential -Credential $Credential

    Write-Host "`nMode: $($topo.Mode)" -ForegroundColor Cyan
    $topo.Nodes | Format-Table ComputerName, SqlInstance -AutoSize
    if ($topo.AgNames) { Write-Host "AGs: $($topo.AgNames -join ', ')" -ForegroundColor Cyan }

    $computers = @($topo.Nodes.ComputerName | Select-Object -Unique)
    $allServices = @(Get-SqlTargetService -Nodes $topo.Nodes -InstanceName $InstanceName -Credential $Credential)
    if (-not $allServices) {
        throw "No $($script:ServiceTypes -join '/') services on: $($computers -join ', ')"
    }

    Write-Host "`nServices:" -ForegroundColor Cyan
    $allServices | Select-Object ComputerName, ServiceName, ServiceType, State, StartName | Format-Table -AutoSize

    $domainAccounts = @(Get-DomainSqlServiceAccount -Services $allServices)
    $listView = {
        $domainAccounts | Select-Object Account, ServiceTypes, ServiceCount, Computers, Services
    }

    if ($ListAccounts) {
        Write-Host "`nDomain AD service accounts (Engine/Agent/SSRS/SSIS):" -ForegroundColor Cyan
        if (-not $domainAccounts) {
            Write-Warning 'No domain AD service accounts found.'
            return
        }
        & $listView | Format-Table -AutoSize
        & $listView | Write-Output
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
            Write-Warning "Password supplied for '$name' but account not found on this topology."
        }
    }

    if (-not $targets) {
        throw 'No matching domain accounts to update. Use -ListAccounts, then pass matching -Account/-SecurePassword pairs.'
    }

    Write-Host "`nPlan: apply SecOps password(s) to $($targets.Count) account(s), then restart once" -ForegroundColor Cyan
    Write-Host 'No AD password change will be performed.' -ForegroundColor Yellow

    $mutex = [Threading.Mutex]::new($false, $mutexName)
    $gotLock = $false
    try {
        try { $gotLock = $mutex.WaitOne([TimeSpan]::FromSeconds(60)) }
        catch [Threading.AbandonedMutexException] {
            Write-Warning 'Recovered abandoned vault lock.'
            $gotLock = $true
        }
        if (-not $gotLock) { throw 'Vault lock timeout (60s).' }

        $unattend = [bool]$Unattended
        $opened = Open-PasswordVault -Path $vaultPath -VaultPassword $VaultPassword -Unattended:$unattend
        $vaultDoc = $opened.Doc
        $vaultKey = $opened.Key

        if ($opened.IsNew) {
            Write-VaultAtomic -Doc $vaultDoc -Path $vaultPath
            Write-Host "Vault created: $vaultPath" -ForegroundColor Cyan
        }

        $anyFailures = $false
        $seedComputer = $topo.Nodes[0].ComputerName
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
                    $result = Update-NodeServicePassword -Services $nodeServices -SecurePassword $securePwd -Credential $svcCred
                    if ($result.Status -contains 'Failed') {
                        Write-Host "  FAILED @ ${computer}: $((($result | Where-Object Status -eq Failed).Message) -join '; ')" -ForegroundColor Red
                        $ok = $false; $anyFailures = $true
                    }
                } catch {
                    Write-Host "  FAILED @ ${computer}: $_" -ForegroundColor Red
                    $ok = $false; $anyFailures = $true
                }
            }

            if ($ok) {
                $vaultDoc.Accounts[$acct] = @{
                    EncryptedPassword = Protect-Secret -Secret $securePwd -Key $vaultKey
                    LastComputerName  = $seedComputer
                    LastTopology      = $topo.Mode
                    LastNodes         = ($computers -join ', ')
                    LastServices      = (($row.Group | ForEach-Object { "$($_.ComputerName)\$($_.ServiceName)" }) -join ', ')
                    LastRotatedUtc    = (Get-Date).ToUniversalTime().ToString('u')
                    LastRotatedBy     = "$env:USERDOMAIN\$env:USERNAME"
                    Source            = 'SecOpsProvided'
                }
                Write-VaultAtomic -Doc $vaultDoc -Path $vaultPath
                $updatedAccounts.Add($acct)
                Write-Host '  Saved to vault (not restarted yet).' -ForegroundColor Green
            }
        }

        if (-not $anyFailures) {
            if ($topo.Mode -eq 'AvailabilityGroup') {
                Invoke-GracefulAgApply `
                    -Nodes $topo.Nodes `
                    -AgNames $topo.AgNames `
                    -OriginalPrimary $topo.OriginalPrimary `
                    -Credential $Credential `
                    -SqlCredential $SqlCredential `
                    -SyncTimeoutSeconds $SyncTimeoutSeconds
            } else {
                $node = $topo.Nodes[0]
                Restart-SqlTargetService -Computer $node.ComputerName `
                    -Credential (Get-RemoteCredential $node.ComputerName $Credential)
            }
        }

        $reportPath = Join-Path $script:OutputFolder 'SqlServiceAccountVault_History.csv'
        Write-VaultHistoryCsv -Doc $vaultDoc -Path $reportPath

        Write-Host "`nVault:   $vaultPath (password-protected)" -ForegroundColor Cyan
        Write-Host "History: $reportPath (no secrets)" -ForegroundColor Cyan
        if ($updatedAccounts.Count) {
            Write-Host "`nUpdated account(s): $($updatedAccounts -join ', ')" -ForegroundColor Green
        }

        if ($anyFailures) { Write-Warning 'One or more updates failed.'; exit 1 }
    } finally {
        if ($gotLock) { [void]$mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
} finally {
    Stop-Transcript | Out-Null
}
