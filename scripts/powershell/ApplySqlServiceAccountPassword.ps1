<#
.SYNOPSIS
    Apply a SecOps-provided password to SQL Engine/Agent services (no AD change, no password generation).

.DESCRIPTION
    Use when SecOps already reset the domain account password.
    Same apply path as RotateSqlServiceAccount: update service logon cache,
    vault the password, then always restart (standalone) or AG
    secondary-restart / failover / former-primary-restart / failback.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
[CmdletBinding(DefaultParameterSetName = 'BySqlInstance')]
param(
    [Parameter(Mandatory, ParameterSetName = 'BySqlInstance')]
    [string]$SqlInstance,

    [Parameter(ParameterSetName = 'BySqlInstance')]
    [string[]]$AvailabilityGroup,

    [Parameter(Mandatory, ParameterSetName = 'ByComputer')]
    [string[]]$ComputerName,

    [Parameter(Mandatory)]
    [SecureString]$SecurePassword,

    [string]$Account,

    [string[]]$InstanceName,

    [PSCredential]$Credential,

    [PSCredential]$SqlCredential,

    [bool]$IncludeDomain = $true,

    [switch]$Unattended,

    [switch]$InstallModule,

    [ValidateRange(30, 3600)]
    [int]$SyncTimeoutSeconds = 300,

    [SecureString]$VaultPassword
)

# === CONFIG (edit here) ===
# Shared UNC for vault + history + transcripts. Change once for the environment.
$script:OutputFolder = '\\SERVERNAME\C$\Temp\'

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
    <#
      Returns @{ Doc = hashtable; Key = byte[]; Password = SecureString }
      Doc shape:
        Version, Salt, Check, Accounts = @{ account = @{ EncryptedPassword; ... } }
    #>
    param(
        [string]$Path,
        [SecureString]$VaultPassword,
        [switch]$Unattended
    )

    $legacyKey = Join-Path (Split-Path $Path -Parent) 'vault.key'
    if ((Test-Path $Path) -and (Test-Path $legacyKey)) {
        throw @"
Found legacy DPAPI vault.key next to the vault.
Delete vault.key (and preferably recreate the vault) - this script now uses a password only.
"@
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
        return @{ Doc = $doc; Key = $key; Password = $vaultPwd; IsNew = $true }
    }

    $raw = Import-Clixml -Path $Path
    # Normalize
    if ($raw -isnot [hashtable]) { $raw = @{} + $raw }

    if (-not $raw.Version -or -not $raw.Salt -or -not $raw.Check) {
        throw @"
Vault at $Path is not password-protected (missing Version/Salt/Check).
This is likely a legacy vault. Back it up, remove it, and let the script create a new one.
"@
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

    return @{ Doc = $raw; Key = $key; Password = $vaultPwd; IsNew = $false }
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

function Test-AccountEligible {
    param([string]$StartName, [string]$ForComputer, [bool]$IncludeDomain)
    if ($StartName -match '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\)') {
        return @{ Ok = $false; Reason = 'built-in' }
    }
    if ($StartName -match '\$$') { return @{ Ok = $false; Reason = 'gMSA' } }
    $local = $StartName -match "^$([regex]::Escape($ForComputer))\\|^\.\\"
    if (($StartName -match '\\') -and (-not $local) -and (-not $IncludeDomain)) {
        return @{ Ok = $false; Reason = 'domain (pass -IncludeDomain)' }
    }
    @{ Ok = $true; Reason = $null }
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

    # Standalone instances throw from Get-DbaAvailabilityGroup ("HADR is not configured").
    # Treat that as Mode=Standalone. Real connection failures still bubble up.
    $ags = @()
    try {
        $ags = @(Get-DbaAvailabilityGroup @agParams)
    } catch {
        $msg = [string]$_
        $isNoHadr = $msg -match 'HADR|Availability Group|not configured|is not enabled'
        if (-not $isNoHadr) { throw }
        if ($AvailabilityGroup) {
            throw "Instance $SqlInstance has no HADR/AG configured, but -AvailabilityGroup was specified."
        }
        $ags = @()
    }

    if (-not $ags) {
        $computer = Get-NodeComputer -Instance $SqlInstance -Credential $Credential
        return [pscustomobject]@{
            Mode            = 'Standalone'
            SeedSqlInstance = $SqlInstance
            Nodes           = @([pscustomobject]@{ ComputerName = $computer; SqlInstance = $SqlInstance })
            AgNames         = @()
            OriginalPrimary = $SqlInstance
        }
    }

    $agNames = @($ags.Name | Select-Object -Unique)
    $replicaSql = @(
        $ags |
            ForEach-Object { $_.AvailabilityReplicas.Name } |
            Select-Object -Unique
    )
    if ($replicaSql.Count -lt 1) { throw "AGs found ($($agNames -join ', ')) but no replicas." }

    $nodes = foreach ($rep in $replicaSql) {
        [pscustomobject]@{
            ComputerName = (Get-NodeComputer -Instance $rep -Credential $Credential)
            SqlInstance  = $rep
        }
    }

    $nodes = @($nodes | Group-Object ComputerName | ForEach-Object {
            $_.Group | Select-Object -First 1
        })

    [pscustomobject]@{
        Mode            = 'AvailabilityGroup'
        SeedSqlInstance = $SqlInstance
        Nodes           = $nodes
        AgNames         = $agNames
        OriginalPrimary = $ags[0].PrimaryReplicaServerName
    }
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

function Restart-SqlEngineAgent {
    param([string]$Computer, [string[]]$InstanceName, [PSCredential]$Credential)
    $p = @{
        ComputerName    = $Computer
        Type            = 'Engine', 'Agent'
        Force           = $true
        Confirm         = $false
        EnableException = $true
    }
    if ($InstanceName) { $p.InstanceName = $InstanceName }
    if ($Credential) { $p.Credential = $Credential }
    Write-Host "  Restart Engine/Agent on $Computer" -ForegroundColor Cyan
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
        [string[]]$InstanceName,
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

    Restart-SqlEngineAgent -Computer $secondary.ComputerName -InstanceName $InstanceName -Credential $Credential
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

    Restart-SqlEngineAgent -Computer $primary.ComputerName -InstanceName $InstanceName -Credential $Credential
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
if ($SecurePassword.Length -lt 1) { throw '-SecurePassword is empty.' }

if (-not (Test-Path $script:OutputFolder)) {
    New-Item $script:OutputFolder -ItemType Directory -Force | Out-Null
    Set-RestrictedAcl -Path $script:OutputFolder -Container
}

Start-Transcript -Path (Join-Path $script:OutputFolder "ApplySqlServiceAccountPassword_$timestamp.log") -NoClobber | Out-Null

try {
    $mutex = [Threading.Mutex]::new($false, $mutexName)
    $gotLock = $false
    try {
        try { $gotLock = $mutex.WaitOne([TimeSpan]::FromSeconds(60)) }
        catch [Threading.AbandonedMutexException] {
            Write-Warning 'Recovered abandoned vault lock.'
            $gotLock = $true
        }
        if (-not $gotLock) { throw 'Vault lock timeout (60s).' }

        $unattend = $PSBoundParameters.ContainsKey('Unattended') -and $Unattended
        $opened = Open-PasswordVault -Path $vaultPath -VaultPassword $VaultPassword -Unattended:$unattend
        $vaultDoc = $opened.Doc
        $vaultKey = $opened.Key

        if ($opened.IsNew) {
            Write-VaultAtomic -Doc $vaultDoc -Path $vaultPath
            Write-Host "Vault created: $vaultPath" -ForegroundColor Cyan
        }

        if (-not (Get-Module -ListAvailable -Name dbatools)) {
            if (-not $InstallModule) { throw 'dbatools missing. Install it or pass -InstallModule.' }
            Install-Module dbatools -Scope CurrentUser -Force -AllowClobber
        }
        Import-Module dbatools -ErrorAction Stop
        Set-DbatoolsConfig -FullName sql.connection.encrypt -Value $true
        Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true

        # Topology: SqlInstance (+ AG discover) OR explicit ComputerName (server-level only)
        if ($PSCmdlet.ParameterSetName -eq 'ByComputer') {
            $nodes = foreach ($c in $ComputerName) {
                [pscustomobject]@{ ComputerName = $c; SqlInstance = $c }
            }
            $topo = [pscustomobject]@{
                Mode            = 'Standalone'
                SeedSqlInstance = $ComputerName[0]
                Nodes           = @($nodes)
                AgNames         = @()
                OriginalPrimary = $ComputerName[0]
            }
        } else {
            $topo = Get-TargetTopology -SqlInstance $SqlInstance -AvailabilityGroup $AvailabilityGroup `
                -SqlCredential $SqlCredential -Credential $Credential
        }

        Write-Host "`nMode: $($topo.Mode)  |  AD update: skipped (SecOps-provided password)" -ForegroundColor Cyan
        $topo.Nodes | Format-Table ComputerName, SqlInstance -AutoSize
        if ($topo.AgNames) { Write-Host "AGs: $($topo.AgNames -join ', ')" -ForegroundColor Cyan }

        $computers = @($topo.Nodes.ComputerName | Select-Object -Unique)

        $allServices = foreach ($node in $topo.Nodes) {
            $svcCred = $null
            $remote = $node.ComputerName -notin @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
            if ($Credential -and $remote) { $svcCred = $Credential }
            $gp = @{
                ComputerName = $node.ComputerName; Type = 'Engine', 'Agent'; EnableException = $true
            }
            if ($InstanceName) { $gp.InstanceName = $InstanceName }
            if ($svcCred) { $gp.Credential = $svcCred }
            Get-DbaService @gp
        }
        $allServices = @($allServices)
        if (-not $allServices) { throw "No Engine/Agent services on: $($computers -join ', ')" }

        Write-Host "`nServices:" -ForegroundColor Cyan
        $allServices | Select-Object ComputerName, ServiceName, State, StartName | Format-Table -AutoSize

        $groups = $allServices | Group-Object StartName | Where-Object {
            $c = Test-AccountEligible -StartName $_.Name -ForComputer @($_.Group.ComputerName)[0] -IncludeDomain $IncludeDomain
            if (-not $c.Ok) { Write-Host "Skip $($_.Name): $($c.Reason)" -ForegroundColor Yellow; return $false }
            if ($Account -and ($_.Name -ne $Account)) {
                Write-Host "Skip $($_.Name): not -Account $Account" -ForegroundColor Yellow
                return $false
            }
            $true
        }
        if (-not $groups) { Write-Warning 'No eligible accounts to update.'; return }

        if (-not $Account -and @($groups).Count -gt 1) {
            throw ("Multiple eligible accounts found ({0}). Pass -Account to select which one receives the SecOps password." -f ((@($groups).Name) -join ', '))
        }

        # Same shared-account guard as RotateSqlServiceAccount
        $allowed = [Collections.Generic.HashSet[string]]::new([string[]]$computers, [StringComparer]::OrdinalIgnoreCase)
        $conflicts = foreach ($g in $groups) {
            if (-not $vaultDoc.Accounts.ContainsKey($g.Name)) { continue }
            $prev = $vaultDoc.Accounts[$g.Name].LastComputerName
            if ($prev -and -not $allowed.Contains($prev)) {
                [pscustomobject]@{
                    Account         = $g.Name
                    PreviousServer  = $prev
                    PreviousRotated = $vaultDoc.Accounts[$g.Name].LastRotatedUtc
                }
            }
        }

        $skippedConflicts = @()
        if ($conflicts) {
            Write-Host "`n*** SHARED ACCOUNT (outside this topology) ***" -ForegroundColor Red
            $conflicts | Format-Table -AutoSize
            if ($Unattended) {
                $names = @($conflicts.Account)
                $skippedConflicts = @($groups | Where-Object Name -in $names)
                $groups = @($groups | Where-Object Name -notin $names)
                Write-Warning "Unattended: skipped $($names -join ', ')"
            } else {
                Write-Warning 'Proceeding with shared account update (maintenance).'
            }
        }
        if (-not $groups) {
            if ($skippedConflicts) { exit 2 }
            Write-Warning 'Nothing to update.'; return
        }

        Write-Host "`nPlan: apply SecOps password to $($groups.Count) account(s) on $($computers -join ', ')" -ForegroundColor Cyan
        Write-Host 'No AD password change will be performed.' -ForegroundColor Yellow

        $anyFailures = $false
        $seedComputer = $topo.Nodes[0].ComputerName
        $updatedAccounts = [System.Collections.Generic.List[string]]::new()

        foreach ($g in $groups) {
            $acct = $g.Name
            Write-Host "`nApplying password: $acct" -ForegroundColor Green
            $ok = $true

            foreach ($computer in @($g.Group.ComputerName | Select-Object -Unique)) {
                if (-not $ok) { break }
                $nodeServices = @($g.Group | Where-Object ComputerName -eq $computer)
                $svcCred = $null
                $remote = $computer -notin @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
                if ($Credential -and $remote) { $svcCred = $Credential }
                try {
                    Write-Host "  Update-DbaServiceAccount -NoRestart @ $computer" -ForegroundColor DarkCyan
                    $result = Update-NodeServicePassword -Services $nodeServices -SecurePassword $SecurePassword -Credential $svcCred
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
                    EncryptedPassword = Protect-Secret -Secret $SecurePassword -Key $vaultKey
                    LastComputerName  = $seedComputer
                    LastTopology      = $topo.Mode
                    LastNodes         = ($computers -join ', ')
                    LastServices      = (($g.Group | ForEach-Object { "$($_.ComputerName)\$($_.ServiceName)" }) -join ', ')
                    LastRotatedUtc    = (Get-Date).ToUniversalTime().ToString('u')
                    LastRotatedBy     = "$env:USERDOMAIN\$env:USERNAME"
                    Source            = 'SecOpsProvided'
                }
                Write-VaultAtomic -Doc $vaultDoc -Path $vaultPath
                $updatedAccounts.Add($acct)
                Write-Host '  Saved to password-protected vault (not restarted yet).' -ForegroundColor Green
            }
        }

        # Restart / AG failover+failback is mandatory (no skip switches)
        if (-not $anyFailures) {
            if ($topo.Mode -eq 'AvailabilityGroup') {
                Invoke-GracefulAgApply `
                    -Nodes $topo.Nodes `
                    -AgNames $topo.AgNames `
                    -OriginalPrimary $topo.OriginalPrimary `
                    -InstanceName $InstanceName `
                    -Credential $Credential `
                    -SqlCredential $SqlCredential `
                    -SyncTimeoutSeconds $SyncTimeoutSeconds
            } elseif ($PSCmdlet.ParameterSetName -eq 'ByComputer') {
                # Explicit server list: restart each listed computer
                foreach ($node in $topo.Nodes) {
                    $svcCred = $null
                    $remote = $node.ComputerName -notin @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
                    if ($Credential -and $remote) { $svcCred = $Credential }
                    Restart-SqlEngineAgent -Computer $node.ComputerName -InstanceName $InstanceName -Credential $svcCred
                }
            } else {
                # Match RotateSqlServiceAccount standalone: restart seed node only
                $node = $topo.Nodes[0]
                $svcCred = $null
                $remote = $node.ComputerName -notin @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
                if ($Credential -and $remote) { $svcCred = $Credential }
                Restart-SqlEngineAgent -Computer $node.ComputerName -InstanceName $InstanceName -Credential $svcCred
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
        if ($skippedConflicts) { Write-Warning "$($skippedConflicts.Count) shared account(s) skipped."; exit 2 }
    } finally {
        if ($gotLock) { [void]$mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
} finally {
    Stop-Transcript | Out-Null
}
