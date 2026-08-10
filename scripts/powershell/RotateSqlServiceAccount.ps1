<#
.SYNOPSIS
    Rotate SQL Engine/Agent service account passwords (standalone or Always On).

.DESCRIPTION
    One entry point: -SqlInstance.

      1. Connect and detect topology (standalone vs AG replicas)
      2. For domain accounts: reset AD password once, then Update-DbaServiceAccount -NoRestart on every node
      3. Save ciphertext to a password-protected vault (one team password, no key file)
      4. Apply:
           Standalone -> Restart-DbaService
           AG        -> restart secondary -> Invoke-DbaAgFailover -> restart former primary -> fail back

    Vault (KISS)
      - One file: SqlServiceAccountVault.xml
      - Secrets encrypted with AES key = SHA256(password + salt)
      - Salt + password-check canary stored in the file
      - ACL: Administrators + SYSTEM
      - Open from any machine if you know the vault password
      - Prefer gMSA when possible (script skips those)

.PARAMETER SqlInstance
    Any replica or standalone instance. AG partner nodes are discovered automatically.
    Not required with -ListVault / -RevealAccount.

.PARAMETER VaultPassword
    Password that protects the vault. Prompted if omitted.
    Required for -Unattended (cannot prompt).

.PARAMETER ListVault
    List vault account metadata (no secrets) and exit.

.PARAMETER RevealAccount
    Decrypt and print one account password, then exit.

.EXAMPLE
    .\RotateSqlServiceAccount.ps1 -SqlInstance SQL01

.EXAMPLE
    $vp = Read-Host 'Vault password' -AsSecureString
    .\RotateSqlServiceAccount.ps1 -SqlInstance SQL01 -AvailabilityGroup AG1 -VaultPassword $vp -Unattended -Confirm:$false

.EXAMPLE
    .\RotateSqlServiceAccount.ps1 -ListVault
    .\RotateSqlServiceAccount.ps1 -RevealAccount 'CONTOSO\sqlsvc'
#>
# Interactive ops script: Write-Host is intentional. Helpers are gated by script-level ShouldProcess.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
[CmdletBinding(DefaultParameterSetName = 'Rotate', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Rotate')]
    [string]$SqlInstance,

    [Parameter(ParameterSetName = 'Rotate')]
    [string[]]$AvailabilityGroup,

    [Parameter(ParameterSetName = 'Rotate')]
    [string[]]$InstanceName,

    [Parameter(ParameterSetName = 'Rotate')]
    [PSCredential]$Credential,

    [Parameter(ParameterSetName = 'Rotate')]
    [PSCredential]$SqlCredential,

    [Parameter(ParameterSetName = 'Rotate')]
    [bool]$IncludeDomain = $true,

    [Parameter(ParameterSetName = 'Rotate')]
    [switch]$SkipAdPasswordReset,

    [Parameter(ParameterSetName = 'Rotate')]
    [switch]$SkipRestart,

    [Parameter(ParameterSetName = 'Rotate')]
    [switch]$SkipFailback,

    [Parameter(ParameterSetName = 'Rotate')]
    [switch]$Unattended,

    [Parameter(ParameterSetName = 'Rotate')]
    [switch]$InstallModule,

    [Parameter(ParameterSetName = 'Rotate')]
    [ValidateRange(12, 128)]
    [int]$PasswordLength = 18,

    [Parameter(ParameterSetName = 'Rotate')]
    [ValidateRange(30, 3600)]
    [int]$SyncTimeoutSeconds = 300,

    [Parameter(ParameterSetName = 'ListVault', Mandatory)]
    [switch]$ListVault,

    [Parameter(ParameterSetName = 'Reveal', Mandatory)]
    [string]$RevealAccount,

    [SecureString]$VaultPassword,

    [string]$OutputFolder = $(Join-Path $env:ProgramData 'SqlServiceAccountVault')
)

$ErrorActionPreference = 'Stop'
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$vaultPath = Join-Path $OutputFolder 'SqlServiceAccountVault.xml'
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

function Get-StrongPassword {
    param([int]$Length = 18)
    $sets = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ'
        'abcdefghijkmnopqrstuvwxyz'
        '23456789'
        '!@#$%^&*_-+='
    )
    $all = -join $sets
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $nextIndex = {
            param([int]$Max)
            $b = [byte[]]::new(4)
            do { $rng.GetBytes($b); $v = [BitConverter]::ToUInt32($b, 0) }
            while ($v -ge ([uint32]::MaxValue - ([uint32]::MaxValue % [uint32]$Max)))
            [int]($v % [uint32]$Max)
        }

        $chars = [System.Collections.Generic.List[char]]::new()
        foreach ($s in $sets) {
            $idx = & $nextIndex $s.Length
            $chars.Add($s[$idx])
        }
        while ($chars.Count -lt $Length) {
            $idx = & $nextIndex $all.Length
            $chars.Add($all[$idx])
        }
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $j = & $nextIndex ($i + 1)
            $t = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $t
        }

        $secure = [System.Security.SecureString]::new()
        foreach ($ch in $chars) { $secure.AppendChar($ch) }
        $secure.MakeReadOnly()
        return $secure
    } finally {
        $rng.Dispose()
    }
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

function Test-IsDomainAccount {
    param([string]$Account, [string]$Computer)
    ($Account -match '\\') -and ($Account -notmatch "^$([regex]::Escape($Computer))\\|^\.\\")
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

    $ags = @(Get-DbaAvailabilityGroup @agParams)

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

function Reset-DomainAccountPassword {
    param([string]$Account, [securestring]$SecurePassword, [string]$LocalComputer)
    if (-not (Test-IsDomainAccount -Account $Account -Computer $LocalComputer)) { return }

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw @"
Domain account '$Account' needs Set-ADAccountPassword, but ActiveDirectory module is missing.
Install RSAT ActiveDirectory, or reset AD yourself and re-run with -SkipAdPasswordReset.
"@
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    $sam = $Account.Split('\')[-1]
    Write-Host "  AD: Set-ADAccountPassword $sam" -ForegroundColor DarkCyan
    Set-ADAccountPassword -Identity $sam -NewPassword $SecurePassword -Reset -ErrorAction Stop
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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [object[]]$Nodes,
        [string[]]$AgNames,
        [string]$OriginalPrimary,
        [string[]]$InstanceName,
        [PSCredential]$Credential,
        [PSCredential]$SqlCredential,
        [int]$SyncTimeoutSeconds,
        [switch]$SkipFailback
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

    if (-not $PSCmdlet.ShouldProcess($secondary.ComputerName, 'Restart secondary')) { return }
    Restart-SqlEngineAgent -Computer $secondary.ComputerName -InstanceName $InstanceName -Credential $Credential
    Wait-AgReady -SqlInstance $primary.SqlInstance -AgNames $AgNames -SecondarySqlInstance $secondary.SqlInstance `
        -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds

    if (-not $PSCmdlet.ShouldProcess($secondary.SqlInstance, "Failover $($AgNames -join ', ')")) { return }
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

    if (-not $PSCmdlet.ShouldProcess($primary.ComputerName, 'Restart former primary')) { return }
    Restart-SqlEngineAgent -Computer $primary.ComputerName -InstanceName $InstanceName -Credential $Credential
    Wait-AgReady -SqlInstance $secondary.SqlInstance -AgNames $AgNames -SecondarySqlInstance $primary.SqlInstance `
        -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds

    if ($SkipFailback) {
        Write-Warning "SkipFailback: primary left on $($secondary.SqlInstance)"
        return
    }

    if (-not $PSCmdlet.ShouldProcess($primary.SqlInstance, "Failback $($AgNames -join ', ')")) { return }
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

function Show-VaultAccount {
    param([hashtable]$Doc)
    $accounts = $Doc.Accounts
    if (-not $accounts.Keys.Count) {
        Write-Host 'Vault is empty.' -ForegroundColor Yellow
        return
    }
    $accounts.Keys | Sort-Object | ForEach-Object {
        $e = $accounts[$_]
        [pscustomobject]@{
            Account          = $_
            LastComputerName = $e.LastComputerName
            LastTopology     = $e.LastTopology
            LastNodes        = $e.LastNodes
            LastServices     = $e.LastServices
            LastRotatedUtc   = $e.LastRotatedUtc
            LastRotatedBy    = $e.LastRotatedBy
        }
    } | Format-Table -AutoSize
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
        }
    } | Sort-Object Account | Export-Csv -Path $Path -NoTypeInformation -Force
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if (-not (Test-Path $OutputFolder)) {
    New-Item $OutputFolder -ItemType Directory -Force | Out-Null
    Set-RestrictedAcl -Path $OutputFolder -Container
}

$transcript = $PSCmdlet.ParameterSetName -eq 'Rotate'
if ($transcript) {
    Start-Transcript -Path (Join-Path $OutputFolder "RotateSqlServiceAccount_$timestamp.log") -NoClobber | Out-Null
}

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

        # ---- Vault-only modes ----
        if ($ListVault) {
            Show-VaultAccount -Doc $vaultDoc
            return
        }

        if ($RevealAccount) {
            if (-not $vaultDoc.Accounts.ContainsKey($RevealAccount)) {
                throw "Account '$RevealAccount' not found in vault. Use -ListVault."
            }
            $secure = Unprotect-Secret -CipherText $vaultDoc.Accounts[$RevealAccount].EncryptedPassword -Key $vaultKey
            $plain = [Net.NetworkCredential]::new('', $secure).Password
            Write-Host "Account: $RevealAccount" -ForegroundColor Cyan
            Write-Output $plain
            $secure.Dispose()
            return
        }

        # ---- Rotate mode ----
        if (-not (Get-Module -ListAvailable -Name dbatools)) {
            if (-not $InstallModule) { throw 'dbatools missing. Install it or pass -InstallModule.' }
            Install-Module dbatools -Scope CurrentUser -Force -AllowClobber
        }
        Import-Module dbatools -ErrorAction Stop

        $topo = Get-TargetTopology -SqlInstance $SqlInstance -AvailabilityGroup $AvailabilityGroup `
            -SqlCredential $SqlCredential -Credential $Credential

        Write-Host "`nMode: $($topo.Mode)" -ForegroundColor Cyan
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
            $true
        }
        if (-not $groups) { Write-Warning 'No eligible accounts.'; return }

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
            } elseif (-not $PSCmdlet.ShouldProcess(($conflicts.Account -join ', '), 'Rotate shared account')) {
                return
            }
        }
        if (-not $groups) {
            if ($skippedConflicts) { exit 2 }
            Write-Warning 'Nothing to rotate.'; return
        }

        Write-Host "`nPlan: $($groups.Count) account(s) on $($computers -join ', ')" -ForegroundColor Cyan
        if (-not $PSCmdlet.ShouldProcess("$($groups.Count) account(s)", 'Rotate password')) { return }

        $anyFailures = $false
        $seedComputer = $topo.Nodes[0].ComputerName

        foreach ($g in $groups) {
            $account = $g.Name
            if (-not $PSCmdlet.ShouldProcess($account, 'Rotate password')) { continue }

            Write-Host "`nRotating: $account" -ForegroundColor Green
            $securePwd = Get-StrongPassword -Length $PasswordLength
            $ok = $true

            if (-not $SkipAdPasswordReset) {
                try {
                    Reset-DomainAccountPassword -Account $account -SecurePassword $securePwd -LocalComputer $seedComputer
                } catch {
                    Write-Host "  FAILED (AD): $_" -ForegroundColor Red
                    $ok = $false; $anyFailures = $true
                }
            }

            foreach ($computer in @($g.Group.ComputerName | Select-Object -Unique)) {
                if (-not $ok) { break }
                $nodeServices = @($g.Group | Where-Object ComputerName -eq $computer)
                $svcCred = $null
                $remote = $computer -notin @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
                if ($Credential -and $remote) { $svcCred = $Credential }
                try {
                    Write-Host "  Update-DbaServiceAccount -NoRestart @ $computer" -ForegroundColor DarkCyan
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
                $vaultDoc.Accounts[$account] = @{
                    EncryptedPassword = Protect-Secret -Secret $securePwd -Key $vaultKey
                    LastComputerName  = $seedComputer
                    LastTopology      = $topo.Mode
                    LastNodes         = ($computers -join ', ')
                    LastServices      = (($g.Group | ForEach-Object { "$($_.ComputerName)\$($_.ServiceName)" }) -join ', ')
                    LastRotatedUtc    = (Get-Date).ToUniversalTime().ToString('u')
                    LastRotatedBy     = "$env:USERDOMAIN\$env:USERNAME"
                }
                Write-VaultAtomic -Doc $vaultDoc -Path $vaultPath
                Write-Host '  Saved to password-protected vault (not restarted yet).' -ForegroundColor Green
            }

            if ($securePwd) { $securePwd.Dispose(); Remove-Variable securePwd -EA SilentlyContinue }
        }

        if (-not $SkipRestart -and -not $anyFailures) {
            if ($topo.Mode -eq 'AvailabilityGroup') {
                $roll = @{
                    Nodes              = $topo.Nodes
                    AgNames            = $topo.AgNames
                    OriginalPrimary    = $topo.OriginalPrimary
                    InstanceName       = $InstanceName
                    Credential         = $Credential
                    SqlCredential      = $SqlCredential
                    SyncTimeoutSeconds = $SyncTimeoutSeconds
                    SkipFailback       = $SkipFailback
                }
                if ($Unattended -or $ConfirmPreference -eq 'None') { $roll.Confirm = $false }
                Invoke-GracefulAgApply @roll
            } else {
                $node = $topo.Nodes[0]
                if ($PSCmdlet.ShouldProcess($node.ComputerName, 'Restart Engine/Agent')) {
                    $svcCred = $null
                    $remote = $node.ComputerName -notin @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
                    if ($Credential -and $remote) { $svcCred = $Credential }
                    Restart-SqlEngineAgent -Computer $node.ComputerName -InstanceName $InstanceName -Credential $svcCred
                }
            }
        } elseif ($SkipRestart) {
            Write-Warning 'SkipRestart: password updated; restart/failover later to apply.'
        }

        $reportPath = Join-Path $OutputFolder 'SqlServiceAccountVault_History.csv'
        Write-VaultHistoryCsv -Doc $vaultDoc -Path $reportPath

        Write-Host "`nVault:   $vaultPath (password-protected)" -ForegroundColor Cyan
        Write-Host "History: $reportPath (no secrets)" -ForegroundColor Cyan

        if ($anyFailures) { Write-Warning 'One or more updates failed.'; exit 1 }
        if ($skippedConflicts) { Write-Warning "$($skippedConflicts.Count) shared account(s) skipped."; exit 2 }
    } finally {
        if ($gotLock) { [void]$mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
} finally {
    if ($transcript) { Stop-Transcript | Out-Null }
}
