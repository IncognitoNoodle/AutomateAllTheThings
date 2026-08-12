<#
.SYNOPSIS
    Rotate SQL Engine/Agent/SSRS/SSIS service account passwords (standalone or Always On).

.NOTES
    Order: Set-ADAccountPassword first, vault immediately, wait until the password validates
    on the management host AND each SQL node (WinRM), then Update-DbaServiceAccount -NoRestart,
    then restart. Jump-box ValidateCredentials alone can race site DC replication.

    Vault mutex (Global\SqlServiceAccountVault) is held only during vault file open/read/write,
    not during AD waits, service updates, or restarts — so other operators can use the vault
    while a long rotate is waiting on replication.

    Domain Kerberos WinRM encrypts the remoting session used for per-node checks.
    Prefer Kerberos; avoid Basic auth / CredSSP. HTTPS WinRM is optional environment
    hardening and is not required by this script.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
[CmdletBinding(DefaultParameterSetName = 'Rotate')]
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
    [int]$PasswordLength = 24,

    [Parameter(ParameterSetName = 'Rotate')]
    [ValidateRange(30, 3600)]
    [int]$SyncTimeoutSeconds = 300,

    [Parameter(ParameterSetName = 'ListVault', Mandatory)]
    [switch]$ListVault,

    [Parameter(ParameterSetName = 'Reveal', Mandatory)]
    [string]$RevealAccount,

    [SecureString]$VaultPassword
)

# === CONFIG (edit here) ===
# Shared UNC for vault + history + transcripts. Change once for the environment.
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

function Invoke-WithVaultLock {
    <#
      Hold Global\SqlServiceAccountVault only for vault file I/O (open/read/write).
      Do NOT hold across AD waits, service updates, or restarts.
      Returns whatever the scriptblock outputs.
    #>
    param(
        [scriptblock]$ScriptBlock,
        [int]$TimeoutSeconds = 60
    )
    $mutex = [Threading.Mutex]::new($false, $mutexName)
    $gotLock = $false
    try {
        try {
            $gotLock = $mutex.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))
        } catch [Threading.AbandonedMutexException] {
            Write-Warning 'Recovered abandoned vault lock.'
            $gotLock = $true
        }
        if (-not $gotLock) {
            throw @"
Vault lock timeout (${TimeoutSeconds}s).
Another process on this machine is reading/writing the vault file right now.
Wait a moment and retry (lock is only held during vault I/O, not during AD wait/restart).
"@
        }
        & $ScriptBlock
    } finally {
        if ($gotLock) { [void]$mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

function Save-VaultAccountEntry {
    # Lock → reload from disk → upsert account → write. Avoids clobbering concurrent vault updates.
    param(
        [string]$Path,
        [string]$Account,
        [hashtable]$Entry
    )
    Invoke-WithVaultLock {
        if (-not (Test-Path $Path)) {
            throw "Vault file missing at '$Path' (expected to exist before saving an account)."
        }
        $doc = Import-Clixml -Path $Path
        if (-not $doc.Accounts) { $doc.Accounts = @{} }
        $doc.Accounts[$Account] = $Entry
        Write-VaultAtomic -Doc $doc -Path $Path
        $doc
    }
}

function Get-StrongPassword {
    param([int]$Length = 24)
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
    # No -Server: use normal AD discovery (same as the previously working runs).
    Write-Host "  AD: Set-ADAccountPassword $sam" -ForegroundColor DarkCyan
    Set-ADAccountPassword -Identity $sam -NewPassword $SecurePassword -Reset -ErrorAction Stop
}

function Unlock-AdServiceAccount {
    param([string]$Account)
    $sam = $Account.Split('\')[-1]
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { return }
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
    # Prefer DNS domain for PrincipalContext; NETBIOS alone can make ValidateCredentials return false.
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
    # Asks this host's DC: does domain\user + password authenticate?
    # ValidateCredentials requires a plain string; SecureString is used at the call sites.
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
    <#
      Phase 1: wait until THIS management host's DC accepts the password.
      Not enough alone - SQL nodes may still use a lagging site DC.
    #>
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
                # ValidateCredentials returned false (wrong/old password on this host's DC) - not an exception, so warn explicitly.
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
Set-ADAccountPassword may have succeeded, but ValidateCredentials still fails from this host.
Check: account lockout, wrong domain NETBIOS vs DNS, password policy reject, jump-box DC lag, or RSAT/AD connectivity.
"@
}

function Test-AdCredentialOnComputer {
    <#
      Validate from the SQL node itself so we use THAT machine's DC affinity.
      PlainPassword is required for remoting ArgumentList + ValidateCredentials.
    #>
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
    $localNames = @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
    if ($Computer -in $localNames) {
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

    $ic = @{
        ComputerName = $Computer
        ScriptBlock  = $sb
        ArgumentList = @($domain, $sam, $PlainPassword)
        ErrorAction  = 'Stop'
    }
    if ($Credential) {
        $ic.Credential = $Credential
    } else {
        # Prefer Kerberos (encrypted session). Avoid falling back to weaker auth by default.
        $ic.Authentication = 'Kerberos'
    }
    return [bool](Invoke-Command @ic)
}

function Wait-AdCredentialReadyOnNode {
    <#
      Phase 2: wait until each SQL node accepts the password via its own DC path.
      Closes the race where mgmt host DC is updated but SQL site DC is not.
    #>
    param(
        [string]$Account,
        [securestring]$SecurePassword,
        [string[]]$ComputerName,
        [PSCredential]$Credential,
        [int]$TimeoutSeconds = 300
    )

    $nodes = @($ComputerName | Where-Object { $_ } | Sort-Object -Unique)
    if ($nodes.Count -eq 0) { return }

    $plain = [Net.NetworkCredential]::new('', $SecurePassword).Password
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    Write-Host ("  AD (SQL nodes): waiting for {0} on {1} (up to {2}s)" -f $Account, ($nodes -join ', '), $TimeoutSeconds) -ForegroundColor DarkCyan

    $pending = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $nodes) { [void]$pending.Add($n) }

    do {
        Unlock-AdServiceAccount -Account $Account
        foreach ($node in @($pending)) {
            try {
                $svcCred = $null
                $remote = $node -notin @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
                if ($Credential -and $remote) { $svcCred = $Credential }
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
        Start-Sleep -Seconds 8
    } while ((Get-Date) -lt $deadline)

    throw @"
AD password for '$Account' not accepted on SQL node(s): $($pending -join ', ') within ${TimeoutSeconds}s.
Management host may already see the new password while SQL site DCs are still catching up.
Requires WinRM to the SQL nodes for per-node ValidateCredentials. Unlock if locked, wait for replication, re-run.
Do not restart SQL until node checks pass.
"@
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
        [PSCredential]$Credential,
        [int]$TimeoutSeconds
    )
    Write-Warning "  Auth/logon failure suspected - unlock, re-check AD on node, retry"
    foreach ($acct in @($Account)) {
        if (-not $acct) { continue }
        Unlock-AdServiceAccount -Account $acct
        if ($AccountPassword -and $AccountPassword.ContainsKey($acct)) {
            Wait-AdCredentialReadyOnNode -Account $acct -SecurePassword $AccountPassword[$acct] `
                -ComputerName $Computer -Credential $Credential -TimeoutSeconds $TimeoutSeconds
        }
    }
}

function Restart-SqlTargetService {
    param(
        [string]$Computer,
        [string[]]$Type = $script:ServiceTypes,
        [PSCredential]$Credential,
        [string[]]$Account,
        [hashtable]$AccountPassword,
        [int]$RetryCount = 5,
        [int]$RetryDelaySeconds = 20
    )
    $Type = @($Type | Sort-Object -Unique)
    $p = @{
        ComputerName    = $Computer
        Type            = $Type
        Force           = $true
        Confirm         = $false
        EnableException = $true
    }
    # Omit InstanceName so host-level SSRS/SSIS are included.
    if ($Credential) { $p.Credential = $Credential }
    $retryWait = [Math]::Max(60, $RetryDelaySeconds * 3)

    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        Write-Host "  Restart $($Type -join '/') on $Computer (attempt $attempt/$RetryCount)" -ForegroundColor Cyan
        try {
            $result = @(Restart-DbaService @p)
        } catch {
            $err = [string]$_
            Write-Warning "  Restart-DbaService threw on ${Computer}: $err"
            $authFail = $err -match 'authentication|logon|password|credential|dependent service'
            if (-not $authFail -or $attempt -ge $RetryCount) { throw }
            Wait-AdAfterAuthFailure -Account $Account -AccountPassword $AccountPassword `
                -Computer $Computer -Credential $Credential -TimeoutSeconds $retryWait
            Start-Sleep -Seconds $RetryDelaySeconds
            continue
        }

        $bad = @($result | Where-Object {
                $_.Status -eq 'Failed' -or (
                    [string]$_.ServiceType -in @('Engine', 'Agent') -and $_.State -ne 'Running'
                )
            })
        if (-not $bad) { return }

        $names = ($bad.ServiceName) -join ', '
        Write-Warning "  Restart failed on ${Computer}: $names"
        if (-not (Test-RestartAuthFailure -Results $bad) -or $attempt -ge $RetryCount) {
            throw "Restart failed on ${Computer}: $names"
        }

        Wait-AdAfterAuthFailure -Account $Account -AccountPassword $AccountPassword `
            -Computer $Computer -Credential $Credential -TimeoutSeconds $retryWait
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

function Get-NodeSqlConnectName {
    <#
      Prefer FQDN\INSTANCE for Kerberos (SPN). Discovery often keeps short SqlInstance
      (HOST\SQL01) while ComputerName is already FQDN — short name can SSPI-fail after
      service-account restart.
    #>
    param([object]$Node)
    if (-not $Node) { return $null }
    $parts = ([string]$Node.SqlInstance).Split('\')
    $instanceName = if ($parts.Count -gt 1) { $parts[1] } else { $null }
    $hostName = if ($Node.ComputerName) { [string]$Node.ComputerName } else { $parts[0] }
    if ($instanceName) { return "$hostName\$instanceName" }
    return $hostName
}

function Test-SqlConnectRetryable {
    param([string]$ErrorText)
    return [bool]($ErrorText -match 'SSPI|principal name|Cannot generate SSPI|Login timeout|network-related|error: 40|error: 0|connection.*fail|timeout|not allowed to connect|pipeline')
}

function Wait-SqlInstanceReady {
    # After Engine restart (esp. service-account password change), wait until SQL accepts connections.
    param(
        [string]$SqlInstance,
        [PSCredential]$SqlCredential,
        [int]$TimeoutSeconds = 180
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt = 0
    Write-Host "  SQL connect: waiting for $SqlInstance (up to ${TimeoutSeconds}s)" -ForegroundColor DarkCyan
    do {
        $attempt++
        try {
            $p = @{ SqlInstance = $SqlInstance; EnableException = $true }
            if ($SqlCredential) { $p.SqlCredential = $SqlCredential }
            $null = Connect-DbaInstance @p
            Write-Host "  SQL connect: OK $SqlInstance (attempt $attempt)" -ForegroundColor Green
            return
        } catch {
            $msg = [string]$_
            Write-Host ("  SQL connect: not ready {0} (attempt {1}): {2}" -f $SqlInstance, $attempt, $msg) -ForegroundColor DarkYellow
            if (-not (Test-SqlConnectRetryable -ErrorText $msg) -and $attempt -gt 3) { throw }
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    throw "SQL instance '$SqlInstance' not accepting connections within ${TimeoutSeconds}s (often SSPI/Kerberos right after service account restart)."
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
        try {
            $p = @{ SqlInstance = $SqlInstance; AvailabilityGroup = $AgNames; EnableException = $true }
            if ($SqlCredential) { $p.SqlCredential = $SqlCredential }
            $ags = @(Get-DbaAvailabilityGroup @p)
        } catch {
            $msg = [string]$_
            if (Test-SqlConnectRetryable -ErrorText $msg) {
                Write-Host ("  Wait sync: connect error on {0}: {1}" -f $SqlInstance, $msg) -ForegroundColor DarkYellow
                Start-Sleep -Seconds 5
                continue
            }
            throw
        }

        # Empty AG list is NOT "ready" (can happen while SQL is still coming up).
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
    throw "AG sync timeout (${TimeoutSeconds}s) waiting on $SecondarySqlInstance (connected via $SqlInstance)"
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
        [switch]$SkipFailback,
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

    # Connect with FQDN when available (Kerberos SPN); keep short names for replica matching.
    $primaryConnect = Get-NodeSqlConnectName -Node $primary
    $secondaryConnect = Get-NodeSqlConnectName -Node $secondary
    Write-Host "Connect:   $primaryConnect / $secondaryConnect" -ForegroundColor DarkCyan

    Restart-SqlTargetService -Computer $secondary.ComputerName -Type $ServiceType -Credential $Credential `
        -Account $Account -AccountPassword $AccountPassword
    Wait-SqlInstanceReady -SqlInstance $secondaryConnect -SqlCredential $SqlCredential `
        -TimeoutSeconds ([Math]::Min(180, $SyncTimeoutSeconds))
    Wait-AgReady -SqlInstance $primaryConnect -AgNames $AgNames -SecondarySqlInstance $secondary.SqlInstance `
        -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds

    Write-Host "  Failover -> $($secondary.SqlInstance) (via $secondaryConnect)" -ForegroundColor Cyan
    $fo = @{
        SqlInstance = $secondaryConnect; AvailabilityGroup = $AgNames
        Confirm = $false; EnableException = $true
    }
    if ($SqlCredential) { $fo.SqlCredential = $SqlCredential }
    $foAttempt = 0
    do {
        $foAttempt++
        try {
            Invoke-DbaAgFailover @fo | Out-Null
            break
        } catch {
            $msg = [string]$_
            if ($foAttempt -ge 5 -or -not (Test-SqlConnectRetryable -ErrorText $msg)) { throw }
            Write-Warning "  Failover connect/SSPI retry $foAttempt/5 on ${secondaryConnect}: $msg"
            Start-Sleep -Seconds 8
        }
    } while ($true)
    Start-Sleep -Seconds 3
    Wait-AgReady -SqlInstance $secondaryConnect -AgNames $AgNames -SecondarySqlInstance $primary.SqlInstance `
        -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds

    Restart-SqlTargetService -Computer $primary.ComputerName -Type $ServiceType -Credential $Credential `
        -Account $Account -AccountPassword $AccountPassword
    Wait-SqlInstanceReady -SqlInstance $primaryConnect -SqlCredential $SqlCredential `
        -TimeoutSeconds ([Math]::Min(180, $SyncTimeoutSeconds))
    Wait-AgReady -SqlInstance $secondaryConnect -AgNames $AgNames -SecondarySqlInstance $primary.SqlInstance `
        -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds

    if ($SkipFailback) {
        Write-Warning "SkipFailback: primary left on $($secondary.SqlInstance)"
        return
    }

    Write-Host "  Failback -> $($primary.SqlInstance) (via $primaryConnect)" -ForegroundColor Cyan
    $fb = @{
        SqlInstance = $primaryConnect; AvailabilityGroup = $AgNames
        Confirm = $false; EnableException = $true
    }
    if ($SqlCredential) { $fb.SqlCredential = $SqlCredential }
    $fbAttempt = 0
    do {
        $fbAttempt++
        try {
            Invoke-DbaAgFailover @fb | Out-Null
            break
        } catch {
            $msg = [string]$_
            if ($fbAttempt -ge 5 -or -not (Test-SqlConnectRetryable -ErrorText $msg)) { throw }
            Write-Warning "  Failback connect/SSPI retry $fbAttempt/5 on ${primaryConnect}: $msg"
            Start-Sleep -Seconds 8
        }
    } while ($true)
    Wait-AgReady -SqlInstance $primaryConnect -AgNames $AgNames -SecondarySqlInstance $secondary.SqlInstance `
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
        Set-RestrictedAcl -Path $script:OutputFolder -Container
    } catch {
        throw "Cannot create/access OutputFolder '$($script:OutputFolder)'. Check the UNC path and share permissions. $_"
    }
}

$transcript = $PSCmdlet.ParameterSetName -eq 'Rotate'
if ($transcript) {
    Start-Transcript -Path (Join-Path $script:OutputFolder "RotateSqlServiceAccount_$timestamp.log") -NoClobber | Out-Null
}

try {
    $unattend = $PSBoundParameters.ContainsKey('Unattended') -and $Unattended

    # Vault lock is only held for file I/O (open / save / history), not the whole rotate.
    $opened = Invoke-WithVaultLock {
        $o = Open-PasswordVault -Path $vaultPath -VaultPassword $VaultPassword -Unattended:$unattend
        if ($o.IsNew) {
            Write-VaultAtomic -Doc $o.Doc -Path $vaultPath
            Write-Host "Vault created: $vaultPath" -ForegroundColor Cyan
        }
        $o
    }
    $vaultDoc = $opened.Doc
    $vaultKey = $opened.Key

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
        Set-DbatoolsConfig -FullName sql.connection.encrypt -Value $true
        Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true

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
                ComputerName    = $node.ComputerName
                Type            = $script:ServiceTypes
                EnableException = $true
            }
            if ($svcCred) { $gp.Credential = $svcCred }
            Get-DbaService @gp
        }
        $allServices = @($allServices)
        # Engine/Agent honor -InstanceName; keep host-level SSRS/SSIS.
        if ($InstanceName) {
            $allServices = @(
                $allServices | Where-Object {
                    $type = [string]$_.ServiceType
                    ($type -in @('SSRS', 'SSIS')) -or ($_.InstanceName -in $InstanceName)
                }
            )
        }
        if (-not $allServices) {
            throw "No $($script:ServiceTypes -join '/') services on: $($computers -join ', ')"
        }

        Write-Host "`nServices:" -ForegroundColor Cyan
        $allServices | Select-Object ComputerName, ServiceName, ServiceType, State, StartName | Format-Table -AutoSize

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
            } else {
                Write-Warning 'Proceeding with shared account rotation (maintenance).'
            }
        }
        if (-not $groups) {
            if ($skippedConflicts) { exit 2 }
            Write-Warning 'Nothing to rotate.'; return
        }

        $groupList = @($groups)
        Write-Host "`nPlan: $($groupList.Count) account(s) on $($computers -join ', ')" -ForegroundColor Cyan

        $anyFailures = $false
        $seedComputer = $topo.Nodes[0].ComputerName
        $rotatedAccounts = [System.Collections.Generic.List[string]]::new()

        foreach ($g in $groupList) {
            $account = $g.Name
            Write-Host "`nRotating: $account" -ForegroundColor Green
            $securePwd = Get-StrongPassword -Length $PasswordLength
            $ok = $true
            $accountNodes = @($g.Group.ComputerName | Sort-Object -Unique)

            # 1) AD first (previous working order), vault immediately, wait until auth is ready.
            #    Then update service logon caches. Running services keep the old password in
            #    memory until restart, so AD can change safely before SCM is updated.
            if (-not $SkipAdPasswordReset) {
                try {
                    Reset-DomainAccountPassword -Account $account -SecurePassword $securePwd -LocalComputer $seedComputer

                    $entry = @{
                        EncryptedPassword = Protect-Secret -Secret $securePwd -Key $vaultKey
                        LastComputerName  = $seedComputer
                        LastTopology      = $topo.Mode
                        LastNodes         = ($computers -join ', ')
                        LastServices      = (($g.Group | ForEach-Object { "$($_.ComputerName)\$($_.ServiceName)" }) -join ', ')
                        LastRotatedUtc    = (Get-Date).ToUniversalTime().ToString('u')
                        LastRotatedBy     = "$env:USERDOMAIN\$env:USERNAME"
                    }
                    $vaultDoc = Save-VaultAccountEntry -Path $vaultPath -Account $account -Entry $entry
                    Write-Host '  Saved to vault (AD changed; waiting for replication before service update).' -ForegroundColor Green

                    Wait-AdCredentialReady -Account $account -SecurePassword $securePwd -TimeoutSeconds $SyncTimeoutSeconds
                    Wait-AdCredentialReadyOnNode -Account $account -SecurePassword $securePwd `
                        -ComputerName $accountNodes -Credential $Credential -TimeoutSeconds $SyncTimeoutSeconds
                } catch {
                    Write-Host "  FAILED (AD): $_" -ForegroundColor Red
                    if ($vaultDoc.Accounts.ContainsKey($account) -and $vaultDoc.Accounts[$account].EncryptedPassword) {
                        Write-Warning @"
AD password for '$account' may already be changed, and is saved in the vault.
Do NOT rotate again blindly. Use -RevealAccount '$account' to recover it, fix lockout/replication,
then re-run with -SkipAdPasswordReset once ValidateCredentials works (to update services + restart).
"@
                    }
                    $ok = $false; $anyFailures = $true
                }
            }

            # 2) Update Windows service logon cache on every node (NoRestart).
            if ($ok) {
                foreach ($computer in $accountNodes) {
                    if (-not $ok) { break }
                    $nodeServices = @($g.Group | Where-Object ComputerName -eq $computer)
                    $svcCred = $null
                    $remote = $computer -notin @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
                    if ($Credential -and $remote) { $svcCred = $Credential }
                    try {
                        Write-Host "  Update-DbaServiceAccount -NoRestart @ $computer" -ForegroundColor DarkCyan
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
            }

            if ($ok) {
                if ($SkipAdPasswordReset) {
                    $entry = @{
                        EncryptedPassword = Protect-Secret -Secret $securePwd -Key $vaultKey
                        LastComputerName  = $seedComputer
                        LastTopology      = $topo.Mode
                        LastNodes         = ($computers -join ', ')
                        LastServices      = (($g.Group | ForEach-Object { "$($_.ComputerName)\$($_.ServiceName)" }) -join ', ')
                        LastRotatedUtc    = (Get-Date).ToUniversalTime().ToString('u')
                        LastRotatedBy     = "$env:USERDOMAIN\$env:USERNAME"
                    }
                    $vaultDoc = Save-VaultAccountEntry -Path $vaultPath -Account $account -Entry $entry
                    Write-Host '  Saved to vault (SkipAdPasswordReset; services updated, not restarted yet).' -ForegroundColor Green
                } else {
                    Write-Host '  Services updated (not restarted yet).' -ForegroundColor Green
                }
                $rotatedAccounts.Add($account)
            }

            if ($securePwd) { $securePwd.Dispose(); Remove-Variable securePwd -EA SilentlyContinue }
        }

        if (-not $SkipRestart -and -not $anyFailures) {
            # Pre-restart: re-check from each SQL node (site DC lag / lockout after vault write).
            # Keep decrypted passwords for restart auth-retry path.
            $restartAccounts = @($rotatedAccounts)
            $restartPasswords = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
            try {
                if (-not $SkipAdPasswordReset) {
                    $sqlNodes = @($topo.Nodes.ComputerName | Sort-Object -Unique)
                    foreach ($account in $restartAccounts) {
                        $sec = Unprotect-Secret -CipherText $vaultDoc.Accounts[$account].EncryptedPassword -Key $vaultKey
                        $restartPasswords[$account] = $sec
                        Write-Host "`nPre-restart AD check on SQL nodes: $account" -ForegroundColor Cyan
                        Wait-AdCredentialReadyOnNode -Account $account -SecurePassword $sec `
                            -ComputerName $sqlNodes -Credential $Credential `
                            -TimeoutSeconds ([Math]::Min(180, $SyncTimeoutSeconds))
                    }
                }

                # Restart only service types that were rotated.
                $typesToRestart = @(
                    $groupList |
                        ForEach-Object { $_.Group } |
                        ForEach-Object { [string]$_.ServiceType } |
                        Sort-Object -Unique
                )
                if (-not $typesToRestart) { $typesToRestart = $script:ServiceTypes }

                if ($topo.Mode -eq 'AvailabilityGroup') {
                    Invoke-GracefulAgApply `
                        -Nodes $topo.Nodes `
                        -AgNames $topo.AgNames `
                        -OriginalPrimary $topo.OriginalPrimary `
                        -ServiceType $typesToRestart `
                        -Credential $Credential `
                        -SqlCredential $SqlCredential `
                        -SyncTimeoutSeconds $SyncTimeoutSeconds `
                        -SkipFailback:$SkipFailback `
                        -Account $restartAccounts `
                        -AccountPassword $restartPasswords
                } else {
                    $node = $topo.Nodes[0]
                    $svcCred = $null
                    $remote = $node.ComputerName -notin @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
                    if ($Credential -and $remote) { $svcCred = $Credential }
                    Restart-SqlTargetService -Computer $node.ComputerName -Type $typesToRestart -Credential $svcCred `
                        -Account $restartAccounts -AccountPassword $restartPasswords
                }
            } finally {
                foreach ($k in @($restartPasswords.Keys)) {
                    if ($restartPasswords[$k]) { $restartPasswords[$k].Dispose() }
                }
                $restartPasswords.Clear()
            }
        } elseif ($SkipRestart) {
            Write-Warning 'SkipRestart: password updated; restart/failover later to apply.'
        }

        $reportPath = Join-Path $script:OutputFolder 'SqlServiceAccountVault_History.csv'
        Invoke-WithVaultLock {
            # Prefer on-disk vault so history includes any concurrent saves.
            $histDoc = if (Test-Path $vaultPath) { Import-Clixml -Path $vaultPath } else { $vaultDoc }
            Write-VaultHistoryCsv -Doc $histDoc -Path $reportPath
        }

        Write-Host "`nVault:   $vaultPath (password-protected)" -ForegroundColor Cyan
        Write-Host "History: $reportPath (no secrets)" -ForegroundColor Cyan

        if ($anyFailures) { Write-Warning 'One or more updates failed.'; exit 1 }
        if ($skippedConflicts) { Write-Warning "$($skippedConflicts.Count) shared account(s) skipped."; exit 2 }
} finally {
    if ($transcript) { Stop-Transcript | Out-Null }
}
