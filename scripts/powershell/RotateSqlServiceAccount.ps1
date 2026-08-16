<#
.SYNOPSIS
    Rotate SQL Engine/Agent service account passwords (standalone or Always On).
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
    [ValidateRange(12, 127)]
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
$script:ServiceTypes = @('Engine', 'Agent')
$script:VaultKdfIterations = 600000

$ErrorActionPreference = 'Stop'
$script:DomainDnsSuffixCache = $null
$script:SqlHostDnsCache = @{}
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$vaultPath = Join-Path $script:OutputFolder 'SqlServiceAccountVault.xml'
$vaultCanary = 'SqlServiceAccountVault.v2'

# Mutex name is derived from the resolved vault path, so two environments pointing at
# different vault files never serialize against each other on the same jump box.
$vaultPathHashBytes = [Security.Cryptography.SHA1]::Create().ComputeHash(
    [Text.Encoding]::UTF8.GetBytes($vaultPath.ToLowerInvariant()))
$mutexName = 'Global\SqlServiceAccountVault_' + ([BitConverter]::ToString($vaultPathHashBytes).Replace('-', ''))

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

function Test-SecretEqual {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Expected')]
    param([SecureString]$Secret, [string]$Expected)
    if (-not $Secret) { return $false }

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
    try {
        $actual = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        return $actual -ceq $Expected
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-VaultAesKey {
    param(
        [SecureString]$VaultPassword,
        [string]$SaltBase64,
        [int]$Iterations = $script:VaultKdfIterations
    )
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($VaultPassword)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        if ([string]::IsNullOrWhiteSpace($plain)) { throw 'Vault password is empty.' }
        if ($plain.Length -lt 12) { throw 'Vault password must be at least 12 characters.' }
        if ($Iterations -lt 100000) { throw "Vault PBKDF2 iteration count is too low: $Iterations" }

        $saltBytes = [Convert]::FromBase64String($SaltBase64)
        $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new(
            $plain,
            $saltBytes,
            $Iterations,
            [Security.Cryptography.HashAlgorithmName]::SHA256)
        try { return $kdf.GetBytes(32) }
        finally { $kdf.Dispose() }
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-LegacyVaultAesKey {
    param([SecureString]$VaultPassword, [string]$SaltBase64)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($VaultPassword)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        if ([string]::IsNullOrWhiteSpace($plain)) { throw 'Vault password is empty.' }

        $pwdBytes = [Text.Encoding]::UTF8.GetBytes($plain)
        $saltBytes = [Convert]::FromBase64String($SaltBase64)
        $combined = New-Object byte[] ($pwdBytes.Length + $saltBytes.Length)
        [Array]::Copy($pwdBytes, 0, $combined, 0, $pwdBytes.Length)
        [Array]::Copy($saltBytes, 0, $combined, $pwdBytes.Length, $saltBytes.Length)

        $sha = [Security.Cryptography.SHA256]::Create()
        try { return $sha.ComputeHash($combined) }
        finally {
            $sha.Dispose()
            [Array]::Clear($pwdBytes, 0, $pwdBytes.Length)
            [Array]::Clear($combined, 0, $combined.Length)
        }
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
        Version, Iterations, Salt, Check, Accounts = @{ account = @{ EncryptedPassword; ... } }
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
        $key = Get-VaultAesKey -VaultPassword $vaultPwd -SaltBase64 $salt -Iterations $script:VaultKdfIterations
        $checkSecret = [System.Security.SecureString]::new()
        try {
            foreach ($ch in $vaultCanary.ToCharArray()) { $checkSecret.AppendChar($ch) }
            $checkSecret.MakeReadOnly()
            $doc = @{
                Version    = 3
                Iterations = $script:VaultKdfIterations
                Salt       = $salt
                Check      = (Protect-Secret -Secret $checkSecret -Key $key)
                Accounts   = @{}
            }
        } finally {
            $checkSecret.Dispose()
        }
        return @{ Doc = $doc; Key = $key; Password = $vaultPwd; IsNew = $true; NeedsSave = $true }
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

    if ([int]$raw.Version -eq 3) {
        if (-not $raw.Iterations) { throw 'Version 3 vault is missing Iterations.' }
        $key = Get-VaultAesKey -VaultPassword $vaultPwd -SaltBase64 $raw.Salt -Iterations ([int]$raw.Iterations)
        $valid = $false
        $probe = $null
        try {
            $probe = Unprotect-Secret -CipherText $raw.Check -Key $key
            $valid = Test-SecretEquals -Secret $probe -Expected $vaultCanary
        } catch {
            $valid = $false
        } finally {
            if ($probe) { $probe.Dispose() }
        }
        if (-not $valid) {
            [Array]::Clear($key, 0, $key.Length)
            throw 'Wrong vault password (or vault is corrupt).'
        }
        return @{ Doc = $raw; Key = $key; Password = $vaultPwd; IsNew = $false; NeedsSave = $false }
    }

    if ([int]$raw.Version -ne 2) {
        throw "Unsupported vault version '$($raw.Version)'."
    }

    Write-Warning 'Legacy version 2 vault detected; upgrading key derivation to PBKDF2.'
    $legacyKey = Get-LegacyVaultAesKey -VaultPassword $vaultPwd -SaltBase64 $raw.Salt
    $legacyValid = $false
    $legacyProbe = $null
    try {
        $legacyProbe = Unprotect-Secret -CipherText $raw.Check -Key $legacyKey
        $legacyValid = Test-SecretEquals -Secret $legacyProbe -Expected $vaultCanary
    } catch {
        $legacyValid = $false
    } finally {
        if ($legacyProbe) { $legacyProbe.Dispose() }
    }
    if (-not $legacyValid) {
        [Array]::Clear($legacyKey, 0, $legacyKey.Length)
        throw 'Wrong vault password (or vault is corrupt).'
    }

    $newKey = Get-VaultAesKey -VaultPassword $vaultPwd -SaltBase64 $raw.Salt -Iterations $script:VaultKdfIterations
    $keepNewKey = $false
    try {
        foreach ($account in @($raw.Accounts.Keys)) {
            $entry = $raw.Accounts[$account]
            if (-not $entry.EncryptedPassword) { continue }
            $secret = Unprotect-Secret -CipherText $entry.EncryptedPassword -Key $legacyKey
            try {
                $entry.EncryptedPassword = Protect-Secret -Secret $secret -Key $newKey
            } finally {
                $secret.Dispose()
            }
        }

        $newCheck = [System.Security.SecureString]::new()
        try {
            foreach ($ch in $vaultCanary.ToCharArray()) { $newCheck.AppendChar($ch) }
            $newCheck.MakeReadOnly()
            $raw.Check = Protect-Secret -Secret $newCheck -Key $newKey
        } finally {
            $newCheck.Dispose()
        }
        $raw.Version = 3
        $raw.Iterations = $script:VaultKdfIterations
        $keepNewKey = $true
        return @{ Doc = $raw; Key = $newKey; Password = $vaultPwd; IsNew = $false; NeedsSave = $true }
    } finally {
        [Array]::Clear($legacyKey, 0, $legacyKey.Length)
        if (-not $keepNewKey) { [Array]::Clear($newKey, 0, $newKey.Length) }
    }
}

function Write-VaultAtomic {
    param([hashtable]$Doc, [string]$Path)
    $temp = "$Path.tmp"
    $Doc | Export-Clixml -Path $temp -Force
    $round = Import-Clixml -Path $temp
    if (-not $round.Accounts -or -not $round.Check -or -not $round.Salt -or
        [int]$round.Version -ne 3 -or -not $round.Iterations) {
        Remove-Item $temp -Force -ErrorAction SilentlyContinue
        throw 'Vault integrity check failed - previous vault untouched.'
    }
    if (Test-Path $Path) { Copy-Item $Path "$Path.bak" -Force }
    Move-Item $temp $Path -Force
    Set-RestrictedAcl -Path $Path
}

function Invoke-WithVaultLock {
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
    param(
        [string]$Path,
        [string]$Account,
        [hashtable]$Entry
    )
    # Locals so the nested lock scriptblock (and PSScriptAnalyzer) clearly see the params used.
    $savePath = $Path
    $saveAccount = $Account
    $saveEntry = $Entry
    Invoke-WithVaultLock {
        if (-not (Test-Path $savePath)) {
            throw "Vault file missing at '$savePath' (expected to exist before saving an account)."
        }
        $doc = Import-Clixml -Path $savePath
        if (-not $doc.Accounts) { $doc.Accounts = @{} }
        $doc.Accounts[$saveAccount] = $saveEntry
        Write-VaultAtomic -Doc $doc -Path $savePath
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

function Test-SqlSspiFailure {
    param([string]$Message)
    [bool]($Message -match '(?i)SSPI|Kerberos|target principal name|Cannot generate SSPI context|untrusted domain|NT AUTHORITY\\ANONYMOUS LOGON')
}

function Get-SqlSspiGuidance {
    param([string]$SqlInstance)
    @"
Windows authentication to SQL instance '$SqlInstance' failed because of Kerberos/SSPI.
Check SQL service SPNs, DNS, delegation/trust, and the account running this script.
For AG discovery, synchronization checks, and failover, pass -SqlCredential with a SQL-authenticated login.
"@
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
        if ((Test-SqlSspiFailure -Message $msg) -and -not $SqlCredential) {
            throw "$(Get-SqlSspiGuidance -SqlInstance $SqlInstance)`nOriginal error: $msg"
        }
        $isNoHadr = $msg -match 'HADR|Availability Group|not configured|is not enabled'
        if (-not $isNoHadr) { throw }
        if ($AvailabilityGroup) {
            throw "Instance $SqlInstance has no HADR/AG configured, but -AvailabilityGroup was specified."
        }
        $ags = @()
    }

    if (-not $ags) {
        $computer = Get-NodeComputer -Instance $SqlInstance -Credential $Credential -SqlCredential $SqlCredential
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
            ComputerName = (Get-NodeComputer -Instance $rep -Credential $Credential -SqlCredential $SqlCredential)
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
    if ($sam -match '@') { $sam = $sam.Split('@')[0] }
    $domain = Resolve-AdAuthDomain -Account $Account
    Unlock-AdServiceAccount -Account $Account
    Write-Host "  AD: Set-ADAccountPassword $sam" -ForegroundColor DarkCyan
    Set-ADAccountPassword -Identity $sam -NewPassword $SecurePassword -Reset -Server $domain -ErrorAction Stop
}

function Clear-AdServiceAccountExpiration {
    param([string]$Account)
    $sam = $Account.Split('\')[-1]
    if ($sam -match '@') { $sam = $sam.Split('@')[0] }
    $domain = Resolve-AdAuthDomain -Account $Account
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { return }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adUser = Get-ADUser -Identity $sam -Properties AccountExpirationDate -Server $domain -ErrorAction Stop
        $exp = $adUser.AccountExpirationDate
        if ($exp -and ($exp -le (Get-Date))) {
            Write-Warning "  AD account $sam is expired (AccountExpirationDate=$exp) - Clear-ADAccountExpiration"
            Clear-ADAccountExpiration -Identity $sam -Server $domain -ErrorAction Stop
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
    $domain = Resolve-AdAuthDomain -Account $Account
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { return }
    Clear-AdServiceAccountExpiration -Account $Account
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adUser = Get-ADUser -Identity $sam -Properties LockedOut -Server $domain -ErrorAction Stop
        if ($adUser.LockedOut) {
            Write-Warning "  AD account $sam is locked out - unlocking"
            Unlock-ADAccount -Identity $sam -Server $domain -ErrorAction Stop
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
Set-ADAccountPassword may have succeeded, but ValidateCredentials still fails from this host.
Check: account lockout, wrong domain NETBIOS vs DNS, password policy reject, jump-box DC lag, or RSAT/AD connectivity.
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
                $svcCred = $null
                if ($Credential -and -not (Test-IsLocalComputerName $node)) { $svcCred = $Credential }
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
        [PSCredential]$Credential
    )
    Write-Warning '  Auth/logon failure suspected - unlock, re-check AD on node, retry'
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
    $Type = @($Type | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $Type) { $Type = $script:ServiceTypes }
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
    $lastSqlError = $null
    do {
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
            $lastSqlError = $null
        } catch {
            $lastSqlError = [string]$_
            if (Test-SqlSspiFailure -Message $lastSqlError) {
                Write-Host "  Wait sync: $SqlInstance Windows authentication not ready (Kerberos/SSPI; retrying)" -ForegroundColor DarkYellow
            } else {
                Write-Host ("  Wait sync: {0} - {1}" -f $SqlInstance, $lastSqlError.Split("`n")[0]) -ForegroundColor DarkYellow
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
    if ($lastSqlError -and (Test-SqlSspiFailure -Message $lastSqlError) -and -not $SqlCredential) {
        throw "AG sync timeout (${TimeoutSeconds}s) waiting on $SecondarySqlInstance`n$(Get-SqlSspiGuidance -SqlInstance $SqlInstance)"
    }
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

    $svcCredSecondary = $null
    if ($Credential -and -not (Test-IsLocalComputerName $secondary.ComputerName)) { $svcCredSecondary = $Credential }
    Restart-SqlTargetService -Computer $secondary.ComputerName -SqlInstance $secondary.SqlInstance -Type $ServiceType `
        -Credential $svcCredSecondary -SqlCredential $SqlCredential `
        -Account $Account -AccountPassword $AccountPassword
    Wait-SqlTargetServiceRunning -Computer $secondary.ComputerName -SqlInstance $secondary.SqlInstance -Type $ServiceType `
        -Credential $svcCredSecondary -SqlCredential $SqlCredential `
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

    $svcCredPrimary = $null
    if ($Credential -and -not (Test-IsLocalComputerName $primary.ComputerName)) { $svcCredPrimary = $Credential }
    Restart-SqlTargetService -Computer $primary.ComputerName -SqlInstance $primary.SqlInstance -Type $ServiceType `
        -Credential $svcCredPrimary -SqlCredential $SqlCredential `
        -Account $Account -AccountPassword $AccountPassword
    Wait-SqlTargetServiceRunning -Computer $primary.ComputerName -SqlInstance $primary.SqlInstance -Type $ServiceType `
        -Credential $svcCredPrimary -SqlCredential $SqlCredential `
        -TimeoutSeconds ([Math]::Min(180, $SyncTimeoutSeconds))
    Wait-AgReady -SqlInstance $secondary.SqlInstance -AgNames $AgNames -SecondarySqlInstance $primary.SqlInstance `
        -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds

    if ($SkipFailback) {
        Write-Warning "SkipFailback: primary left on $($secondary.SqlInstance)"
        return
    }

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
Set-DbatoolsConfig sql.connection.encrypt $true
Set-DbatoolsConfig sql.connection.trustcert $true

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
$vaultKey = $null
$vaultPwdReady = $null
if ($transcript) {
    Start-Transcript -Path (Join-Path $script:OutputFolder "RotateSqlServiceAccount_$timestamp.log") -NoClobber | Out-Null
}

try {
    $unattend = $PSBoundParameters.ContainsKey('Unattended') -and $Unattended

    # Prompt for vault password outside the mutex (lock only covers vault file I/O).
    if (Test-Path $vaultPath) {
        $vaultPwdReady = Get-VaultPasswordInput -VaultPassword $VaultPassword -Unattended:$unattend
    } else {
        $vaultPwdReady = Get-VaultPasswordInput -VaultPassword $VaultPassword -ConfirmNew -Unattended:$unattend
    }

    $opened = Invoke-WithVaultLock {
        $o = Open-PasswordVault -Path $vaultPath -VaultPassword $vaultPwdReady -Unattended:$unattend
        if ($o.NeedsSave) {
            Write-VaultAtomic -Doc $o.Doc -Path $vaultPath
            if ($o.IsNew) {
                Write-Host "Vault created: $vaultPath" -ForegroundColor Cyan
            } else {
                Write-Host "Vault upgraded to version 3 PBKDF2: $vaultPath" -ForegroundColor Cyan
            }
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

    # -SqlCredential is optional (Windows auth by default; pass SQL auth to avoid Kerberos/SSPI).
    $topo = Get-TargetTopology -SqlInstance $SqlInstance -AvailabilityGroup $AvailabilityGroup `
        -SqlCredential $SqlCredential -Credential $Credential

    if ($SqlCredential -and $topo.Mode -eq 'AvailabilityGroup') {
        Write-Host "AG SQL login: $($SqlCredential.UserName)" -ForegroundColor DarkCyan
    }

    Write-Host "`nMode: $($topo.Mode)" -ForegroundColor Cyan
    $topo.Nodes | Format-Table ComputerName, SqlInstance -AutoSize
    if ($topo.AgNames) { Write-Host "AGs: $($topo.AgNames -join ', ')" -ForegroundColor Cyan }

    $computers = @($topo.Nodes.ComputerName | Select-Object -Unique)

    $allServices = foreach ($node in $topo.Nodes) {
        $svcCred = $null
        if ($Credential -and -not (Test-IsLocalComputerName $node.ComputerName)) { $svcCred = $Credential }
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
    $allServices = @($allServices)
    if ($InstanceName) {
        $allServices = @(
            $allServices | Where-Object {
                $_.InstanceName -in $InstanceName
            }
        )
    }
    if (-not $allServices) {
        throw "No $($script:ServiceTypes -join '/') services on: $($computers -join ', ')"
    }

    Write-Host "`nServices:" -ForegroundColor Cyan
    $allServices | Select-Object ComputerName, ServiceName, ServiceType, State, StartName | Format-Table -AutoSize

    $groups = @($allServices | Group-Object StartName | Where-Object {
            $c = Test-AccountEligible -StartName $_.Name -ForComputer @($_.Group.ComputerName)[0] -IncludeDomain $IncludeDomain
            if (-not $c.Ok) { Write-Host "Skip $($_.Name): $($c.Reason)" -ForegroundColor Yellow; return $false }
            $true
        })
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

    Write-Host "`nPlan: $($groups.Count) account(s) on $($computers -join ', ')" -ForegroundColor Cyan

    $anyFailures = $false
    $seedComputer = $topo.Nodes[0].ComputerName
    $rotatedAccounts = [System.Collections.Generic.List[string]]::new()

    foreach ($g in $groups) {
        $account = $g.Name
        Write-Host "`nRotating: $account" -ForegroundColor Green
        $ok = $true
        $accountNodes = @($g.Group.ComputerName | Sort-Object -Unique)
        $securePwd = $null
        $vaultedAfterAd = $false

        if ($SkipAdPasswordReset) {
            if (-not $vaultDoc.Accounts.ContainsKey($account) -or -not $vaultDoc.Accounts[$account].EncryptedPassword) {
                throw "SkipAdPasswordReset requires a vault entry for '$account'. Use -RevealAccount or rotate without -SkipAdPasswordReset first."
            }
            $securePwd = Unprotect-Secret -CipherText $vaultDoc.Accounts[$account].EncryptedPassword -Key $vaultKey
            Write-Host '  Using vault password (SkipAdPasswordReset; AD not changed).' -ForegroundColor Cyan
        } else {
            $securePwd = Get-StrongPassword -Length $PasswordLength
            try {
                Reset-DomainAccountPassword -Account $account -SecurePassword $securePwd -LocalComputer $seedComputer
                if (Test-IsDomainAccount -Account $account -Computer $seedComputer) {
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
                    $vaultedAfterAd = $true
                    Write-Host '  Saved to vault (AD changed; waiting for replication before service update).' -ForegroundColor Green

                    Wait-AdCredentialReady -Account $account -SecurePassword $securePwd -TimeoutSeconds $SyncTimeoutSeconds
                    Wait-AdCredentialReadyOnNode -Account $account -SecurePassword $securePwd `
                        -ComputerName $accountNodes -Credential $Credential
                }
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

        foreach ($computer in $accountNodes) {
            if (-not $ok) { break }
            $nodeServices = @($g.Group | Where-Object ComputerName -eq $computer)
            $svcCred = $null
            if ($Credential -and -not (Test-IsLocalComputerName $computer)) { $svcCred = $Credential }
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

        if ($ok) {
            if ($SkipAdPasswordReset) {
                $existing = $vaultDoc.Accounts[$account]
                $entry = @{
                    EncryptedPassword = $existing.EncryptedPassword
                    LastComputerName  = $seedComputer
                    LastTopology      = $topo.Mode
                    LastNodes         = ($computers -join ', ')
                    LastServices      = (($g.Group | ForEach-Object { "$($_.ComputerName)\$($_.ServiceName)" }) -join ', ')
                    LastRotatedUtc    = (Get-Date).ToUniversalTime().ToString('u')
                    LastRotatedBy     = "$env:USERDOMAIN\$env:USERNAME"
                }
                $vaultDoc = Save-VaultAccountEntry -Path $vaultPath -Account $account -Entry $entry
                Write-Host '  Services updated (SkipAdPasswordReset; vault password unchanged).' -ForegroundColor Green
            } elseif ($vaultedAfterAd) {
                Write-Host '  Services updated (not restarted yet).' -ForegroundColor Green
            } else {
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
                Write-Host '  Saved to password-protected vault (not restarted yet).' -ForegroundColor Green
            }
            $rotatedAccounts.Add($account)
        }

        if ($securePwd) { $securePwd.Dispose(); Remove-Variable securePwd -EA SilentlyContinue }
    }

    if (-not $SkipRestart -and -not $anyFailures) {
        $restartAccounts = @($rotatedAccounts)
        $restartPasswords = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
        try {
            $sqlNodes = @($topo.Nodes.ComputerName | Sort-Object -Unique)
            foreach ($account in $restartAccounts) {
                if (-not (Test-IsDomainAccount -Account $account -Computer $seedComputer)) { continue }
                if (-not $vaultDoc.Accounts.ContainsKey($account)) { continue }
                $sec = Unprotect-Secret -CipherText $vaultDoc.Accounts[$account].EncryptedPassword -Key $vaultKey
                $restartPasswords[$account] = $sec
                Write-Host "`nPre-restart AD check on SQL nodes: $account" -ForegroundColor Cyan
                Wait-AdCredentialReadyOnNode -Account $account -SecurePassword $sec `
                    -ComputerName $sqlNodes -Credential $Credential
            }

            $typesToRestart = @(
                $groups |
                    Where-Object { $_.Name -in $rotatedAccounts } |
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
                    -SkipFailback:$SkipFailback `
                    -Account $restartAccounts `
                    -AccountPassword $restartPasswords
            } else {
                if ($topo.Mode -eq 'AvailabilityGroup' -and -not $needsAgFailover) {
                    Write-Host 'No Engine/Agent in restart set; restarting without AG failover.' -ForegroundColor Cyan
                }
                foreach ($node in $topo.Nodes) {
                    $svcCred = $null
                    if ($Credential -and -not (Test-IsLocalComputerName $node.ComputerName)) { $svcCred = $Credential }
                    Restart-SqlTargetService -Computer $node.ComputerName -SqlInstance $node.SqlInstance -Type $typesToRestart `
                        -Credential $svcCred -SqlCredential $SqlCredential `
                        -Account $restartAccounts -AccountPassword $restartPasswords
                    Wait-SqlTargetServiceRunning -Computer $node.ComputerName -SqlInstance $node.SqlInstance -Type $typesToRestart `
                        -Credential $svcCred -SqlCredential $SqlCredential `
                        -TimeoutSeconds ([Math]::Min(180, $SyncTimeoutSeconds))
                }
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
        $histDoc = if (Test-Path $vaultPath) { Import-Clixml -Path $vaultPath } else { $vaultDoc }
        Write-VaultHistoryCsv -Doc $histDoc -Path $reportPath
    }

    Write-Host "`nVault:   $vaultPath (password-protected)" -ForegroundColor Cyan
    Write-Host "History: $reportPath (no secrets)" -ForegroundColor Cyan

    if ($anyFailures) { Write-Warning 'One or more updates failed.'; exit 1 }
    if ($skippedConflicts) { Write-Warning "$($skippedConflicts.Count) shared account(s) skipped."; exit 2 }
} finally {
    if ($vaultKey) { [Array]::Clear($vaultKey, 0, $vaultKey.Length) }
    if ($vaultPwdReady) { $vaultPwdReady.Dispose() }
    if ($transcript) { Stop-Transcript | Out-Null }
}
