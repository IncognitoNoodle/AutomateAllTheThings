<#
.SYNOPSIS
    Rotate SQL Engine/Agent service account passwords, then apply them with a
    graceful Always On restart + failover + failback (dbatools).

.DESCRIPTION
    KISS flow:

      1. Discover eligible Engine/Agent service accounts
      2. Generate a strong password and Update-DbaServiceAccount -NoRestart
         on the target (and partner, when provided)
      3. Persist encrypted password to a local DPAPI vault
      4. Apply with a controlled restart:
           - Standalone: Restart-DbaService on ComputerName
           - AG pair:    restart secondary -> failover -> restart former primary
                         -> failover back (Invoke-DbaAgFailover, no -Force)

    Audit notes vs the previous draft:
      - [switch]$NoRestart = $true was a bug (switch defaults are $false).
        Password update always uses -NoRestart; restart is an explicit step.
      - Dropped the extra Read-Host YES/SHARED prompt; SupportsShouldProcess
        + ConfirmImpact High already gates destructive work (-Unattended / -Confirm:$false).
      - No silent Install-Module in prod paths; pass -InstallModule if you want it.
      - Shared-account conflict check no longer false-positives on the AG partner.
      - Nested helpers flattened; AG rolling apply is one function.

.PARAMETER ComputerName
    Node to rotate (and preferred/home primary for failback). Default: local host.

.PARAMETER PartnerComputerName
    AG partner node. When set, password is updated on both nodes, then the
    graceful rolling restart/failover sequence runs.

.PARAMETER SqlInstance
    SQL instance used for AG discovery/failover on ComputerName.
    Default: ComputerName (default instance). Use SERVER\INSTANCE for named.

.PARAMETER PartnerSqlInstance
    SQL instance on the partner. Default: PartnerComputerName.

.PARAMETER AvailabilityGroup
    AG name(s) to failover. Omit to failover every AG found on the pair.

.PARAMETER InstanceName
    Limit Get-DbaService to specific instance name(s).

.PARAMETER Credential
    Windows credential for remote service WMI (Get/Update/Restart-DbaService).

.PARAMETER SqlCredential
    SQL login for Get-DbaAvailabilityGroup / Invoke-DbaAgFailover.

.PARAMETER IncludeDomain
    Rotate domain accounts (default $true). Local/built-in/gMSA still skipped.

.PARAMETER SkipAdPasswordReset
    Do not call Set-ADAccountPassword. Use when AD was already rotated
    out-of-band and you only need to refresh the service logon cache.

.PARAMETER SkipRestart
    Update passwords + vault only; do not restart or failover.

.PARAMETER SkipFailback
    After failing over to the partner, leave roles there (no failback).

.PARAMETER Unattended
    Skip shared-account interactive confirmation; skip conflicting accounts.

.PARAMETER InstallModule
    Allow Install-Module dbatools -Scope CurrentUser when missing.

.PARAMETER OutputFolder
    Vault, key, history CSV, and transcript location.

.PARAMETER PasswordLength
    Generated password length (default 18).

.PARAMETER SyncTimeoutSeconds
    Max wait for AG replica sync before failover/failback (default 300).

.EXAMPLE
    # Standalone node
    .\RotateSqlServiceAccount.ps1 -ComputerName SQL01 -Confirm:$false

.EXAMPLE
    # AG pair: rotate both, restart secondary, failover, restart former primary, fail back
    .\RotateSqlServiceAccount.ps1 `
        -ComputerName SQL01 -PartnerComputerName SQL02 `
        -AvailabilityGroup 'AG1' -Unattended -Confirm:$false

.NOTES
    Requires: dbatools, local admin on target nodes, permissions to failover AGs.
    Vault key is DPAPI LocalMachine-scoped — unreadable after OS rebuild.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [string]$PartnerComputerName,
    [string]$SqlInstance,
    [string]$PartnerSqlInstance,
    [string[]]$AvailabilityGroup,
    [string[]]$InstanceName,
    [PSCredential]$Credential,
    [PSCredential]$SqlCredential,
    [bool]$IncludeDomain = $true,
    [switch]$SkipAdPasswordReset,
    [switch]$SkipRestart,
    [switch]$SkipFailback,
    [switch]$Unattended,
    [switch]$InstallModule,
    [string]$OutputFolder = '\\DBAPRDAG03\C$\Temp\SecureCreds',
    [ValidateRange(12, 128)]
    [int]$PasswordLength = 18,
    [ValidateRange(30, 3600)]
    [int]$SyncTimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'

if (-not $SqlInstance) { $SqlInstance = $ComputerName }
if ($PartnerComputerName -and -not $PartnerSqlInstance) { $PartnerSqlInstance = $PartnerComputerName }

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$vaultPath = Join-Path $OutputFolder 'SqlServiceAccountVault.xml'
$keyPath   = Join-Path $OutputFolder 'vault.key'
$mutexName = 'Global\SqlServiceAccountVault'
$agPair    = [bool]$PartnerComputerName
$nodes     = @($ComputerName) + @(if ($agPair) { $PartnerComputerName })

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
                [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            } else {
                [System.Security.AccessControl.FileSystemAccessRule]::new($id, 'FullControl', 'Allow')
            }
            $acl.AddAccessRule($rule)
        }
        Set-Acl -Path $Path -AclObject $acl
    } catch {
        Write-Warning "Could not harden ACLs on $Path : $_"
    }
}

function Get-OrCreateMachineKey {
    param([string]$Path)
    Add-Type -AssemblyName System.Security -ErrorAction Stop

    if (Test-Path -Path $Path) {
        $bytes = [IO.File]::ReadAllBytes($Path)
        try {
            return [Security.Cryptography.ProtectedData]::Unprotect(
                $bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
        } catch {
            throw "Vault key at $Path is unreadable (machine rebuilt?). Reset vault/key. $_"
        }
    }

    Write-Host 'No vault key found - creating LocalMachine DPAPI key (first run).' -ForegroundColor Cyan
    $key = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($key) } finally { $rng.Dispose() }
    $protected = [Security.Cryptography.ProtectedData]::Protect(
        $key, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    [IO.File]::WriteAllBytes($Path, $protected)
    Set-RestrictedAcl -Path $Path
    return $key
}

function New-StrongPassword {
    param([int]$Length = 18)
    # Guaranteed charset mix + CSPRNG; no nested helper function.
    $sets = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ',
        'abcdefghijkmnopqrstuvwxyz',
        '23456789',
        '!@#$%^&*_-+='
    )
    $all = -join $sets
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $pick = {
            param([string]$Alphabet)
            $b = [byte[]]::new(4)
            $max = $Alphabet.Length
            do {
                $rng.GetBytes($b)
                $v = [BitConverter]::ToUInt32($b, 0)
            } while ($v -ge ([uint32]::MaxValue - ([uint32]::MaxValue % [uint32]$max)))
            $Alphabet[$v % $max]
        }

        $chars = [char[]]::new($Length)
        for ($i = 0; $i -lt $sets.Count; $i++) { $chars[$i] = & $pick $sets[$i] }
        for ($i = $sets.Count; $i -lt $Length; $i++) { $chars[$i] = & $pick $all }

        # Fisher-Yates
        for ($i = $Length - 1; $i -gt 0; $i--) {
            $b = [byte[]]::new(4)
            do {
                $rng.GetBytes($b)
                $v = [BitConverter]::ToUInt32($b, 0)
            } while ($v -ge ([uint32]::MaxValue - ([uint32]::MaxValue % [uint32]($i + 1))))
            $j = [int]($v % [uint32]($i + 1))
            $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
        }
        return -join $chars
    } finally {
        $rng.Dispose()
    }
}

function Test-AccountEligible {
    param([string]$StartName, [string]$ForComputer, [bool]$IncludeDomain)
    if ($StartName -match '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\)') {
        return @{ Ok = $false; Reason = 'built-in account' }
    }
    if ($StartName -match '\$$') {
        return @{ Ok = $false; Reason = 'gMSA (AD-managed)' }
    }
    $isLocal = $StartName -match "^$([regex]::Escape($ForComputer))\\|^\.\\"
    if (($StartName -match '\\') -and (-not $isLocal) -and (-not $IncludeDomain)) {
        return @{ Ok = $false; Reason = 'domain account (use -IncludeDomain)' }
    }
    return @{ Ok = $true; Reason = $null }
}

function Read-Vault {
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) { return @{} }
    return @{} + (Import-Clixml -Path $Path)
}

function Write-VaultAtomic {
    param([hashtable]$Vault, [string]$Path)
    $temp = "$Path.tmp"
    $Vault | Export-Clixml -Path $temp -Force
    $check = Import-Clixml -Path $temp
    if (@($check.Keys).Count -ne @($Vault.Keys).Count) {
        Remove-Item -Path $temp -Force -ErrorAction SilentlyContinue
        throw 'Vault integrity check failed - previous vault left untouched.'
    }
    if (Test-Path -Path $Path) { Copy-Item -Path $Path -Destination "$Path.bak" -Force }
    Move-Item -Path $temp -Destination $Path -Force
}

function Get-SqlServices {
    param(
        [string]$Computer,
        [string[]]$InstanceName,
        [PSCredential]$Credential
    )
    $p = @{
        ComputerName    = $Computer
        Type            = 'Engine', 'Agent'
        EnableException = $true
    }
    if ($InstanceName) { $p.InstanceName = $InstanceName }
    if ($Credential) { $p.Credential = $Credential }
    Get-DbaService @p
}

function Update-SqlServicePassword {
    param(
        [object[]]$Services,
        [securestring]$SecurePassword,
        [PSCredential]$Credential
    )
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

function Reset-DomainAccountPassword {
    <#
      Update-DbaServiceAccount only refreshes the Windows service logon cache.
      Domain accounts also need the AD password changed (once) or SQL won't start.
    #>
    param(
        [string]$Account,
        [securestring]$SecurePassword,
        [string]$LocalComputer
    )

    $isDomain = ($Account -match '\\') -and ($Account -notmatch "^$([regex]::Escape($LocalComputer))\\|^\.\\")
    if (-not $isDomain) { return }

    $sam = $Account.Split('\')[-1]
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw @"
Domain account '$Account' needs an AD password reset, but the ActiveDirectory
module is not available. Either:
  - Install RSAT ActiveDirectory and re-run, or
  - Reset the AD password yourself, then re-run with -SkipAdPasswordReset
"@
    }

    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  Set-ADAccountPassword -Identity $sam -Reset" -ForegroundColor DarkCyan
    Set-ADAccountPassword -Identity $sam -NewPassword $SecurePassword -Reset -ErrorAction Stop
}

function Restart-SqlEngineAgent {
    param(
        [string]$Computer,
        [string[]]$InstanceName,
        [object[]]$InputObject,
        [PSCredential]$Credential
    )
    $p = @{
        Force           = $true
        Confirm         = $false
        EnableException = $true
    }
    if ($InputObject) {
        $p.InputObject = $InputObject
    } else {
        $p.ComputerName = $Computer
        $p.Type = 'Engine', 'Agent'
        if ($InstanceName) { $p.InstanceName = $InstanceName }
    }
    if ($Credential) { $p.Credential = $Credential }

    Write-Host "  Restarting Engine/Agent on $Computer ..." -ForegroundColor Cyan
    $result = Restart-DbaService @p
    $failed = @($result | Where-Object { $_.Status -eq 'Failed' -or $_.State -ne 'Running' })
    if ($failed.Count) {
        throw "Restart failed/not Running on ${Computer}: $(($failed.ServiceName) -join ', ')"
    }
}

function Test-ReplicaNameMatch {
    param([string]$ReplicaName, [string]$SqlInstance)
    if (-not $ReplicaName -or -not $SqlInstance) { return $false }
    if ($ReplicaName -eq $SqlInstance) { return $true }
    # Compare host part case-insensitively (named instances: HOST\INST)
    $rHost = $ReplicaName.Split('\')[0]
    $sHost = $SqlInstance.Split('\')[0]
    if ($rHost -eq $sHost -and $ReplicaName.Contains('\') -eq $SqlInstance.Contains('\')) {
        if (-not $ReplicaName.Contains('\')) { return $true }
        return $ReplicaName.Split('\')[1] -eq $SqlInstance.Split('\')[1]
    }
    return ($rHost -eq $sHost)
}

function Wait-AgReplicaReady {
    param(
        [string]$SqlInstance,
        [PSCredential]$SqlCredential,
        [string[]]$AvailabilityGroup,
        [string]$SecondarySqlInstance,
        [int]$TimeoutSeconds
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $agParams = @{
            SqlInstance     = $SqlInstance
            EnableException = $true
        }
        if ($SqlCredential) { $agParams.SqlCredential = $SqlCredential }
        if ($AvailabilityGroup) { $agParams.AvailabilityGroup = $AvailabilityGroup }

        $ags = @(Get-DbaAvailabilityGroup @agParams)
        if (-not $ags) { throw "No availability groups found on $SqlInstance." }

        $pending = foreach ($ag in $ags) {
            $replicas = @($ag.AvailabilityReplicas)
            $target = $replicas | Where-Object {
                Test-ReplicaNameMatch -ReplicaName $_.Name -SqlInstance $SecondarySqlInstance
            } | Select-Object -First 1

            if (-not $target) {
                [pscustomobject]@{ Ag = $ag.Name; Why = "replica $SecondarySqlInstance not found" }
                continue
            }

            # Prefer Synchronized (safe failover). Synchronizing allowed for async replicas.
            $sync = [string]$target.RollupSynchronizationState
            $conn = [string]$target.ConnectionState
            $mode = [string]$target.AvailabilityMode
            $ok = ($conn -eq 'Connected') -and (
                $sync -eq 'Synchronized' -or
                ($mode -match 'Asynchronous' -and $sync -eq 'Synchronizing')
            )
            if (-not $ok) {
                [pscustomobject]@{ Ag = $ag.Name; Why = "$($target.Name) conn=$conn sync=$sync mode=$mode" }
            }
        }

        if (-not $pending) { return $ags }

        Write-Host ("  Waiting for AG sync: " + (($pending | ForEach-Object { "$($_.Ag) ($($_.Why))" }) -join '; ')) -ForegroundColor DarkYellow
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)

    throw "Timed out after ${TimeoutSeconds}s waiting for AG sync toward $SecondarySqlInstance."
}

function Invoke-AgRollingRestart {
    <#
      Graceful apply sequence (password already set with -NoRestart on both nodes):
        1) Restart SECONDARY services
        2) Failover to secondary (Invoke-DbaAgFailover, no -Force)
        3) Restart FORMER PRIMARY (now secondary)
        4) Fail back to original primary (unless -SkipFailback)
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [string]$HomeComputer,
        [string]$PartnerComputer,
        [string]$HomeSqlInstance,
        [string]$PartnerSqlInstance,
        [string[]]$AvailabilityGroup,
        [string[]]$InstanceName,
        [PSCredential]$Credential,
        [PSCredential]$SqlCredential,
        [int]$SyncTimeoutSeconds,
        [switch]$SkipFailback
    )

    Write-Host "`n=== AG rolling apply ===" -ForegroundColor Cyan
    Write-Host "Home (preferred primary): $HomeComputer ($HomeSqlInstance)" -ForegroundColor Cyan
    Write-Host "Partner:                  $PartnerComputer ($PartnerSqlInstance)" -ForegroundColor Cyan

    # Discover current primary from home instance
    $getAg = @{ SqlInstance = $HomeSqlInstance; EnableException = $true }
    if ($SqlCredential) { $getAg.SqlCredential = $SqlCredential }
    if ($AvailabilityGroup) { $getAg.AvailabilityGroup = $AvailabilityGroup }
    $ags = @(Get-DbaAvailabilityGroup @getAg)
    if (-not $ags) { throw "No AGs on $HomeSqlInstance. Pass -AvailabilityGroup or omit Partner for standalone." }

    $agNames = @($ags.Name | Select-Object -Unique)
    Write-Host "Availability groups: $($agNames -join ', ')" -ForegroundColor Cyan

    # Resolve which computer is currently secondary (restart that one first)
    $primaryName = $ags[0].PrimaryReplicaServerName
    $homeIsPrimary = $primaryName -eq $HomeSqlInstance -or
        $primaryName.Split('\')[0] -eq $HomeComputer -or
        $primaryName -eq $HomeComputer

    if ($homeIsPrimary) {
        $currentPrimarySql = $HomeSqlInstance
        $currentSecondarySql = $PartnerSqlInstance
        $currentSecondaryComputer = $PartnerComputer
        $currentPrimaryComputer = $HomeComputer
    } else {
        $currentPrimarySql = $PartnerSqlInstance
        $currentSecondarySql = $HomeSqlInstance
        $currentSecondaryComputer = $HomeComputer
        $currentPrimaryComputer = $PartnerComputer
        Write-Warning "Home node is not primary right now (primary=$primaryName). Continuing with actual roles."
    }

    # Remember original primary so failback restores topology (not always -ComputerName).
    $originalPrimarySql = $currentPrimarySql
    $originalSecondarySql = $currentSecondarySql

    if (-not $PSCmdlet.ShouldProcess($currentSecondaryComputer, 'Restart SQL Engine/Agent (secondary first)')) { return }

    # 1) Restart secondary
    Restart-SqlEngineAgent -Computer $currentSecondaryComputer -InstanceName $InstanceName -Credential $Credential
    Wait-AgReplicaReady -SqlInstance $currentPrimarySql -SqlCredential $SqlCredential `
        -AvailabilityGroup $agNames -SecondarySqlInstance $currentSecondarySql -TimeoutSeconds $SyncTimeoutSeconds

    # 2) Failover to secondary
    if (-not $PSCmdlet.ShouldProcess($currentSecondarySql, "Graceful failover AG(s): $($agNames -join ', ')")) { return }
    Write-Host "  Failing over to $currentSecondarySql ..." -ForegroundColor Cyan
    $fo = @{
        SqlInstance       = $currentSecondarySql
        AvailabilityGroup = $agNames
        Confirm           = $false
        EnableException   = $true
    }
    if ($SqlCredential) { $fo.SqlCredential = $SqlCredential }
    Invoke-DbaAgFailover @fo | Out-Null

    Start-Sleep -Seconds 3
    Wait-AgReplicaReady -SqlInstance $currentSecondarySql -SqlCredential $SqlCredential `
        -AvailabilityGroup $agNames -SecondarySqlInstance $currentPrimarySql -TimeoutSeconds $SyncTimeoutSeconds

    # 3) Restart former primary (now secondary)
    if (-not $PSCmdlet.ShouldProcess($currentPrimaryComputer, 'Restart SQL Engine/Agent (former primary)')) { return }
    Restart-SqlEngineAgent -Computer $currentPrimaryComputer -InstanceName $InstanceName -Credential $Credential
    Wait-AgReplicaReady -SqlInstance $currentSecondarySql -SqlCredential $SqlCredential `
        -AvailabilityGroup $agNames -SecondarySqlInstance $currentPrimarySql -TimeoutSeconds $SyncTimeoutSeconds

    if ($SkipFailback) {
        Write-Warning "SkipFailback set - primary remains on $currentSecondarySql."
        return
    }

    # 4) Fail back to the primary we started with
    if (-not $PSCmdlet.ShouldProcess($originalPrimarySql, "Graceful failback AG(s): $($agNames -join ', ')")) { return }
    Write-Host "  Failing back to $originalPrimarySql ..." -ForegroundColor Cyan
    $fb = @{
        SqlInstance       = $originalPrimarySql
        AvailabilityGroup = $agNames
        Confirm           = $false
        EnableException   = $true
    }
    if ($SqlCredential) { $fb.SqlCredential = $SqlCredential }
    Invoke-DbaAgFailover @fb | Out-Null

    Wait-AgReplicaReady -SqlInstance $originalPrimarySql -SqlCredential $SqlCredential `
        -AvailabilityGroup $agNames -SecondarySqlInstance $originalSecondarySql -TimeoutSeconds $SyncTimeoutSeconds

    Write-Host "  AG rolling apply complete (primary restored on $originalPrimarySql)." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
    Set-RestrictedAcl -Path $OutputFolder -Container
}

Start-Transcript -Path (Join-Path $OutputFolder "RotateSqlServiceAccount_$timestamp.log") -NoClobber | Out-Null

try {
    if (-not (Get-Module -ListAvailable -Name dbatools)) {
        if (-not $InstallModule) {
            throw 'dbatools not found. Install it, or re-run with -InstallModule.'
        }
        Write-Host 'Installing dbatools (CurrentUser)...' -ForegroundColor Cyan
        Install-Module dbatools -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module dbatools -ErrorAction Stop
    Add-Type -AssemblyName System.Security -ErrorAction Stop

    $mutex = [Threading.Mutex]::new($false, $mutexName)
    $gotLock = $false
    try {
        try {
            $gotLock = $mutex.WaitOne([TimeSpan]::FromSeconds(60))
        } catch [Threading.AbandonedMutexException] {
            Write-Warning 'Recovered abandoned vault lock from a previous run.'
            $gotLock = $true
        }
        if (-not $gotLock) { throw 'Could not acquire vault lock within 60s.' }

        $machineKey = Get-OrCreateMachineKey -Path $keyPath
        $vault = Read-Vault -Path $vaultPath

        # Discover services on all nodes in scope
        $allServices = foreach ($node in $nodes) {
            $svcCred = $null
            $isRemote = $node -notin @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
            if ($Credential -and $isRemote) { $svcCred = $Credential }
            Get-SqlServices -Computer $node -InstanceName $InstanceName -Credential $svcCred
        }
        $allServices = @($allServices)
        if (-not $allServices) { throw "No SQL Engine/Agent services found on: $($nodes -join ', ')" }

        Write-Host "`nDetected SQL services:" -ForegroundColor Cyan
        $allServices | Select-Object ComputerName, ServiceName, State, StartName | Format-Table -AutoSize

        # Eligible accounts (grouped across nodes so one password covers the AG pair)
        $groups = $allServices | Group-Object StartName | Where-Object {
            $sampleComputer = @($_.Group.ComputerName)[0]
            $check = Test-AccountEligible -StartName $_.Name -ForComputer $sampleComputer -IncludeDomain $IncludeDomain
            if (-not $check.Ok) {
                Write-Host "Skipping $($_.Name): $($check.Reason)" -ForegroundColor Yellow
                return $false
            }
            $true
        }

        if (-not $groups) {
            Write-Warning 'No eligible accounts to rotate.'
            return
        }

        # Shared-account warning (ignore AG partner — expected to share domain accounts)
        $allowedComputers = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]$nodes, [StringComparer]::OrdinalIgnoreCase)

        $conflicts = foreach ($g in $groups) {
            if (-not $vault.ContainsKey($g.Name)) { continue }
            $prev = $vault[$g.Name].LastComputerName
            if ($prev -and -not $allowedComputers.Contains($prev)) {
                [pscustomobject]@{
                    Account         = $g.Name
                    PreviousServer  = $prev
                    PreviousRotated = $vault[$g.Name].LastRotatedUtc
                }
            }
        }

        $skippedConflicts = @()
        if ($conflicts) {
            Write-Host "`n*** SHARED ACCOUNT WARNING (outside this AG pair) ***" -ForegroundColor Red
            $conflicts | Format-Table -AutoSize
            if ($Unattended) {
                $names = @($conflicts.Account)
                $skippedConflicts = @($groups | Where-Object { $_.Name -in $names })
                $groups = @($groups | Where-Object { $_.Name -notin $names })
                Write-Warning "Unattended: skipped shared account(s): $($names -join ', ')"
            } elseif (-not $PSCmdlet.ShouldProcess(($conflicts.Account -join ', '), 'Rotate shared account used on another server')) {
                return
            }
        }

        if (-not $groups) {
            Write-Warning 'Nothing left to rotate after conflict filtering.'
            if ($skippedConflicts) { exit 2 }
            return
        }

        Write-Host "`nPlan: rotate $($groups.Count) account(s) on $($nodes -join ', ')." -ForegroundColor Cyan
        $groups | Select-Object Name, @{
            N = 'Services'
            E = { ($_.Group | ForEach-Object { "$($_.ComputerName)\$($_.ServiceName)" }) -join ', ' }
        } | Format-Table -AutoSize

        if (-not $PSCmdlet.ShouldProcess("$($groups.Count) account(s)", 'Rotate password')) { return }

        $anyFailures = $false

        foreach ($g in $groups) {
            $account = $g.Name
            if (-not $PSCmdlet.ShouldProcess($account, 'Rotate password')) { continue }

            Write-Host "`nRotating: $account" -ForegroundColor Green
            $securePwd = ConvertTo-SecureString (New-StrongPassword -Length $PasswordLength) -AsPlainText -Force
            $updateOk = $true

            # Domain accounts: reset AD once before touching service configs
            if (-not $SkipAdPasswordReset) {
                try {
                    Reset-DomainAccountPassword -Account $account -SecurePassword $securePwd -LocalComputer $ComputerName
                } catch {
                    Write-Host "  FAILED (AD password): $_" -ForegroundColor Red
                    $updateOk = $false
                    $anyFailures = $true
                }
            }

            # One password, every node that uses this StartName
            foreach ($nodeName in @($g.Group.ComputerName | Select-Object -Unique)) {
                if (-not $updateOk) { break }
                $nodeServices = @($g.Group | Where-Object ComputerName -eq $nodeName)
                $svcCred = $null
                $isRemote = $nodeName -notin @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
                if ($Credential -and $isRemote) { $svcCred = $Credential }

                try {
                    Write-Host "  Update-DbaServiceAccount -NoRestart on $nodeName" -ForegroundColor DarkCyan
                    $result = Update-SqlServicePassword -Services $nodeServices -SecurePassword $securePwd -Credential $svcCred
                    if ($result.Status -contains 'Failed') {
                        $msg = ($result | Where-Object Status -eq 'Failed').Message -join '; '
                        Write-Host "  FAILED on ${nodeName}: $msg" -ForegroundColor Red
                        $updateOk = $false
                        $anyFailures = $true
                    }
                } catch {
                    Write-Host "  FAILED on ${nodeName}: $_" -ForegroundColor Red
                    $updateOk = $false
                    $anyFailures = $true
                }
            }

            if ($updateOk) {
                $vault[$account] = @{
                    EncryptedPassword = ConvertFrom-SecureString -SecureString $securePwd -Key $machineKey
                    LastComputerName  = $ComputerName
                    LastPartnerName   = $PartnerComputerName
                    LastServices      = (($g.Group | ForEach-Object { "$($_.ComputerName)\$($_.ServiceName)" }) -join ', ')
                    LastRotatedUtc    = (Get-Date).ToUniversalTime().ToString('u')
                    LastRotatedBy     = "$env:USERDOMAIN\$env:USERNAME"
                }
                Write-VaultAtomic -Vault $vault -Path $vaultPath
                Write-Host '  Password updated (services not restarted yet).' -ForegroundColor Green
            }

            if ($securePwd) {
                $securePwd.Dispose()
                Remove-Variable securePwd -ErrorAction SilentlyContinue
            }
        }

        # Controlled apply
        if (-not $SkipRestart -and -not $anyFailures) {
            if ($agPair) {
                $roll = @{
                    HomeComputer        = $ComputerName
                    PartnerComputer     = $PartnerComputerName
                    HomeSqlInstance     = $SqlInstance
                    PartnerSqlInstance  = $PartnerSqlInstance
                    AvailabilityGroup   = $AvailabilityGroup
                    InstanceName        = $InstanceName
                    Credential          = $Credential
                    SqlCredential       = $SqlCredential
                    SyncTimeoutSeconds  = $SyncTimeoutSeconds
                    SkipFailback        = $SkipFailback
                }
                # Propagate non-interactive confirm to nested advanced function
                if ($Unattended -or $ConfirmPreference -eq 'None') { $roll.Confirm = $false }
                Invoke-AgRollingRestart @roll
            } else {
                if ($PSCmdlet.ShouldProcess($ComputerName, 'Restart SQL Engine/Agent')) {
                    $svcCred = $null
                    $isRemote = $ComputerName -notin @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
                    if ($Credential -and $isRemote) { $svcCred = $Credential }
                    Restart-SqlEngineAgent -Computer $ComputerName -InstanceName $InstanceName -Credential $svcCred
                }
            }
        } elseif ($SkipRestart) {
            Write-Warning 'SkipRestart set - password changed in the service config only. Restart/failover later to apply.'
        }

        # Non-secret history
        $reportPath = Join-Path $OutputFolder 'SqlServiceAccountVault_History.csv'
        $vault.Keys | ForEach-Object {
            $e = $vault[$_]
            [pscustomobject]@{
                Account          = $_
                LastComputerName = $e.LastComputerName
                LastPartnerName  = $e.LastPartnerName
                LastServices     = $e.LastServices
                LastRotatedUtc   = $e.LastRotatedUtc
                LastRotatedBy    = $e.LastRotatedBy
            }
        } | Sort-Object Account | Export-Csv -Path $reportPath -NoTypeInformation -Force

        Write-Host "`nVault:   $vaultPath" -ForegroundColor Cyan
        Write-Host "History: $reportPath (no secrets)" -ForegroundColor Cyan

        if ($anyFailures) {
            Write-Warning 'One or more updates failed.'
            exit 1
        }
        if ($skippedConflicts) {
            Write-Warning "$($skippedConflicts.Count) shared account(s) skipped - needs a coordinated pass."
            exit 2
        }
    } finally {
        if ($gotLock) { [void]$mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
} finally {
    Stop-Transcript | Out-Null
}
