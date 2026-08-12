<#
.SYNOPSIS
    Apply SecOps-provided passwords to domain AD SQL service accounts (no AD change).

.DESCRIPTION
    Discovers domain AD service accounts for Engine/Agent/SSRS/SSIS (not local users).
    Applies one or more SecOps passwords in a single pass, then restarts once
    (standalone) or AG secondary-restart / failover / former-primary-restart / failback.
    Does not update AD and does not store passwords in a vault.

    Before restart, waits until the supplied password validates on the management host
    AND on each SQL node (WinRM). SecOps may have reset AD on a DC that SQL nodes
    have not replicated from yet.

.NOTES
    Per-node checks use WinRM Invoke-Command. Domain Kerberos WinRM encrypts the
    session (including the brief password used for ValidateCredentials). Prefer
    Kerberos; avoid Basic auth / CredSSP. HTTPS WinRM is optional environment
    hardening and is not required by this script.

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

    [switch]$InstallModule,

    [ValidateRange(30, 3600)]
    [int]$SyncTimeoutSeconds = 300
)

# === CONFIG (edit here) ===
$script:OutputFolder = '\\SERVERNAME\C$\Temp\'
$script:ServiceTypes = @('Engine', 'Agent', 'SSRS', 'SSIS')

$ErrorActionPreference = 'Stop'
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
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

function Unlock-AdServiceAccount {
    param([string]$Account)
    $sam = $Account.Split('\')[-1]
    if ($sam -match '@') { $sam = $sam.Split('@')[0] }
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

function Test-AdCredentialHere {
    # ValidateCredentials requires a plain string; SecureString is used at the call sites.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PlainPassword')]
    param([string]$Domain, [string]$SamAccountName, [string]$PlainPassword)
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
    $ctx = [DirectoryServices.AccountManagement.PrincipalContext]::new(
        [DirectoryServices.AccountManagement.ContextType]::Domain,
        $Domain
    )
    try { return [bool]$ctx.ValidateCredentials($SamAccountName, $PlainPassword) }
    finally { $ctx.Dispose() }
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
    $domain = if ($Account -match '\\') {
        $Account.Split('\')[0]
    } elseif ($Account -match '@') {
        $Account.Split('@')[1]
    } else {
        $env:USERDOMAIN
    }
    $plain = [Net.NetworkCredential]::new('', $SecurePassword).Password
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $successes = 0
    Write-Host "  AD (mgmt host): waiting for $Account (up to ${TimeoutSeconds}s)" -ForegroundColor DarkCyan

    do {
        try {
            Unlock-AdServiceAccount -Account $Account
            if (Test-AdCredentialHere -Domain $domain -SamAccountName $sam -PlainPassword $plain) {
                $successes++
                Write-Host "  AD (mgmt host): OK for $Account ($successes/$RequiredSuccesses)" -ForegroundColor Green
                if ($successes -ge $RequiredSuccesses) { return }
            } else {
                $successes = 0
            }
        } catch {
            $successes = 0
            Write-Host ("  AD (mgmt host) wait: {0}" -f $_) -ForegroundColor DarkYellow
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)

    throw "AD password for '$Account' not accepted on management host within ${TimeoutSeconds}s."
}

function Test-AdCredentialOnComputer {
    <#
      Validate from the SQL node itself so we use THAT machine's DC affinity.
      Domain Kerberos WinRM encrypts the remoting session (password not cleartext).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PlainPassword')]
    param(
        [string]$Computer,
        [string]$Account,
        [string]$PlainPassword,
        [PSCredential]$Credential
    )

    $sam = $Account.Split('\')[-1]
    $domain = if ($Account -match '\\') {
        $Account.Split('\')[0]
    } elseif ($Account -match '@') {
        $Account.Split('@')[1]
    } else {
        $env:USERDOMAIN
    }
    $localNames = @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
    if ($Computer -in $localNames) {
        return Test-AdCredentialHere -Domain $domain -SamAccountName $sam -PlainPassword $PlainPassword
    }

    $sb = {
        param($Domain, $Sam, $SecretText)
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
            [System.DirectoryServices.AccountManagement.ContextType]::Domain,
            $Domain
        )
        try { return [bool]$ctx.ValidateCredentials($Sam, $SecretText) }
        finally { $ctx.Dispose() }
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
      Phase 2: wait until each SQL node accepts the SecOps password via its own DC path.
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
        Start-Sleep -Seconds 8
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
            ($_.ComputerName -eq $OriginalPrimary.Split('\')[0])
        } | Select-Object -First 1
        if (-not $mapped) { throw "Could not map primary '$OriginalPrimary' to discovered nodes." }
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

    Restart-SqlTargetService -Computer $secondary.ComputerName -Type $ServiceType `
        -Credential (Get-RemoteCredential $secondary.ComputerName $Credential) `
        -Account $Account -AccountPassword $AccountPassword
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

    Restart-SqlTargetService -Computer $primary.ComputerName -Type $ServiceType `
        -Credential (Get-RemoteCredential $primary.ComputerName $Credential) `
        -Account $Account -AccountPassword $AccountPassword
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
            try {
                $accountNodes = @($row.Group.ComputerName | Sort-Object -Unique)
                Wait-AdCredentialReady -Account $acct -SecurePassword $securePwd -TimeoutSeconds $SyncTimeoutSeconds
                Wait-AdCredentialReadyOnNode -Account $acct -SecurePassword $securePwd `
                    -ComputerName $accountNodes -Credential $Credential -TimeoutSeconds $SyncTimeoutSeconds
                $updatedAccounts.Add($acct)
                Write-Host '  Service password updated; AD ready on SQL nodes (not restarted yet).' -ForegroundColor Green
            } catch {
                Write-Host "  FAILED (AD wait): $_" -ForegroundColor Red
                $ok = $false; $anyFailures = $true
            }
        }
    }

    if (-not $anyFailures) {
        # Pre-restart: re-check on all topology nodes (site DC lag after service update).
        $sqlNodes = @($topo.Nodes.ComputerName | Sort-Object -Unique)
        $restartAccounts = @($updatedAccounts)
        $restartPasswords = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($acct in $restartAccounts) {
            $restartPasswords[$acct] = $passwordMap[$acct]
            Write-Host "`nPre-restart AD check on SQL nodes: $acct" -ForegroundColor Cyan
            Wait-AdCredentialReadyOnNode -Account $acct -SecurePassword $restartPasswords[$acct] `
                -ComputerName $sqlNodes -Credential $Credential `
                -TimeoutSeconds ([Math]::Min(180, $SyncTimeoutSeconds))
        }

        # Restart only service types we actually updated (avoids touching unrelated SSRS/SSIS).
        $typesToRestart = @(
            $targets |
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
                -Account $restartAccounts `
                -AccountPassword $restartPasswords
        } else {
            $node = $topo.Nodes[0]
            Restart-SqlTargetService -Computer $node.ComputerName -Type $typesToRestart `
                -Credential (Get-RemoteCredential $node.ComputerName $Credential) `
                -Account $restartAccounts -AccountPassword $restartPasswords
        }
    }

    if ($updatedAccounts.Count) {
        Write-Host "`nUpdated account(s): $($updatedAccounts -join ', ')" -ForegroundColor Green
    }

    if ($anyFailures) { Write-Warning 'One or more updates failed.'; exit 1 }
} finally {
    Stop-Transcript | Out-Null
}
