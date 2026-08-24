<#
.SYNOPSIS
    Stage 04 — Restart SQL services and (for AG Engine/Agent) graceful failover.

.DESCRIPTION
    Separated from password apply so a failure mid-restart is recoverable without
    re-touching AD or service caches.

    Standalone: restart targeted types on the node.
    AG + Engine/Agent: restart secondary → wait sync → failover → restart former
    primary → wait sync. Failback is OFF by default (safer). Use -Failback to
    restore original primary after sync, or -FailbackOnly later.

    SSRS/SSIS-only changes: restart those types on all nodes; no AG failover.

.EXAMPLE
    $p = ConvertTo-SecureString 'NewPw!' -AsPlainText -Force
    .\04-Restart-Services.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
        -Account 'DOMAIN\svcSql' -SecurePassword $p

.EXAMPLE
    .\04-Restart-Services.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' -FailbackOnly
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding(DefaultParameterSetName = 'Restart')]
param(
    [Parameter(Mandatory)]
    [string]$SqlInstance,

    [string[]]$AvailabilityGroup,

    [string[]]$InstanceName,

    [string[]]$Account,

    [SecureString[]]$SecurePassword,

    [string[]]$Type,

    [PSCredential]$Credential,

    [PSCredential]$SqlCredential,

    [string]$OutputFolder = '\\SERVERNAME\C$\Temp\SqlServiceAccountRotation\',

    [ValidateRange(30, 3600)]
    [int]$SyncTimeoutSeconds = 300,

    [switch]$Failback,

    [Parameter(ParameterSetName = 'FailbackOnly')]
    [switch]$FailbackOnly,

    [switch]$InstallModule
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here 'Common\SqlServiceAccount.Common.psm1') -Force

$OutputFolder = Initialize-SsaOutputFolder -OutputFolder $OutputFolder
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

$passwordMap = $null
if ($Account -and $SecurePassword) {
    $passwordMap = Resolve-AccountPasswordMap -Account $Account -SecurePassword $SecurePassword
} elseif ($Account -and -not $SecurePassword) {
    throw 'When -Account is supplied, also pass -SecurePassword (needed for auth-failure unlock/retry).'
}

Start-Transcript -Path (Join-Path $OutputFolder "04-Restart_$timestamp.log") -NoClobber | Out-Null

try {
    Import-SsaDependencies -InstallModule:$InstallModule
    Write-SsaBanner 'Stage 04 — Restart services / graceful AG failover'

    $topo = Get-TargetTopology -SqlInstance $SqlInstance -AvailabilityGroup $AvailabilityGroup `
        -SqlCredential $SqlCredential -Credential $Credential
    Write-Host "Mode: $($topo.Mode)" -ForegroundColor Cyan
    $topo.Nodes | Format-Table ComputerName, SqlInstance, Role -AutoSize
    if ($topo.AgNames) { Write-Host "AGs: $($topo.AgNames -join ', ')" -ForegroundColor Cyan }

    if ($FailbackOnly) {
        if ($topo.Mode -ne 'AvailabilityGroup') { throw '-FailbackOnly requires an Availability Group topology.' }
        $primaryNow = $topo.OriginalPrimary
        $desired = $null
        $disc = Read-SsaDiscovery -OutputFolder $OutputFolder
        if ($disc -and $disc.OriginalPrimary) { $desired = [string]$disc.OriginalPrimary }
        if (-not $desired) {
            throw 'Cannot determine original primary for failback. Re-run stage 01 or pass topology where current seed is the desired primary and use Invoke-DbaAgFailover manually.'
        }
        Write-Host "FailbackOnly: failing back to $desired (current primary reported: $primaryNow)" -ForegroundColor Cyan
        # Re-read live primary
        $live = Get-TargetTopology -SqlInstance $SqlInstance -AvailabilityGroup $AvailabilityGroup `
            -SqlCredential $SqlCredential -Credential $Credential
        $currentPrimary = $live.OriginalPrimary
        if (Test-ReplicaMatch -ReplicaName $currentPrimary -SqlInstance $desired) {
            Write-Host "Already primary on $desired — nothing to do." -ForegroundColor Green
            return
        }
        $fo = @{
            SqlInstance       = $desired
            AvailabilityGroup = $live.AgNames
            Confirm           = $false
            EnableException   = $true
        }
        if ($SqlCredential) { $fo.SqlCredential = $SqlCredential }
        Invoke-DbaAgFailover @fo | Out-Null
        $secondary = @($live.Nodes | Where-Object { -not (Test-ReplicaMatch $_.SqlInstance $desired) } | Select-Object -First 1)
        if ($secondary) {
            Wait-AgReady -SqlInstance $desired -AgNames $live.AgNames -SecondarySqlInstance $secondary.SqlInstance `
                -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds
        }
        Write-Host "Failback complete. Primary: $desired" -ForegroundColor Green
        return
    }

    # Determine service types to restart
    $typesToRestart = @($Type | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $typesToRestart) {
        $services = @(Get-SqlTargetService -Nodes $topo.Nodes -InstanceName $InstanceName `
                -Credential $Credential -SqlCredential $SqlCredential)
        if ($Account) {
            $domainAccounts = @(Get-DomainSqlServiceAccount -Services $services)
            $typesToRestart = @(
                $domainAccounts |
                    Where-Object { $passwordMap.ContainsKey($_.Account) } |
                    ForEach-Object { $_.Group } |
                    ForEach-Object { [string]$_.ServiceType } |
                    Sort-Object -Unique
            )
        }
        if (-not $typesToRestart) {
            $typesToRestart = @(Get-SsaServiceTypes)
        }
    }
    Write-Host "Types to restart: $($typesToRestart -join ', ')" -ForegroundColor Cyan

    $restartAccounts = @($Account)
    $restartPasswords = $passwordMap
    if (-not $restartPasswords) {
        $restartPasswords = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
    }

    # Final AD gate before restart (prevents lockouts)
    if ($Account -and $passwordMap) {
        $sqlNodes = @($topo.Nodes.ComputerName | Sort-Object -Unique)
        foreach ($acct in $Account) {
            Write-Host "`nPre-restart AD check: $acct" -ForegroundColor Cyan
            Unlock-AdServiceAccount -Account $acct
            Wait-AdCredentialReadyOnNode -Account $acct -SecurePassword $passwordMap[$acct] `
                -ComputerName $sqlNodes -Credential $Credential -TimeoutSeconds 600 -PollSeconds 60
        }
    } else {
        Write-Warning 'No -Account/-SecurePassword supplied: restart will proceed without AD re-validation / unlock retry.'
    }

    $needsAgFailover = @($typesToRestart | Where-Object { $_ -in @('Engine', 'Agent') }).Count -gt 0

    if ($topo.Mode -eq 'AvailabilityGroup' -and $needsAgFailover) {
        $nodes = @($topo.Nodes)
        $bySql = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($n in $nodes) { $bySql[$n.SqlInstance] = $n }

        $primarySql = $topo.OriginalPrimary
        if (-not $bySql.ContainsKey($primarySql)) {
            $mapped = $nodes | Where-Object {
                (Test-ReplicaMatch -ReplicaName $primarySql -SqlInstance $_.SqlInstance) -or
                (Test-ComputerNameMatch -Left $_.ComputerName -Right ($primarySql.Split('\')[0]))
            } | Select-Object -First 1
            if (-not $mapped) { throw "Could not map primary '$primarySql' to discovered nodes." }
            $primarySql = $mapped.SqlInstance
        }
        $primary = $bySql[$primarySql]
        $secondary = $nodes | Where-Object { $_.SqlInstance -ne $primarySql } | Select-Object -First 1
        if (-not $secondary) { throw 'AG mode requires at least two replicas.' }

        Write-Host "`n=== AG graceful restart (failback default: OFF) ===" -ForegroundColor Cyan
        Write-Host "Primary:   $($primary.SqlInstance) [$($primary.ComputerName)]" -ForegroundColor Cyan
        Write-Host "Secondary: $($secondary.SqlInstance) [$($secondary.ComputerName)]" -ForegroundColor Cyan
        Write-Host 'Order: secondary restart → sync → failover → former primary restart → sync' -ForegroundColor Yellow
        if ($Failback) {
            Write-Host 'Then: failback to original primary (-Failback)' -ForegroundColor Yellow
        } else {
            Write-Host 'Failback skipped (recommended). Use -Failback or later -FailbackOnly if required.' -ForegroundColor DarkCyan
        }

        Restart-SqlTargetService -Computer $secondary.ComputerName -SqlInstance $secondary.SqlInstance -Type $typesToRestart `
            -Credential (Get-RemoteCredential $secondary.ComputerName $Credential) -SqlCredential $SqlCredential `
            -Account $restartAccounts -AccountPassword $restartPasswords
        Wait-SqlTargetServiceRunning -Computer $secondary.ComputerName -SqlInstance $secondary.SqlInstance -Type $typesToRestart `
            -Credential (Get-RemoteCredential $secondary.ComputerName $Credential) -SqlCredential $SqlCredential `
            -TimeoutSeconds ([Math]::Min(180, $SyncTimeoutSeconds))
        Wait-AgReady -SqlInstance $primary.SqlInstance -AgNames $topo.AgNames -SecondarySqlInstance $secondary.SqlInstance `
            -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds

        Write-Host "  Failover -> $($secondary.SqlInstance)" -ForegroundColor Cyan
        $fo = @{
            SqlInstance       = $secondary.SqlInstance
            AvailabilityGroup = $topo.AgNames
            Confirm           = $false
            EnableException   = $true
        }
        if ($SqlCredential) { $fo.SqlCredential = $SqlCredential }
        Invoke-DbaAgFailover @fo | Out-Null
        Start-Sleep -Seconds 3
        Wait-AgReady -SqlInstance $secondary.SqlInstance -AgNames $topo.AgNames -SecondarySqlInstance $primary.SqlInstance `
            -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds

        Restart-SqlTargetService -Computer $primary.ComputerName -SqlInstance $primary.SqlInstance -Type $typesToRestart `
            -Credential (Get-RemoteCredential $primary.ComputerName $Credential) -SqlCredential $SqlCredential `
            -Account $restartAccounts -AccountPassword $restartPasswords
        Wait-SqlTargetServiceRunning -Computer $primary.ComputerName -SqlInstance $primary.SqlInstance -Type $typesToRestart `
            -Credential (Get-RemoteCredential $primary.ComputerName $Credential) -SqlCredential $SqlCredential `
            -TimeoutSeconds ([Math]::Min(180, $SyncTimeoutSeconds))
        Wait-AgReady -SqlInstance $secondary.SqlInstance -AgNames $topo.AgNames -SecondarySqlInstance $primary.SqlInstance `
            -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds

        if ($Failback) {
            Write-Host "  Failback -> $($primary.SqlInstance)" -ForegroundColor Cyan
            $fb = @{
                SqlInstance       = $primary.SqlInstance
                AvailabilityGroup = $topo.AgNames
                Confirm           = $false
                EnableException   = $true
            }
            if ($SqlCredential) { $fb.SqlCredential = $SqlCredential }
            Invoke-DbaAgFailover @fb | Out-Null
            Wait-AgReady -SqlInstance $primary.SqlInstance -AgNames $topo.AgNames -SecondarySqlInstance $secondary.SqlInstance `
                -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds
            Write-Host "  Primary restored on $($primary.SqlInstance)." -ForegroundColor Green
        } else {
            Write-Host "  Done. Primary is now on $($secondary.SqlInstance) (no failback)." -ForegroundColor Green
        }
    } else {
        if ($topo.Mode -eq 'AvailabilityGroup' -and -not $needsAgFailover) {
            Write-Host 'SSRS/SSIS only (or non-Engine/Agent): restarting on all nodes — no AG failover.' -ForegroundColor Cyan
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

    Write-Host "`nNext: .\05-Validate-Health.ps1" -ForegroundColor Cyan
} finally {
    Stop-Transcript | Out-Null
}
