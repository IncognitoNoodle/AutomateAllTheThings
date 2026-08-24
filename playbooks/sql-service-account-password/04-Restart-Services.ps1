<#
.SYNOPSIS
    Stage 04 — Restart SQL services and (for AG Engine/Agent) graceful failover.

.DESCRIPTION
    Separated from password apply so a failure mid-restart is recoverable without
    re-touching AD or service caches.

    Standalone: restart targeted types on the node.
    AG + Engine/Agent: restart secondary → wait sync → failover → restart former
    primary → wait sync. Failback is OFF by default. Use -Failback or -FailbackOnly.

    SSRS/SSIS-only: restart those types on all nodes; no AG failover.

.EXAMPLE
    $p = ConvertTo-SecureString 'NewPw!' -AsPlainText -Force
    .\04-Restart-Services.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
        -Account 'DOMAIN\svcSql' -SecurePassword $p

.EXAMPLE
    .\04-Restart-Services.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
        -FailbackOnly -OriginalPrimary 'SQL01\INST'
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
    [string]$OutputFolder,

    [ValidateRange(30, 3600)]
    [int]$SyncTimeoutSeconds = 300,

    # Pre-restart AD gate: keep poll slow (300s) to avoid lockouts
    [ValidateRange(60, 14400)]
    [int]$NodeTimeoutSeconds = 600,

    [ValidateRange(30, 900)]
    [int]$NodePollSeconds = 300,

    [switch]$Failback,

    [Parameter(ParameterSetName = 'FailbackOnly')]
    [switch]$FailbackOnly,

    # Desired primary for -FailbackOnly (else 04-restart-latest / discovery-latest)
    [string]$OriginalPrimary,

    [switch]$InstallModule
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. (Join-Path $here 'Common\SqlServiceAccount.Common.ps1')

$OutputFolder = Resolve-SsaOutputFolder -OutputFolder $OutputFolder
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

$passwordMap = $null
if ($Account -and $SecurePassword) {
    $passwordMap = Resolve-AccountPasswordMap -Account $Account -SecurePassword $SecurePassword
} elseif ($Account -and -not $SecurePassword) {
    throw 'When -Account is supplied, also pass -SecurePassword (needed for auth-failure unlock/retry).'
}

Start-Transcript -Path (Join-Path $OutputFolder "04-Restart_$timestamp.log") -NoClobber | Out-Null

try {
    Import-SsaDependencies -InstallModule:$InstallModule -PreferActiveDirectory
    Write-SsaBanner 'Stage 04 — Restart services / graceful AG failover'

    $topo = Get-TargetTopology -SqlInstance $SqlInstance -AvailabilityGroup $AvailabilityGroup `
        -SqlCredential $SqlCredential -Credential $Credential
    Write-Host "Mode: $($topo.Mode)" -ForegroundColor Cyan
    $topo.Nodes | Format-Table ComputerName, SqlInstance, Role -AutoSize
    if ($topo.AgNames) { Write-Host "AGs: $($topo.AgNames -join ', ')" -ForegroundColor Cyan }

    if ($FailbackOnly) {
        if ($topo.Mode -ne 'AvailabilityGroup') { throw '-FailbackOnly requires an Availability Group topology.' }

        $desired = $OriginalPrimary
        if (-not $desired) {
            $restartState = Read-SsaStageState -OutputFolder $OutputFolder -Stage '04-restart'
            if ($restartState -and $restartState.OriginalPrimary) { $desired = [string]$restartState.OriginalPrimary }
        }
        if (-not $desired) {
            $disc = Read-SsaDiscovery -OutputFolder $OutputFolder
            if ($disc -and $disc.OriginalPrimary) { $desired = [string]$disc.OriginalPrimary }
        }
        if (-not $desired) {
            throw 'Cannot determine original primary. Pass -OriginalPrimary or re-run stage 01/04 first.'
        }

        $currentPrimary = $topo.OriginalPrimary
        Write-Host "FailbackOnly: target=$desired (live primary=$currentPrimary)" -ForegroundColor Cyan
        if (Test-ReplicaMatch -ReplicaName $currentPrimary -SqlInstance $desired) {
            Write-Host "Already primary on $desired — nothing to do." -ForegroundColor Green
            return
        }

        Invoke-SsaAgFailover -TargetSqlInstance $desired -AgNames $topo.AgNames -SqlCredential $SqlCredential
        $secondary = @($topo.Nodes | Where-Object { -not (Test-ReplicaMatch $_.SqlInstance $desired) } | Select-Object -First 1)
        if ($secondary) {
            Wait-AgReady -SqlInstance $desired -AgNames $topo.AgNames -SecondarySqlInstance $secondary.SqlInstance `
                -SqlCredential $SqlCredential -TimeoutSeconds $SyncTimeoutSeconds
        }

        $null = Save-SsaStageState -OutputFolder $OutputFolder -Stage '04-restart' -State ([pscustomobject]@{
                CompletedAt     = (Get-Date).ToString('o')
                Mode            = $topo.Mode
                OriginalPrimary = $desired
                CurrentPrimary  = $desired
                FailedBack      = $true
                FailbackOnly    = $true
            })
        Write-Host "Failback complete. Primary: $desired" -ForegroundColor Green
        return
    }

    $typesToRestart = @($Type | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $typesToRestart) {
        $applyState = Read-SsaStageState -OutputFolder $OutputFolder -Stage '03-apply'
        if ($applyState -and $applyState.TypesTouched) {
            $typesToRestart = @($applyState.TypesTouched)
            Write-Host "Types from 03-apply-latest.json: $($typesToRestart -join ', ')" -ForegroundColor DarkCyan
        }
    }
    if (-not $typesToRestart) {
        $services = @(Get-SqlTargetService -Nodes $topo.Nodes -InstanceName $InstanceName `
                -Credential $Credential -SqlCredential $SqlCredential)
        if ($Account -and $passwordMap) {
            $domainAccounts = @(Get-DomainSqlServiceAccount -Services $services)
            $typesToRestart = @(
                $domainAccounts |
                    Where-Object { $passwordMap.ContainsKey($_.Account) } |
                    ForEach-Object { $_.Group } |
                    ForEach-Object { [string]$_.ServiceType } |
                    Sort-Object -Unique
            )
        }
        if (-not $typesToRestart) { $typesToRestart = @(Get-SsaServiceTypes) }
    }
    Write-Host "Types to restart: $($typesToRestart -join ', ')" -ForegroundColor Cyan

    $restartAccounts = @($Account)
    $restartPasswords = if ($passwordMap) { $passwordMap } else {
        [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
    }

    if ($Account -and $passwordMap) {
        $sqlNodes = @($topo.Nodes.ComputerName | Sort-Object -Unique)
        foreach ($acct in $Account) {
            Write-Host "`nPre-restart AD check: $acct" -ForegroundColor Cyan
            Unlock-AdServiceAccount -Account $acct
            Wait-AdCredentialReadyOnNode -Account $acct -SecurePassword $passwordMap[$acct] `
                -ComputerName $sqlNodes -Credential $Credential `
                -TimeoutSeconds $NodeTimeoutSeconds -PollSeconds $NodePollSeconds
        }
    } else {
        Write-Warning 'No -Account/-SecurePassword: restart proceeds without AD re-validation / unlock retry.'
    }

    $needsAgFailover = @($typesToRestart | Where-Object { $_ -in @('Engine', 'Agent') }).Count -gt 0
    $agResult = $null

    if ($topo.Mode -eq 'AvailabilityGroup' -and $needsAgFailover) {
        if ($Failback) {
            Write-Host 'Failback will run after former-primary restart (-Failback).' -ForegroundColor Yellow
        } else {
            Write-Host 'Failback skipped (recommended). Use -Failback or later -FailbackOnly if required.' -ForegroundColor DarkCyan
        }

        $agResult = Invoke-SsaGracefulAgRestart `
            -Nodes $topo.Nodes `
            -AgNames $topo.AgNames `
            -OriginalPrimary $topo.OriginalPrimary `
            -ServiceType $typesToRestart `
            -Credential $Credential `
            -SqlCredential $SqlCredential `
            -SyncTimeoutSeconds $SyncTimeoutSeconds `
            -Account $restartAccounts `
            -AccountPassword $restartPasswords `
            -Failback:$Failback
    } else {
        if ($topo.Mode -eq 'AvailabilityGroup' -and -not $needsAgFailover) {
            Write-Host 'SSRS/SSIS only (or non-Engine/Agent): restarting on all nodes — no AG failover.' -ForegroundColor Cyan
        }
        foreach ($node in $topo.Nodes) {
            Restart-SqlTargetService -Computer $node.ComputerName -SqlInstance $node.SqlInstance -Type $typesToRestart `
                -Credential (Get-RemoteCredential -Computer $node.ComputerName -Credential $Credential) `
                -SqlCredential $SqlCredential -Account $restartAccounts -AccountPassword $restartPasswords
            Wait-SqlTargetServiceRunning -Computer $node.ComputerName -SqlInstance $node.SqlInstance -Type $typesToRestart `
                -Credential (Get-RemoteCredential -Computer $node.ComputerName -Credential $Credential) `
                -SqlCredential $SqlCredential -TimeoutSeconds ([Math]::Min(180, $SyncTimeoutSeconds))
        }
    }

    $null = Save-SsaStageState -OutputFolder $OutputFolder -Stage '04-restart' -State ([pscustomobject]@{
            CompletedAt     = (Get-Date).ToString('o')
            Mode            = $topo.Mode
            TypesRestarted  = $typesToRestart
            OriginalPrimary = if ($agResult) { $agResult.OriginalPrimary } else { $topo.OriginalPrimary }
            CurrentPrimary  = if ($agResult) { $agResult.CurrentPrimary } else { $topo.OriginalPrimary }
            FailedBack      = if ($agResult) { $agResult.FailedBack } else { $false }
            Accounts        = @($Account)
        })

    Write-Host "`nNext: .\05-Validate-Health.ps1" -ForegroundColor Cyan
} finally {
    Stop-Transcript | Out-Null
}
