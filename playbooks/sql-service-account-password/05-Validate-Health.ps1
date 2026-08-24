<#
.SYNOPSIS
    Stage 05 — Validate services, AD account health, SPNs, and AG database sync.

.DESCRIPTION
    Post-change verification. Confirms Engine/Agent/SSRS/SSIS are Running, domain
    accounts are unlocked/enabled, SPNs still present, and AG databases are
    Synchronized (or Synchronizing for async). Exit code 1 if critical issues remain.

.EXAMPLE
    .\05-Validate-Health.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
        -Account 'DOMAIN\svcSql'
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SqlInstance,

    [string[]]$AvailabilityGroup,
    [string[]]$InstanceName,
    [string[]]$Account,
    [PSCredential]$Credential,
    [PSCredential]$SqlCredential,
    [string]$OutputFolder,
    [switch]$InstallModule
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. (Join-Path $here 'Common\SqlServiceAccount.Common.ps1')

$OutputFolder = Resolve-SsaOutputFolder -OutputFolder $OutputFolder
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
Start-Transcript -Path (Join-Path $OutputFolder "05-Validate_$timestamp.log") -NoClobber | Out-Null

try {
    Import-SsaDependencies -InstallModule:$InstallModule -PreferActiveDirectory
    Write-SsaBanner 'Stage 05 — Validate health / AG sync / SPNs'

    $topo = Get-TargetTopology -SqlInstance $SqlInstance -AvailabilityGroup $AvailabilityGroup `
        -SqlCredential $SqlCredential -Credential $Credential
    Write-Host "Mode: $($topo.Mode)" -ForegroundColor Cyan
    $topo.Nodes | Format-Table ComputerName, SqlInstance, Role -AutoSize

    $services = @(Get-SqlTargetService -Nodes $topo.Nodes -InstanceName $InstanceName `
            -Credential $Credential -SqlCredential $SqlCredential)

    Write-Host "`nService state:" -ForegroundColor Cyan
    $services | Select-Object ComputerName, ServiceName, ServiceType, State, StartName |
        Sort-Object ComputerName, ServiceType |
        Format-Table -AutoSize

    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($svc in $services) {
        if ([string]$svc.ServiceType -in @('Engine', 'Agent') -and [string]$svc.State -ne 'Running') {
            Add-SsaFinding $findings Critical Service "$($svc.ComputerName)\$($svc.ServiceName)" "State=$($svc.State)" `
                'Re-run stage 04 restart for this node/type; check ERRORLOG / System event log'
        }
        if ([string]$svc.ServiceType -in @('SSRS', 'SSIS') -and [string]$svc.State -ne 'Running') {
            Add-SsaFinding $findings Warning Service "$($svc.ComputerName)\$($svc.ServiceName)" "State=$($svc.State)" `
                'Confirm whether this service is required; restart or exclude'
        }
    }

    $domainAccounts = @(Get-DomainSqlServiceAccount -Services $services)
    $checkAccounts = @($Account | Where-Object { $_ })
    if (-not $checkAccounts) { $checkAccounts = @($domainAccounts.Account) }

    foreach ($acct in $checkAccounts) {
        Write-Host "`nAD / SPN: $acct" -ForegroundColor Cyan
        try {
            $ad = Get-AdServiceAccountStatus -Account $acct
            if ($ad.Available) {
                $ad | Format-List Enabled, LockedOut, PasswordExpired, PasswordNeverExpires, AccountExpirationDate, PasswordLastSet, BadPwdCount
                if (-not $ad.Enabled) { Add-SsaFinding $findings Critical AD $acct 'Disabled' 'Enable-ADAccount' }
                if ($ad.LockedOut) { Add-SsaFinding $findings Critical AD $acct 'Locked out' 'Unlock-ADAccount; investigate bad password sources' }
                if ($ad.PasswordExpired) { Add-SsaFinding $findings Critical AD $acct 'Password expired' 'Re-run stage 02' }
            } else {
                Write-Warning $ad.Message
            }
        } catch {
            Add-SsaFinding $findings Warning AD $acct ([string]$_) 'Verify AD connectivity'
        }

        $spn = Get-ServiceAccountSpn -Account $acct
        if ($spn.SpnCount -eq 0) {
            Add-SsaFinding $findings Warning SPN $acct 'No SPNs listed' "setspn -L $acct"
        } else {
            $spn.Spns | ForEach-Object { Write-Host "  $_" }
            $svcTypes = @(($domainAccounts | Where-Object Account -eq $acct).ServiceTypes)
            if (($svcTypes -match 'Engine') -and -not $spn.HasMssqlSpn) {
                Add-SsaFinding $findings Warning SPN $acct 'Missing MSSQLSvc/*' 'Register SQL SPNs or confirm alternate account'
            }
        }
    }

    if ($topo.Mode -eq 'AvailabilityGroup') {
        Write-Host "`nAG database synchronization:" -ForegroundColor Cyan
        try {
            $dbRows = @(Get-AgDatabaseSyncStatus -SqlInstance $SqlInstance -AgNames $topo.AgNames -SqlCredential $SqlCredential)
            if (-not $dbRows) {
                Add-SsaFinding $findings Warning AG ($topo.AgNames -join ',') 'No database replica rows returned' 'Check AG membership / permissions'
            } else {
                $dbRows | Format-Table AvailabilityGroup, DatabaseName, Replica, SynchronizationState, SynchronizationHealth, IsSuspended -AutoSize
                foreach ($r in $dbRows) {
                    if ($r.IsSuspended) {
                        Add-SsaFinding $findings Critical AG "$($r.AvailabilityGroup)/$($r.DatabaseName)" "Suspended on $($r.Replica)" 'Resume data movement'
                    }
                    $sync = [string]$r.SynchronizationState
                    if ($sync -notin @('Synchronized', 'Synchronizing')) {
                        Add-SsaFinding $findings Critical AG "$($r.AvailabilityGroup)/$($r.DatabaseName)" `
                            "$($r.Replica) state=$sync health=$($r.SynchronizationHealth)" `
                            'Wait for catch-up; check AG dashboard / mirroring endpoints'
                    }
                }

                $agParams = @{
                    SqlInstance       = $SqlInstance
                    AvailabilityGroup = $topo.AgNames
                    EnableException   = $true
                    WarningAction     = 'SilentlyContinue'
                }
                if ($SqlCredential) { $agParams.SqlCredential = $SqlCredential }
                $ags = @(Get-DbaAvailabilityGroup @agParams)
                foreach ($ag in $ags) {
                    Write-Host "AG $($ag.Name) primary: $($ag.PrimaryReplicaServerName)" -ForegroundColor DarkCyan
                    foreach ($rep in $ag.AvailabilityReplicas) {
                        $conn = [string]$rep.ConnectionState
                        $roll = [string]$rep.RollupSynchronizationState
                        if ($conn -ne 'Connected') {
                            Add-SsaFinding $findings Critical AG "$($ag.Name)/$($rep.Name)" "ConnectionState=$conn" 'Fix connectivity / endpoints'
                        }
                        if ($roll -notin @('Synchronized', 'Synchronizing')) {
                            Add-SsaFinding $findings Warning AG "$($ag.Name)/$($rep.Name)" "RollupSynchronizationState=$roll" 'Investigate replica health'
                        }
                    }
                }
            }
        } catch {
            Add-SsaFinding $findings Critical AG ($topo.AgNames -join ',') ([string]$_) 'Fix SQL connectivity (consider -SqlCredential) and re-run'
        }
    }

    Write-SsaBanner 'Validation findings'
    $critCount = Show-SsaFindings -Findings $findings `
        -EmptyMessage 'All checks passed. Services, AD, and AG sync look healthy.'

    $null = Save-SsaStageState -OutputFolder $OutputFolder -Stage '05-validate' -State ([pscustomobject]@{
            CompletedAt   = (Get-Date).ToString('o')
            Mode          = $topo.Mode
            CriticalCount = $critCount
            Findings      = @($findings)
            Services      = @($services | Select-Object ComputerName, ServiceName, ServiceType, State, StartName)
        })

    if ($critCount -gt 0) {
        Write-Warning "$critCount critical validation failure(s)."
        exit 1
    }
} finally {
    Stop-Transcript | Out-Null
}
