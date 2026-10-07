<#
.SYNOPSIS
    Stage 01 - Discover SQL service accounts, service health, and SPNs (AG-aware).

.DESCRIPTION
    Read-only pre-flight. Identifies domain service accounts for Engine/Agent/SSRS/SSIS
    on the seed instance and, for Availability Groups, on all replicas via dbatools.
    Checks service state, lists SPNs (setspn -L), and prints actionable findings.

    Services do NOT need to be Running. Return-to-service after machines power on with
    expired service-account passwords is a supported path: discover via WinRM/CIM,
    then stage 02/03/04 to reset, apply, and start.

.EXAMPLE
    .\01-Discover-ServiceAccounts.ps1 -SqlInstance 'SQL01\INST'

.EXAMPLE
    # SQL Engine stopped (expired password) - inventory via WinRM on all nodes
    .\01-Discover-ServiceAccounts.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
        -ComputerName 'SQL01','SQL02'

.EXAMPLE
    .\01-Discover-ServiceAccounts.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' -FailOnCritical
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SqlInstance,

    [string[]]$AvailabilityGroup,

    # WinRM nodes when SQL is down / password expired (skip live AG connect)
    [string[]]$ComputerName,

    [string[]]$InstanceName,
    [PSCredential]$Credential,
    [PSCredential]$SqlCredential,

    # Leave blank to use Common\Config.ps1 default
    [string]$OutputFolder,

    [switch]$InstallModule,
    [switch]$ListOnly,
    [switch]$FailOnCritical
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. (Join-Path $here 'Common\SqlServiceAccount.Common.ps1')

$OutputFolder = Resolve-SsaOutputFolder -OutputFolder $OutputFolder
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
Start-Transcript -Path (Join-Path $OutputFolder "01-Discover_$timestamp.log") -NoClobber | Out-Null

try {
    Import-SsaDependencies -InstallModule:$InstallModule -PreferActiveDirectory
    Write-SsaBanner 'Stage 01 - Discover service accounts / health / SPNs'

    $topo = Get-TargetTopology -SqlInstance $SqlInstance -AvailabilityGroup $AvailabilityGroup `
        -ComputerName $ComputerName -OutputFolder $OutputFolder `
        -SqlCredential $SqlCredential -Credential $Credential

    Write-Host "Mode: $($topo.Mode)$(if ($topo.Offline) { ' [OFFLINE - SQL need not be Running]' })" -ForegroundColor Cyan
    if ($topo.AgNames) { Write-Host "AGs: $($topo.AgNames -join ', ')" -ForegroundColor Cyan }
    Write-Host "Original primary: $($topo.OriginalPrimary)" -ForegroundColor Cyan
    if ($topo.OfflineReason) { Write-Host "Offline reason: $($topo.OfflineReason)" -ForegroundColor DarkYellow }
    $topo.Nodes | Format-Table ComputerName, SqlInstance, Role -AutoSize | Out-Host

    $services = @(Get-SqlTargetService -Nodes $topo.Nodes -InstanceName $InstanceName `
            -Credential $Credential -SqlCredential $SqlCredential)
    if (-not $services) {
        throw "No Engine/Agent/SSRS/SSIS services found on: $(($topo.Nodes.ComputerName | Select-Object -Unique) -join ', '). Check WinRM/CIM and -ComputerName."
    }

    Write-Host "`nServices (all nodes):" -ForegroundColor Cyan
    $services |
        Select-Object ComputerName, ServiceName,
            @{ Name = 'ServiceType'; Expression = { [string]$_.ServiceType } },
            @{ Name = 'State'; Expression = { [string]$_.State } },
            StartMode, StartName |
        Sort-Object ComputerName, ServiceType, ServiceName |
        Format-Table -AutoSize |
        Out-Host

    $domainAccounts = @(Get-DomainSqlServiceAccount -Services $services)
    Write-Host "`nDomain AD service accounts:" -ForegroundColor Cyan
    if (-not $domainAccounts) {
        Write-Warning 'No domain AD service accounts found (local/built-in/gMSA only).'
    } else {
        $domainAccounts | Select-Object Account, ServiceTypes, ServiceCount, Computers, Services |
            Format-Table -AutoSize |
            Out-Host
    }

    $spnReports = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $domainAccounts) {
        Write-Host "`nSPNs for $($row.Account)  (setspn -L):" -ForegroundColor Cyan
        $spn = Get-ServiceAccountSpn -Account $row.Account
        [void]$spnReports.Add($spn)
        if ($spn.SpnCount -eq 0) {
            Write-Warning "  No SPNs returned via $($spn.Method)."
            if ($spn.RawOutput) { Write-Host $spn.RawOutput }
        } else {
            $spn.Spns | ForEach-Object { Write-Host "  $_" }
            Write-Host "  MSSQLSvc present: $($spn.HasMssqlSpn) | HTTP present: $($spn.HasHttpSpn) | method=$($spn.Method)" -ForegroundColor DarkCyan
        }
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    $stoppedEngineOrAgent = $false

    foreach ($node in $topo.Nodes) {
        $nodeSvcs = @($services | Where-Object { $_.ComputerName -eq $node.ComputerName })
        foreach ($type in @('Engine', 'Agent')) {
            $match = @($nodeSvcs | Where-Object { [string]$_.ServiceType -eq $type })
            if ($match.Count -eq 0) {
                Add-SsaFinding $findings Warning Service "$($node.ComputerName)\$type" 'Not found on this node' `
                    'Confirm instance name / -InstanceName filter; Engine+Agent should exist on SQL nodes'
                continue
            }
            foreach ($svc in $match) {
                if ([string]$svc.State -ne 'Running') {
                    $stoppedEngineOrAgent = $true
                    # Not Critical: expired password RTS leaves services Stopped on purpose.
                    Add-SsaFinding $findings Info Service "$($svc.ComputerName)\$($svc.ServiceName)" `
                        "State=$($svc.State) StartName=$($svc.StartName)" `
                        'OK for discover/apply while stopped. Stage 02 resets AD, 03 applies password, 04 starts services.'
                }
                $check = Test-IsDomainServiceAccount -StartName $svc.StartName -ForComputer $svc.ComputerName
                if (-not $check.Ok) {
                    Add-SsaFinding $findings Info Account "$($svc.ComputerName)\$($svc.ServiceName)" `
                        "StartName=$($svc.StartName) ($($check.Reason))" `
                        'Skipped for domain password rotation'
                }
            }
        }

        foreach ($type in @('SSRS', 'SSIS')) {
            foreach ($svc in @($nodeSvcs | Where-Object { [string]$_.ServiceType -eq $type })) {
                if ([string]$svc.State -ne 'Running') {
                    Add-SsaFinding $findings Info Service "$($svc.ComputerName)\$($svc.ServiceName)" `
                        "State=$($svc.State) StartName=$($svc.StartName)" `
                        "Optional for RTS. Include in stage 03/04 if $type must come back with Engine/Agent."
                }
            }
        }
    }

    foreach ($row in $domainAccounts) {
        try {
            $ad = Get-AdServiceAccountStatus -Account $row.Account
            if ($ad.Available) {
                if (-not $ad.Enabled) {
                    Add-SsaFinding $findings Critical AD $row.Account 'Account disabled' 'Enable-ADAccount before rotation'
                }
                if ($ad.LockedOut) {
                    Add-SsaFinding $findings Warning AD $row.Account 'Account locked out' 'Stage 02 unlocks; then continue 03/04'
                }
                if ($ad.PasswordExpired) {
                    Add-SsaFinding $findings Warning AD $row.Account 'Password expired' `
                        'Expected return-to-service case. Run stage 02 (reset), then 03 apply, then 04 restart.'
                }
                if ($ad.AccountExpirationDate -and $ad.AccountExpirationDate -le (Get-Date)) {
                    Add-SsaFinding $findings Warning AD $row.Account "Account expired ($($ad.AccountExpirationDate))" `
                        'Stage 02 Clear-ADAccountExpiration; then 03/04'
                }
                if (-not $ad.PasswordNeverExpires) {
                    Add-SsaFinding $findings Warning AD $row.Account 'PasswordNeverExpires=False' 'Stage 02 sets never-expire by default'
                }
            } else {
                Add-SsaFinding $findings Warning AD $row.Account $ad.Message 'Install RSAT ActiveDirectory on mgmt host for AD checks'
            }
        } catch {
            Add-SsaFinding $findings Warning AD $row.Account ([string]$_) 'Verify account exists in AD and you have read rights'
        }
    }

    foreach ($spn in $spnReports) {
        $types = @(($domainAccounts | Where-Object Account -eq $spn.Account).ServiceTypes)
        if (($types -match 'Engine') -and -not $spn.HasMssqlSpn) {
            Add-SsaFinding $findings Warning SPN $spn.Account 'No MSSQLSvc/* SPN found' `
                "Register Kerberos SPNs for SQL (setspn -S MSSQLSvc/host:port $($spn.SamAccount)) or confirm they live on a different account"
        }
        if ($spn.SpnCount -eq 0) {
            Add-SsaFinding $findings Warning SPN $spn.Account 'setspn -L returned no SPNs' "Run manually: setspn -L $($spn.Account)"
        }
    }

    if ($topo.Mode -eq 'AvailabilityGroup' -and $topo.Nodes.Count -lt 2) {
        $sev = if ($topo.Offline) { 'Warning' } else { 'Critical' }
        Add-SsaFinding $findings $sev AG ($topo.AgNames -join ',') 'Fewer than 2 replicas discovered' `
            $(if ($topo.Offline) {
                    'Pass every AG node with -ComputerName so stage 03 updates all service password caches'
                } else {
                    'Fix AG topology discovery / connectivity before stage 04 failover'
                })
    }

    Write-SsaBanner 'Findings / recommended fixes'
    $critCount = [int](Show-SsaFindings -Findings $findings `
            -EmptyMessage 'No issues found. Safe to proceed to stage 02 (AD) or 03 (apply) as planned.')
    if ($critCount -gt 0) {
        Write-Warning "$critCount critical finding(s). Resolve before stage 03/04 (disabled accounts, live AG topology, etc.)."
    } elseif ($stoppedEngineOrAgent -or $topo.Offline) {
        Write-Host "`nReturn-to-service path: services may stay Stopped until password is fixed." -ForegroundColor Yellow
        Write-Host 'Next: stage 02 (AD reset) -> 03 (apply NoRestart) -> 04 (restart / start services).' -ForegroundColor Yellow
    }

    $null = Save-SsaDiscovery -OutputFolder $OutputFolder -Topology $topo -Services $services `
        -DomainAccounts $domainAccounts -Findings $findings -SpnReports $spnReports

    Write-Host "`nNext:" -ForegroundColor Cyan
    Write-Host '  - Critical = hard blockers (e.g. disabled AD account). Warnings/Info are OK to continue.'
    Write-Host '  - Stage 02: .\02-Reset-AdPassword.ps1 -Account DOMAIN\svc ...  (expired/locked - do this first)'
    Write-Host '  - Stage 03: .\03-Apply-ServicePassword.ps1 ...  (works while services are Stopped)'
    Write-Host '  - Stage 04: .\04-Restart-Services.ps1 ...  (starts Engine/Agent after password apply)'
    if ($topo.Offline -and $topo.Mode -eq 'AvailabilityGroup') {
        Write-Host '  - Offline AG: keep using the same -ComputerName list on stages 03/04 until SQL is up.' -ForegroundColor DarkYellow
    }

    if ($ListOnly) {
        $domainAccounts | Select-Object Account, ServiceTypes, ServiceCount, Computers, Services
    } else {
        [pscustomobject]@{
            Mode           = $topo.Mode
            Offline        = [bool]$topo.Offline
            Nodes          = $topo.Nodes
            DomainAccounts = $domainAccounts | Select-Object Account, ServiceTypes, Computers
            Findings       = $findings
            CriticalCount  = $critCount
        }
    }

    if ($FailOnCritical -and $critCount -gt 0) { exit 1 }
} finally {
    Stop-Transcript | Out-Null
}
