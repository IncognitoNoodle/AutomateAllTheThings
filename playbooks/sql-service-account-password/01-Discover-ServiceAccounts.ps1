<#
.SYNOPSIS
    Stage 01 — Discover SQL service accounts, service health, and SPNs (AG-aware).

.DESCRIPTION
    Read-only pre-flight. Identifies domain service accounts for Engine/Agent/SSRS/SSIS
    on the seed instance and, for Availability Groups, on all replicas via dbatools.
    Checks service state, lists SPNs (setspn -L), and prints actionable findings.

.EXAMPLE
    .\01-Discover-ServiceAccounts.ps1 -SqlInstance 'SQL01\INST'

.EXAMPLE
    .\01-Discover-ServiceAccounts.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' -FailOnCritical
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SqlInstance,

    [string[]]$AvailabilityGroup,
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
    Write-SsaBanner 'Stage 01 — Discover service accounts / health / SPNs'

    $topo = Get-TargetTopology -SqlInstance $SqlInstance -AvailabilityGroup $AvailabilityGroup `
        -SqlCredential $SqlCredential -Credential $Credential

    Write-Host "Mode: $($topo.Mode)" -ForegroundColor Cyan
    if ($topo.AgNames) { Write-Host "AGs: $($topo.AgNames -join ', ')" -ForegroundColor Cyan }
    Write-Host "Original primary: $($topo.OriginalPrimary)" -ForegroundColor Cyan
    $topo.Nodes | Format-Table ComputerName, SqlInstance, Role -AutoSize

    $services = @(Get-SqlTargetService -Nodes $topo.Nodes -InstanceName $InstanceName `
            -Credential $Credential -SqlCredential $SqlCredential)
    if (-not $services) {
        throw "No Engine/Agent/SSRS/SSIS services found on: $(($topo.Nodes.ComputerName | Select-Object -Unique) -join ', ')"
    }

    Write-Host "`nServices (all nodes):" -ForegroundColor Cyan
    $services | Select-Object ComputerName, ServiceName, ServiceType, State, StartMode, StartName |
        Sort-Object ComputerName, ServiceType, ServiceName |
        Format-Table -AutoSize

    $domainAccounts = @(Get-DomainSqlServiceAccount -Services $services)
    Write-Host "`nDomain AD service accounts:" -ForegroundColor Cyan
    if (-not $domainAccounts) {
        Write-Warning 'No domain AD service accounts found (local/built-in/gMSA only).'
    } else {
        $domainAccounts | Select-Object Account, ServiceTypes, ServiceCount, Computers, Services |
            Format-Table -AutoSize
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
                    Add-SsaFinding $findings Critical Service "$($svc.ComputerName)\$($svc.ServiceName)" `
                        "State=$($svc.State) StartName=$($svc.StartName)" `
                        'Start/fix the service before password rotation; do not proceed to stage 03/04'
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
                    Add-SsaFinding $findings Warning Service "$($svc.ComputerName)\$($svc.ServiceName)" `
                        "State=$($svc.State) StartName=$($svc.StartName)" `
                        "Decide if $type must be Running for this change window; fix or exclude from apply"
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
                    Add-SsaFinding $findings Critical AD $row.Account 'Account locked out' 'Unlock-ADAccount (stage 02 does this)'
                }
                if ($ad.PasswordExpired) {
                    Add-SsaFinding $findings Critical AD $row.Account 'Password expired' 'Reset password (stage 02) and set never-expire'
                }
                if ($ad.AccountExpirationDate -and $ad.AccountExpirationDate -le (Get-Date)) {
                    Add-SsaFinding $findings Critical AD $row.Account "Account expired ($($ad.AccountExpirationDate))" 'Clear-ADAccountExpiration (stage 02)'
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
        Add-SsaFinding $findings Critical AG ($topo.AgNames -join ',') 'Fewer than 2 replicas discovered' `
            'Fix AG topology discovery / connectivity before stage 04 failover'
    }

    Write-SsaBanner 'Findings / recommended fixes'
    $critCount = Show-SsaFindings -Findings $findings `
        -EmptyMessage 'No issues found. Safe to proceed to stage 02 (AD) or 03 (apply) as planned.'
    if ($critCount -gt 0) {
        Write-Warning "$critCount critical finding(s). Resolve before stage 03/04."
    }

    $null = Save-SsaDiscovery -OutputFolder $OutputFolder -Topology $topo -Services $services `
        -DomainAccounts $domainAccounts -Findings $findings -SpnReports $spnReports

    Write-Host "`nNext:" -ForegroundColor Cyan
    Write-Host '  - Fix Critical findings first'
    Write-Host '  - Stage 02: .\02-Reset-AdPassword.ps1 -Account DOMAIN\svc ...  (if you own AD reset)'
    Write-Host '  - Or Stage 03 if SecOps already reset AD: .\03-Apply-ServicePassword.ps1 ...'

    if ($ListOnly) {
        $domainAccounts | Select-Object Account, ServiceTypes, ServiceCount, Computers, Services
    } else {
        [pscustomobject]@{
            Mode           = $topo.Mode
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
