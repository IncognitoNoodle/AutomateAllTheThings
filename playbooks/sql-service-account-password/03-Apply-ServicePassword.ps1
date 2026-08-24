<#
.SYNOPSIS
    Stage 03 — Apply SecOps/AD password to Windows SQL services (NoRestart).

.DESCRIPTION
    Updates the service logon password cache on all topology nodes via
    Update-DbaServiceAccount -NoRestart. Does NOT restart services and does NOT
    failover. Re-validates AD on affected nodes before success. Re-run safely if interrupted.

.EXAMPLE
    $p = ConvertTo-SecureString 'NewPw!' -AsPlainText -Force
    .\03-Apply-ServicePassword.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
        -Account 'DOMAIN\svcSql' -SecurePassword $p
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SqlInstance,

    [string[]]$AvailabilityGroup,
    [string[]]$InstanceName,

    [Parameter(Mandatory)]
    [string[]]$Account,

    [Parameter(Mandatory)]
    [SecureString[]]$SecurePassword,

    [PSCredential]$Credential,
    [PSCredential]$SqlCredential,
    [string]$OutputFolder,

    [ValidateRange(30, 7200)]
    [int]$MgmtTimeoutSeconds = 300,

    [ValidateRange(60, 14400)]
    [int]$NodeTimeoutSeconds = 3600,

    [ValidateRange(30, 900)]
    [int]$NodePollSeconds = 300,

    [switch]$InstallModule
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. (Join-Path $here 'Common\SqlServiceAccount.Common.ps1')

$OutputFolder = Resolve-SsaOutputFolder -OutputFolder $OutputFolder
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$passwordMap = Resolve-AccountPasswordMap -Account $Account -SecurePassword $SecurePassword

Start-Transcript -Path (Join-Path $OutputFolder "03-Apply_$timestamp.log") -NoClobber | Out-Null

try {
    Import-SsaDependencies -InstallModule:$InstallModule -PreferActiveDirectory
    Write-SsaBanner 'Stage 03 — Apply service password (NoRestart)'

    $topo = Get-TargetTopology -SqlInstance $SqlInstance -AvailabilityGroup $AvailabilityGroup `
        -SqlCredential $SqlCredential -Credential $Credential
    Write-Host "Mode: $($topo.Mode)" -ForegroundColor Cyan
    $topo.Nodes | Format-Table ComputerName, SqlInstance, Role -AutoSize

    $services = @(Get-SqlTargetService -Nodes $topo.Nodes -InstanceName $InstanceName `
            -Credential $Credential -SqlCredential $SqlCredential)
    $domainAccounts = @(Get-DomainSqlServiceAccount -Services $services)
    if (-not $domainAccounts) { throw 'No domain AD service accounts found on this topology.' }

    $targets = @(
        foreach ($row in $domainAccounts) {
            if ($passwordMap.ContainsKey($row.Account)) { $row }
            else { Write-Host "Skip $($row.Account): no password supplied" -ForegroundColor Yellow }
        }
    )
    foreach ($name in @($passwordMap.Keys)) {
        if (-not ($domainAccounts | Where-Object Account -eq $name)) {
            Write-Warning "Password supplied for '$name' but that account was not found on this topology."
        }
    }
    if (-not $targets) {
        throw 'No matching accounts to update. Run 01-Discover first, then pass matching -Account/-SecurePassword.'
    }

    Write-Host "`nUpdating service logon cache on ALL nodes before any restart (lockout-safe)." -ForegroundColor Yellow
    $anyFailures = $false
    $updated = [System.Collections.Generic.List[string]]::new()

    foreach ($row in $targets) {
        $acct = $row.Account
        $securePwd = $passwordMap[$acct]
        Write-Host "`nApplying (NoRestart): $acct" -ForegroundColor Green
        $ok = $true

        Unlock-AdServiceAccount -Account $acct

        foreach ($computer in @($row.Group.ComputerName | Select-Object -Unique)) {
            if (-not $ok) { break }
            $nodeServices = @($row.Group | Where-Object ComputerName -eq $computer)
            $svcCred = Get-RemoteCredential -Computer $computer -Credential $Credential
            try {
                Write-Host "  Update-DbaServiceAccount -NoRestart @ $computer ($(($nodeServices.ServiceName) -join ', '))" -ForegroundColor DarkCyan
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
            try {
                $accountNodes = @($row.Group.ComputerName | Sort-Object -Unique)
                Wait-AdCredentialReady -Account $acct -SecurePassword $securePwd -TimeoutSeconds $MgmtTimeoutSeconds
                Wait-AdCredentialReadyOnNode -Account $acct -SecurePassword $securePwd `
                    -ComputerName $accountNodes -Credential $Credential `
                    -TimeoutSeconds $NodeTimeoutSeconds -PollSeconds $NodePollSeconds
                $updated.Add($acct)
                Write-Host '  Service password updated; AD ready on SQL nodes (services still running — not restarted).' -ForegroundColor Green
            } catch {
                Write-Host "  FAILED (AD wait): $_" -ForegroundColor Red
                $ok = $false; $anyFailures = $true
            }
        }
    }

    $typesTouched = @(
        $targets | ForEach-Object { $_.Group } | ForEach-Object { [string]$_.ServiceType } | Sort-Object -Unique
    )

    $null = Save-SsaStageState -OutputFolder $OutputFolder -Stage '03-apply' -State ([pscustomobject]@{
            CompletedAt     = (Get-Date).ToString('o')
            Mode            = $topo.Mode
            UpdatedAccounts = @($updated)
            Failed          = $anyFailures
            Nodes           = @($topo.Nodes | Select-Object ComputerName, SqlInstance, Role)
            AgNames         = @($topo.AgNames)
            OriginalPrimary = $topo.OriginalPrimary
            TypesTouched    = $typesTouched
        })

    if ($updated.Count) {
        Write-Host "`nUpdated account(s): $($updated -join ', ')" -ForegroundColor Green
    }
    if ($anyFailures) {
        Write-Warning 'One or more updates failed. Fix, then re-run stage 03. Do not run stage 04 yet.'
        exit 1
    }

    Write-Host "`nNext: .\04-Restart-Services.ps1 (restart + optional AG failover — separate on purpose)" -ForegroundColor Cyan
} finally {
    Stop-Transcript | Out-Null
}
