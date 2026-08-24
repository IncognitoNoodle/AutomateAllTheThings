<#
.SYNOPSIS
    Stage 02 — Reset AD password, unlock, clear expiration / never-expire, wait for node replication.

.DESCRIPTION
    Resets the domain password for a SQL service account (or waits only if SecOps already
    reset it). Unlocks the account, clears account expiration, optionally sets
    PasswordNeverExpires, then validates the password on the management host and on each
    SQL node (WinRM ValidateCredentials) so you do not restart SQL against a stale DC.

.EXAMPLE
    $p = ConvertTo-SecureString 'NewPw!' -AsPlainText -Force
    .\02-Reset-AdPassword.ps1 -Account 'DOMAIN\svcSql' -SecurePassword $p `
        -ComputerName 'SQL01','SQL02'

.EXAMPLE
    # SecOps already reset AD — only wait for replication on nodes
    .\02-Reset-AdPassword.ps1 -Account 'DOMAIN\svcSql' -SecurePassword $p `
        -ComputerName 'SQL01','SQL02' -WaitOnly
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding(DefaultParameterSetName = 'Reset')]
param(
    [Parameter(Mandatory)]
    [string]$Account,

    [Parameter(Mandatory)]
    [securestring]$SecurePassword,

    [string[]]$ComputerName,

    [string]$SqlInstance,

    [string[]]$AvailabilityGroup,

    [PSCredential]$Credential,

    [PSCredential]$SqlCredential,

    [string]$OutputFolder = '\\SERVERNAME\C$\Temp\SqlServiceAccountRotation\',

    # Service accounts should not expire passwords by default (opt out with -PasswordNeverExpires:$false)
    [bool]$PasswordNeverExpires = $true,

    [Parameter(ParameterSetName = 'WaitOnly')]
    [switch]$WaitOnly,

    [ValidateRange(30, 7200)]
    [int]$MgmtTimeoutSeconds = 300,

    [ValidateRange(60, 14400)]
    [int]$NodeTimeoutSeconds = 3600,

    [ValidateRange(30, 900)]
    [int]$NodePollSeconds = 300,

    [switch]$InstallModule
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here 'Common\SqlServiceAccount.Common.psm1') -Force

$OutputFolder = Initialize-SsaOutputFolder -OutputFolder $OutputFolder
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
Start-Transcript -Path (Join-Path $OutputFolder "02-ResetAd_$timestamp.log") -NoClobber | Out-Null

try {
    Import-SsaDependencies -InstallModule:$InstallModule -NeedActiveDirectory
    Write-SsaBanner 'Stage 02 — AD password reset / unlock / replication wait'

    # Resolve nodes: explicit -ComputerName, else discovery JSON, else -SqlInstance topology
    $nodes = @($ComputerName | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $nodes) {
        $disc = Read-SsaDiscovery -OutputFolder $OutputFolder
        if ($disc -and $disc.Nodes) {
            $nodes = @($disc.Nodes.ComputerName | Sort-Object -Unique)
            Write-Host "Using nodes from discovery-latest.json: $($nodes -join ', ')" -ForegroundColor DarkCyan
        }
    }
    if (-not $nodes -and $SqlInstance) {
        $topo = Get-TargetTopology -SqlInstance $SqlInstance -AvailabilityGroup $AvailabilityGroup `
            -SqlCredential $SqlCredential -Credential $Credential
        $nodes = @($topo.Nodes.ComputerName | Sort-Object -Unique)
        Write-Host "Using nodes from topology ($($topo.Mode)): $($nodes -join ', ')" -ForegroundColor DarkCyan
    }
    if (-not $nodes) {
        Write-Warning 'No SQL nodes supplied. Will validate on mgmt host only. Pass -ComputerName or -SqlInstance for per-node replication checks.'
    }

    Write-Host "Account: $Account" -ForegroundColor Cyan
    $before = Get-AdServiceAccountStatus -Account $Account
    $before | Format-List Account, Enabled, LockedOut, PasswordExpired, PasswordNeverExpires, AccountExpirationDate, PasswordLastSet, BadPwdCount

    if (-not $WaitOnly) {
        Write-Host "`nResetting AD password..." -ForegroundColor Cyan
        Reset-DomainAccountPassword -Account $Account -SecurePassword $SecurePassword
        if ($PasswordNeverExpires) {
            Set-AdServiceAccountPasswordPolicy -Account $Account -PasswordNeverExpires
        } else {
            Clear-AdServiceAccountExpiration -Account $Account
            Write-Host '  PasswordNeverExpires left unchanged (caller passed $false).' -ForegroundColor DarkYellow
        }
    } else {
        Write-Host 'WaitOnly: skipping Set-ADAccountPassword (assuming SecOps already reset).' -ForegroundColor Yellow
        Unlock-AdServiceAccount -Account $Account
        Clear-AdServiceAccountExpiration -Account $Account
        if ($PasswordNeverExpires) {
            Set-AdServiceAccountPasswordPolicy -Account $Account -PasswordNeverExpires
        }
    }

    Write-Host "`nWaiting for AD on management host..." -ForegroundColor Cyan
    Wait-AdCredentialReady -Account $Account -SecurePassword $SecurePassword -TimeoutSeconds $MgmtTimeoutSeconds

    if ($nodes.Count -gt 0) {
        Write-Host "`nWaiting for AD replication / acceptance on SQL nodes..." -ForegroundColor Cyan
        Write-Host 'Slow poll by design (avoids lockouts). Do not restart SQL until this passes.' -ForegroundColor Yellow
        Wait-AdCredentialReadyOnNode -Account $Account -SecurePassword $SecurePassword `
            -ComputerName $nodes -Credential $Credential `
            -TimeoutSeconds $NodeTimeoutSeconds -PollSeconds $NodePollSeconds
    }

    $after = Get-AdServiceAccountStatus -Account $Account
    Write-Host "`nAD status after:" -ForegroundColor Cyan
    $after | Format-List Account, Enabled, LockedOut, PasswordExpired, PasswordNeverExpires, AccountExpirationDate, PasswordLastSet, BadPwdCount

    $statusPath = Join-Path $OutputFolder "02-AdReady_$($after.SamAccount)_$timestamp.json"
    [pscustomobject]@{
        Account           = $Account
        WaitOnly          = [bool]$WaitOnly
        NodesValidated    = $nodes
        PasswordLastSet   = $after.PasswordLastSet
        PasswordNeverExpires = $after.PasswordNeverExpires
        LockedOut         = $after.LockedOut
        CompletedAt       = (Get-Date).ToString('o')
    } | ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding UTF8

    Write-Host "`nAD ready. Next: .\03-Apply-ServicePassword.ps1 (Update-DbaServiceAccount -NoRestart)" -ForegroundColor Green
} finally {
    Stop-Transcript | Out-Null
}
