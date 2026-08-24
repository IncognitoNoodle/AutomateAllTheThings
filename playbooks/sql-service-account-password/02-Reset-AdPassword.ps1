<#
.SYNOPSIS
    Stage 02 — Reset AD password, unlock, clear expiration / never-expire, wait for node replication.

.DESCRIPTION
    Resets the domain password for a SQL service account (or waits only if SecOps already
    reset it). Unlocks the account, clears account expiration, sets PasswordNeverExpires
    by default, then validates the password on the management host and on each SQL node
    (WinRM ValidateCredentials) so you do not restart SQL against a stale DC.

.EXAMPLE
    $p = ConvertTo-SecureString 'NewPw!' -AsPlainText -Force
    .\02-Reset-AdPassword.ps1 -Account 'DOMAIN\svcSql' -SecurePassword $p `
        -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1'

.EXAMPLE
    .\02-Reset-AdPassword.ps1 -Account 'DOMAIN\svcSql' -SecurePassword $p `
        -ComputerName 'SQL01','SQL02' -WaitOnly
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding()]
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
    [string]$OutputFolder,

    [bool]$PasswordNeverExpires = $true,
    [switch]$WaitOnly,
    [switch]$RequireNodes,

    # Defaults align with Common\Config.ps1 (override there for env-wide changes)
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
Start-Transcript -Path (Join-Path $OutputFolder "02-ResetAd_$timestamp.log") -NoClobber | Out-Null

try {
    Import-SsaDependencies -InstallModule:$InstallModule -NeedActiveDirectory
    Write-SsaBanner 'Stage 02 — AD password reset / unlock / replication wait'

    $nodes = @(Resolve-SsaNodeList -ComputerName $ComputerName -OutputFolder $OutputFolder `
            -SqlInstance $SqlInstance -AvailabilityGroup $AvailabilityGroup `
            -Credential $Credential -SqlCredential $SqlCredential)

    if (-not $nodes) {
        $msg = 'No SQL nodes resolved. Pass -ComputerName, -SqlInstance, or run stage 01 first.'
        if ($RequireNodes) { throw $msg }
        Write-Warning "$msg Validating on mgmt host only."
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
        Write-Host ("Slow poll every {0}s (avoids lockouts). Do not restart SQL until this passes." -f $NodePollSeconds) -ForegroundColor Yellow
        Wait-AdCredentialReadyOnNode -Account $Account -SecurePassword $SecurePassword `
            -ComputerName $nodes -Credential $Credential `
            -TimeoutSeconds $NodeTimeoutSeconds -PollSeconds $NodePollSeconds
    }

    $after = Get-AdServiceAccountStatus -Account $Account
    Write-Host "`nAD status after:" -ForegroundColor Cyan
    $after | Format-List Account, Enabled, LockedOut, PasswordExpired, PasswordNeverExpires, AccountExpirationDate, PasswordLastSet, BadPwdCount

    $null = Save-SsaStageState -OutputFolder $OutputFolder -Stage '02-ad' -State ([pscustomobject]@{
            Account              = $Account
            SamAccount           = $after.SamAccount
            WaitOnly             = [bool]$WaitOnly
            NodesValidated       = $nodes
            PasswordLastSet      = $after.PasswordLastSet
            PasswordNeverExpires = $after.PasswordNeverExpires
            LockedOut            = $after.LockedOut
            CompletedAt          = (Get-Date).ToString('o')
        })

    Write-Host "`nAD ready. Next: .\03-Apply-ServicePassword.ps1 (Update-DbaServiceAccount -NoRestart)" -ForegroundColor Green
} finally {
    Stop-Transcript | Out-Null
}
