<#
.SYNOPSIS
    Unlock an Active Directory user account.

.EXAMPLE
    .\UnlockAdAccount.ps1 -Account 'DOMAIN\svcSql'

.EXAMPLE
    .\UnlockAdAccount.ps1 -Account 'svcSql' -Server 'ucles.internal'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Account,

    [string]$Server
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw 'ActiveDirectory module is missing. Install RSAT ActiveDirectory tools.'
}
Import-Module ActiveDirectory -ErrorAction Stop

$identity = $Account
if ($Account -match '\\') { $identity = $Account.Split('\')[-1] }
if ($identity -match '@') { $identity = $identity.Split('@')[0] }

$getParams = @{
    Identity   = $identity
    Properties = 'LockedOut', 'Enabled', 'SamAccountName', 'UserPrincipalName'
    ErrorAction = 'Stop'
}
if ($Server) { $getParams.Server = $Server }

$user = Get-ADUser @getParams

Write-Host ("Account:  {0}" -f $user.SamAccountName) -ForegroundColor Cyan
if ($user.UserPrincipalName) {
    Write-Host ("UPN:      {0}" -f $user.UserPrincipalName) -ForegroundColor Cyan
}
Write-Host ("Enabled:  {0}" -f $user.Enabled) -ForegroundColor Cyan
Write-Host ("Locked:   {0}" -f $user.LockedOut) -ForegroundColor Cyan

if (-not $user.LockedOut) {
    Write-Host 'Not locked out - nothing to do.' -ForegroundColor Green
    return
}

$unlockParams = @{ Identity = $user.SamAccountName; ErrorAction = 'Stop' }
if ($Server) { $unlockParams.Server = $Server }

Unlock-ADAccount @unlockParams
Start-Sleep -Seconds 1

$after = Get-ADUser @getParams
if ($after.LockedOut) {
    throw "Unlock-ADAccount ran, but $($after.SamAccountName) is still locked out."
}

Write-Host ("Unlocked: {0}" -f $after.SamAccountName) -ForegroundColor Green
