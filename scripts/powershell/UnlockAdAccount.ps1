# Unlock an AD account. Edit the variables, then run the script.

$Account = 'DOMAIN\svcSql'   # DOMAIN\user, SAM, or user@domain.com
$Server  = ''                # optional DC/domain DNS, e.g. 'ucles.internal'

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw 'ActiveDirectory module is missing. Install RSAT ActiveDirectory tools.'
}
Import-Module ActiveDirectory -ErrorAction Stop

$identity = $Account
if ($Account -match '\\') { $identity = $Account.Split('\')[-1] }
if ($identity -match '@') { $identity = $identity.Split('@')[0] }

$get = @{ Identity = $identity; Properties = 'LockedOut', 'Enabled', 'SamAccountName', 'UserPrincipalName' }
if ($Server) { $get.Server = $Server }

$user = Get-ADUser @get
Write-Host "Account: $($user.SamAccountName)"
Write-Host "Enabled: $($user.Enabled)"
Write-Host "Locked:  $($user.LockedOut)"

if (-not $user.LockedOut) {
    Write-Host 'Not locked out - nothing to do.'
    return
}

$unlock = @{ Identity = $user.SamAccountName }
if ($Server) { $unlock.Server = $Server }
Unlock-ADAccount @unlock

$after = Get-ADUser @get
if ($after.LockedOut) { throw "$($after.SamAccountName) is still locked out." }
Write-Host "Unlocked: $($after.SamAccountName)"
