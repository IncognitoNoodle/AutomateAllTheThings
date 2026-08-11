# ApplySqlServiceAccountPassword.ps1

SecOps already reset the domain password. This script updates SQL Windows services and restarts once. **No AD change. No password generation.**

## What it does

- Targets via `-SqlInstance` (same as the rotator); optional `-AvailabilityGroup`
- Finds **domain AD service accounts** only (skips local / built-in / gMSA)
- Service types: Engine, Agent, SSRS, SSIS
- `-ListAccounts` — show those service accounts
- `-Account` + `-SecurePassword` — one or many pairs (same count/order)
- Updates all supplied service logon caches (`Update-DbaServiceAccount -NoRestart`)
- Saves passwords to the shared vault
- Restarts **once**:
  - Standalone → restart updated service types
  - AG → secondary restart → failover → former primary restart → failback

## Examples

**List**
```powershell
.\ApplySqlServiceAccountPassword.ps1 -SqlInstance 'HOST\SQL01' -ListAccounts
```

**Standalone**
```powershell
$p1 = ConvertTo-SecureString 'PwForSql' -AsPlainText -Force
$p2 = ConvertTo-SecureString 'PwForSsrs' -AsPlainText -Force
.\ApplySqlServiceAccountPassword.ps1 -SqlInstance 'HOST\SQL01' `
  -Account 'DOMAIN\svcSql','DOMAIN\svcSsrs' -SecurePassword $p1,$p2
```

**Availability Group**
```powershell
$p1 = ConvertTo-SecureString 'PwForSql' -AsPlainText -Force
.\ApplySqlServiceAccountPassword.ps1 -SqlInstance 'HOST\SQL01' `
  -AvailabilityGroup 'AgName' -Account 'DOMAIN\svcSql' -SecurePassword $p1
```

## Config

Edit in script:

```powershell
$script:OutputFolder = '\\SERVERNAME\C$\Temp\'
```

Vault + history + transcript land there (same vault as `RotateSqlServiceAccount.ps1`).
