# ApplySqlServiceAccountPassword.ps1

Legacy one-shot script. Prefer the staged playbook:

[`playbooks/sql-service-account-password/`](../../playbooks/sql-service-account-password/README.md)

---

Applies an already-reset domain password to SQL Windows services and restarts once. No AD change, no password generation, no vault.

## Behavior

- Target: `-SqlInstance`, optional `-AvailabilityGroup`
- Domain service accounts only (Engine, Agent, SSRS, SSIS)
- `-ListAccounts` to list accounts
- `-Account` + `-SecurePassword` (same count/order)
- `Update-DbaServiceAccount -NoRestart`, wait for AD on jump box + SQL nodes, then restart
- Standalone: restart updated types  
  AG: secondary restart → failover → former primary restart → failback

Needs WinRM to each SQL node (prefer Kerberos).

## Examples

```powershell
.\ApplySqlServiceAccountPassword.ps1 -SqlInstance 'HOST\SQL01' -ListAccounts

$p1 = ConvertTo-SecureString 'PwForSql' -AsPlainText -Force
$p2 = ConvertTo-SecureString 'PwForSsrs' -AsPlainText -Force
.\ApplySqlServiceAccountPassword.ps1 -SqlInstance 'HOST\SQL01' `
  -Account 'DOMAIN\svcSql','DOMAIN\svcSsrs' -SecurePassword $p1,$p2

.\ApplySqlServiceAccountPassword.ps1 -SqlInstance 'HOST\SQL01' `
  -AvailabilityGroup 'AgName' -Account 'DOMAIN\svcSql' -SecurePassword $p1
```

## Config

In the script:

```powershell
$script:OutputFolder = '\\SERVERNAME\C$\Temp\'
```
