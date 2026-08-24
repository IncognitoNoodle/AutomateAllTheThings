# SQL service account password

Scripts to change domain passwords for SQL Engine, Agent, SSRS, and SSIS (standalone or Always On).

Run stages in order. If a stage fails, fix the issue and re-run that stage.

| Stage | Script | What it does |
|------|--------|--------------|
| 01 | `01-Discover-ServiceAccounts.ps1` | List services/accounts/SPNs, flag problems |
| 02 | `02-Reset-AdPassword.ps1` | Reset AD password, unlock, never-expire, wait for node replication |
| 03 | `03-Apply-ServicePassword.ps1` | `Update-DbaServiceAccount -NoRestart` on all nodes |
| 04 | `04-Restart-Services.ps1` | Restart services; AG failover if Engine/Agent |
| 05 | `05-Validate-Health.ps1` | Confirm services, AD, SPNs, AG sync |

Shared code: `Common/SqlServiceAccount.Common.ps1` (dot-sourced).  
Defaults: `Common/Config.ps1`.

## Requirements

- Windows jump box with **dbatools**, **ActiveDirectory** (RSAT), WinRM to SQL nodes, `setspn.exe`
- Rights to reset the AD account, update SQL services, and (for AG) failover
- Set the log path in `Common/Config.ps1`:

```powershell
$script:SsaDefaultOutputFolder = '\\FileServer\Share\SqlServiceAccountRotation\'
```

Or pass `-OutputFolder` on each run.

## Order of operations

1. Discover and clear Critical findings.
2. Reset AD **once**, then wait until the password works on the jump box **and every SQL node** (default poll 5 minutes — avoids lockouts).
3. Update the service password on **all** nodes with `-NoRestart` (services keep running).
4. Restart:
   - Standalone: restart the service types you changed.
   - AG + Engine/Agent: restart secondary → wait sync → failover → restart old primary. Failback is off unless you ask for it.
   - SSRS/SSIS only: restart those on all nodes (no failover).
5. Validate.

Do not restart SQL until stage 02/03 report the new password is accepted on the nodes.

## Examples

```powershell
cd playbooks\sql-service-account-password
$p = ConvertTo-SecureString 'NewComplexPw!' -AsPlainText -Force

# 1 — inventory
.\01-Discover-ServiceAccounts.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1'

# 2 — AD (skip reset if SecOps already did it: add -WaitOnly)
.\02-Reset-AdPassword.ps1 -Account 'DOMAIN\svcSql' -SecurePassword $p `
  -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' -RequireNodes

# 3 — service logon cache only
.\03-Apply-ServicePassword.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
  -Account 'DOMAIN\svcSql' -SecurePassword $p

# 4 — restart / failover
.\04-Restart-Services.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
  -Account 'DOMAIN\svcSql' -SecurePassword $p

# optional failback later
# .\04-Restart-Services.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
#   -FailbackOnly -OriginalPrimary 'SQL01\INST'

# 5 — check
.\05-Validate-Health.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
  -Account 'DOMAIN\svcSql'
```

Multiple accounts: pass matching arrays to `-Account` and `-SecurePassword`.

Optional SQL auth for AG work (when Kerberos is flaky):

```powershell
$sql = Get-Credential -Message 'SQL login'
.\01-Discover-ServiceAccounts.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' -SqlCredential $sql
```

## Stage reference

### 01 Discover
- Reads Engine/Agent/SSRS/SSIS on all AG replicas (or the single instance).
- Prints domain accounts, service state, `setspn -L` output.
- Writes `discovery-latest.json`.
- `-FailOnCritical` exits 1 if Critical findings exist.
- `-ListOnly` prints account table only.

### 02 Reset AD
- `Set-ADAccountPassword`, unlock, clear expiration, `PasswordNeverExpires` (default `$true`).
- Waits on jump box + SQL nodes via `ValidateCredentials`.
- `-WaitOnly` — only unlock/wait (password already set).
- `-RequireNodes` — fail if no SQL nodes resolved.
- `-ComputerName` optional; otherwise uses discovery JSON or `-SqlInstance` topology.
- Writes `02-ad-latest.json`.

### 03 Apply (NoRestart)
- Updates Windows service passwords on every node; does not restart.
- Re-checks AD on those nodes before success.
- Writes `03-apply-latest.json` (includes `TypesTouched` for stage 04).

### 04 Restart
- Uses types from `03-apply-latest.json` when present, else from `-Account` / `-Type`.
- Pre-restart AD check (slow poll).
- AG Engine/Agent path as above; `-Failback` to fail back in the same run.
- `-FailbackOnly` + `-OriginalPrimary` (or last restart/discovery JSON) to fail back later.
- Writes `04-restart-latest.json`.

### 05 Validate
- Services Running, AD not locked/expired, SPNs present, AG DBs Synchronized or Synchronizing.
- Exit 1 on Critical findings.
- Writes `05-validate-latest.json`.

## If something fails

| Problem | Re-run |
|---------|--------|
| Bad inventory / SPN / service stopped | `01` |
| Nodes still reject new password | `02 -WaitOnly` |
| Service password not updated | `03` |
| Restart or failover incomplete | `04` |
| Need original AG primary back | `04 -FailbackOnly -OriginalPrimary '...'` |
| Sync / health unsure | `05` |

Transcripts and `*-latest.json` files are under the OutputFolder.

## SPNs

```text
setspn -L DOMAIN\AccountSam
```

## Notes

- Domain accounts only (skips LocalSystem, NT SERVICE, local users, gMSA).
- Protect the OutputFolder share; don’t commit passwords or transcripts.
- Older one-shot scripts: `scripts/powershell/ApplySqlServiceAccountPassword.ps1`, `RotateSqlServiceAccount.ps1`.
