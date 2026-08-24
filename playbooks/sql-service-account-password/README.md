# SQL Service Account Password Playbook

Modular, recoverable process for rotating / applying domain passwords on SQL Server service accounts (Engine, Agent, SSRS, SSIS), including Always On Availability Groups.

This replaces the monolithic `scripts/powershell/ApplySqlServiceAccountPassword.ps1` / `RotateSqlServiceAccount.ps1` flow. Each stage is independently re-runnable. If anything breaks, resume from the last successful stage — do not restart from scratch.

## Why modular?

Production pain: one big script failed mid-way (AD lag, lockout, WinRM, failover), and recovery was unclear. Stages create **hard checkpoints**:

| Stage | Changes AD? | Restarts SQL? | Failover? | Safe to re-run? |
|------|-------------|---------------|-----------|-----------------|
| 01 Discover | No | No | No | Yes (read-only) |
| 02 AD reset | Yes | No | No | Yes (idempotent unlock / never-expire; password reset is intentional) |
| 03 Apply service password | No | No (`-NoRestart`) | No | Yes |
| 04 Restart / failover | No | Yes | Optional | Yes (skips already-running healthy path) |
| 05 Validate | No | No | No | Yes |

## Recommended senior-DBA tactic (lockout-safe)

**Do not** reset AD and immediately restart SQL. Classic lockout: one node authenticates with the **old** password while AD already has the **new** one (or the reverse).

### Order of operations

1. **Discover** — inventory accounts, service state, SPNs, AG topology. Fix blockers first.
2. **AD reset once** — set password, unlock, clear expiration / set never-expire. Then **wait** until the new password validates on the **management host and every SQL node** (site DC replication). Slow poll (minutes, not seconds).
3. **Apply on all nodes with `-NoRestart`** — `Update-DbaServiceAccount` updates the Windows service logon cache everywhere while services keep running under the old logon token.
4. **Restart / failover as a separate stage**
   - **Standalone:** restart Engine/Agent (and SSRS/SSIS if targeted) after AD is ready on that node.
   - **AG (Engine/Agent):** restart **secondary first** → wait AG sync → **failover** → restart former primary → wait sync. **Failback is optional** (`-Failback`); default is leave primary on the node you failed over to (safer during change windows).
   - **SSRS/SSIS only:** restart those types on all nodes; **no AG failover**.
5. **Validate** — services Running, SPNs present, AG databases Synchronized/Synchronizing, no locked account.

### Lockout prevention rules

- Reset AD **once**; never spray wrong passwords from scripts.
- Poll `ValidateCredentials` slowly (default 5 minutes on nodes). Aggressive loops lock accounts.
- Unlock + clear expiration before every auth wait and after any auth failure.
- Never restart until stage 02/03 report AD OK on **all** SQL nodes.
- Update service password on **all** nodes **before** any restart.
- Prefer SQL auth (`-SqlCredential`) for AG discovery/failover during Kerberos/SPN instability.

## Folder layout

```
playbooks/sql-service-account-password/
├── README.md
├── Common/
│   └── SqlServiceAccount.Common.psm1
├── 01-Discover-ServiceAccounts.ps1
├── 02-Reset-AdPassword.ps1
├── 03-Apply-ServicePassword.ps1
├── 04-Restart-Services.ps1
└── 05-Validate-Health.ps1
```

## Prerequisites

- Jump box / mgmt host with: **dbatools**, **ActiveDirectory** (RSAT), WinRM to SQL nodes
- Rights: AD reset on the service accounts; local admin (or equivalent) on SQL nodes for service updates; AG failover rights
- Edit `$script:OutputFolder` in each stage (or pass `-OutputFolder`) to a real share, e.g. `\\FileServer\Share\SqlServiceAccountRotation\`

## Quick start

```powershell
cd playbooks\sql-service-account-password

# 1) Discover (always first)
.\01-Discover-ServiceAccounts.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1'

# 2) AD password (per account)
$p = ConvertTo-SecureString 'NewComplexPw!' -AsPlainText -Force
.\02-Reset-AdPassword.ps1 -Account 'DOMAIN\svcSql' -SecurePassword $p `
  -ComputerName 'SQL01','SQL02'

# 3) Apply to Windows services (no restart)
.\03-Apply-ServicePassword.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
  -Account 'DOMAIN\svcSql' -SecurePassword $p

# 4) Restart + graceful AG failover (no automatic failback)
.\04-Restart-Services.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
  -Account 'DOMAIN\svcSql' -SecurePassword $p

# Optional failback after validation:
# .\04-Restart-Services.ps1 ... -FailbackOnly

# 5) Validate
.\05-Validate-Health.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
  -Account 'DOMAIN\svcSql'
```

Discovery JSON is written under `OutputFolder` and reused by later stages when present.

## Recovery cheat sheet

| Symptom | Resume at | Action |
|---------|-----------|--------|
| Wrong account / SPN / service Stopped | 01 | Fix manually, re-discover |
| AD reset done, nodes still reject password | 02 | Re-run wait only (`-WaitOnly`); check DC replication / unlock |
| Service cache not updated | 03 | Re-run apply (`-NoRestart`) |
| Secondary restarted, failover not done | 04 | Re-run 04 (idempotent enough to continue) |
| Failover done, old primary not restarted | 04 | Re-run 04 |
| Everything up, unsure of sync | 05 | Re-run validate |

## SPN check (used in 01 / 05)

```text
setspn -L DOMAIN\AccountSam
```

Example: `setspn -L UCLES\CRTPRDAG02_SQL`

## Relationship to legacy scripts

| Legacy | Status |
|--------|--------|
| `scripts/powershell/ApplySqlServiceAccountPassword.ps1` | Prefer this playbook; legacy kept for reference |
| `scripts/powershell/RotateSqlServiceAccount.ps1` | Prefer stages 02–04; vault logic not required here |

## Security notes

- Passwords are never written to transcript logs as plain text by design; still protect `OutputFolder`.
- Prefer SecOps-generated passwords; stage 02 can set them when DBA owns AD for these accounts.
- Do not commit real passwords, transcripts, or discovery dumps with secrets.
