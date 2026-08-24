# SQL Service Account Password Playbook

Modular, recoverable process for rotating / applying domain passwords on SQL Server service accounts (Engine, Agent, SSRS, SSIS), including Always On Availability Groups.

This replaces the monolithic `scripts/powershell/ApplySqlServiceAccountPassword.ps1` / `RotateSqlServiceAccount.ps1` flow. Each stage is independently re-runnable. If anything breaks, resume from the last successful stage.

See [AUDIT.md](./AUDIT.md) for the design/audit notes.

## Why modular?

Production pain: one big script failed mid-way (AD lag, lockout, WinRM, failover), and recovery was unclear. Stages create **hard checkpoints**:

| Stage | Changes AD? | Restarts SQL? | Failover? | Safe to re-run? |
|------|-------------|---------------|-----------|-----------------|
| 01 Discover | No | No | No | Yes (read-only) |
| 02 AD reset | Yes | No | No | Yes (`-WaitOnly` if SecOps reset) |
| 03 Apply service password | No | No (`-NoRestart`) | No | Yes |
| 04 Restart / failover | No | Yes | Optional | Yes |
| 05 Validate | No | No | No | Yes |

## Recommended senior-DBA tactic (lockout-safe)

1. **Discover** — inventory accounts, service state, SPNs, AG topology. Fix blockers first.
2. **AD reset once** — set password, unlock, never-expire. Wait until the new password validates on the **management host and every SQL node** (slow poll, default 5 minutes).
3. **Apply on all nodes with `-NoRestart`** — update Windows service logon cache everywhere while services keep running.
4. **Restart / failover as a separate stage**
   - Standalone: restart targeted types.
   - AG Engine/Agent: secondary restart → sync → failover → former primary restart. **Failback off by default.**
   - SSRS/SSIS only: restart those types on all nodes; no AG failover.
5. **Validate** — services Running, SPNs present, AG databases Synchronized/Synchronizing, account not locked.

## Folder layout

```
playbooks/sql-service-account-password/
├── README.md
├── AUDIT.md
├── Common/
│   ├── Config.ps1                      # edit OutputFolder here
│   └── SqlServiceAccount.Common.ps1    # dot-sourced helpers (not a .psm1 module)
├── 01-Discover-ServiceAccounts.ps1
├── 02-Reset-AdPassword.ps1
├── 03-Apply-ServicePassword.ps1
├── 04-Restart-Services.ps1
└── 05-Validate-Health.ps1
```

Stages load helpers with:

```powershell
. (Join-Path $PSScriptRoot 'Common\SqlServiceAccount.Common.ps1')
```

## Prerequisites

- Jump box with: **dbatools**, **ActiveDirectory** (RSAT), WinRM to SQL nodes, `setspn.exe`
- Rights: AD reset on the service accounts; local admin on SQL nodes; AG failover rights
- Edit `Common\Config.ps1` → `$script:SsaDefaultOutputFolder` (or pass `-OutputFolder` each run)

## Quick start

```powershell
cd playbooks\sql-service-account-password

# 1) Discover
.\01-Discover-ServiceAccounts.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1'

# 2) AD password (per account)
$p = ConvertTo-SecureString 'NewComplexPw!' -AsPlainText -Force
.\02-Reset-AdPassword.ps1 -Account 'DOMAIN\svcSql' -SecurePassword $p `
  -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' -RequireNodes

# 3) Apply to Windows services (no restart)
.\03-Apply-ServicePassword.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
  -Account 'DOMAIN\svcSql' -SecurePassword $p

# 4) Restart + graceful AG failover (no automatic failback)
.\04-Restart-Services.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
  -Account 'DOMAIN\svcSql' -SecurePassword $p

# Optional later:
# .\04-Restart-Services.ps1 ... -FailbackOnly -OriginalPrimary 'SQL01\INST'

# 5) Validate
.\05-Validate-Health.ps1 -SqlInstance 'SQL01\INST' -AvailabilityGroup 'AG1' `
  -Account 'DOMAIN\svcSql'
```

Stage JSON checkpoints under OutputFolder: `discovery-latest.json`, `02-ad-latest.json`, `03-apply-latest.json`, `04-restart-latest.json`, `05-validate-latest.json`.

## Recovery cheat sheet

| Symptom | Resume at | Action |
|---------|-----------|--------|
| Wrong account / SPN / service Stopped | 01 | Fix manually, re-discover |
| AD reset done, nodes still reject password | 02 | `-WaitOnly`; check DC replication / unlock |
| Service cache not updated | 03 | Re-run apply (`-NoRestart`) |
| Secondary restarted, failover not done | 04 | Re-run 04 |
| Failover done, old primary not restarted | 04 | Re-run 04 |
| Want original primary back | 04 | `-FailbackOnly -OriginalPrimary ...` |
| Everything up, unsure of sync | 05 | Re-run validate |

## SPN check (used in 01 / 05)

```text
setspn -L DOMAIN\AccountSam
```

Example: `setspn -L UCLES\CRTPRDAG02_SQL`

## Relationship to legacy scripts

| Legacy | Status |
|--------|--------|
| `scripts/powershell/ApplySqlServiceAccountPassword.ps1` | Prefer this playbook |
| `scripts/powershell/RotateSqlServiceAccount.ps1` | Prefer stages 02–04 |

## Security notes

- Passwords are not written to transcripts as plain text by design; still protect OutputFolder.
- Do not commit real passwords, transcripts, or discovery dumps with secrets.
