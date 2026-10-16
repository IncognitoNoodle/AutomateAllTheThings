# Editable defaults for the CUPA SQL Server decommission playbook.
# Change this once per environment instead of editing every module.

$script:DecomInstanceSuffix    = '\SQL01'
$script:DecomArchiveBasePath   = '\\ucles.internal\DBArchive'
$script:DecomLocalBackupRoot   = 'N:\'
$script:DecomInventoryInstance = 'DBAPRDAG01\SQL01'
$script:DecomLogDir            = 'C:\Temp\DecomLogs'

# Host inventory used for hostname <-> ExpectedIP validation (decom team list).
$script:DecomHostsFile         = Join-Path $PSScriptRoot 'DecomHosts.csv'

# User databases never touched by backup/rename (in addition to system DBs).
$script:DecomExcludeDatabases  = @(
    'SSISDB',
    'distribution',
    'ReportServer',
    'ReportServerTempDB'
)

# AG remove-membership poll
$script:DecomAgRemovePollSeconds = 2
$script:DecomAgRemovePollAttempts = 30
