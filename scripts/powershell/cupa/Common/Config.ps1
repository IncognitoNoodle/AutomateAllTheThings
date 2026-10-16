# Editable defaults for the CUPA SQL Server decommission playbook.
# Change this once per environment instead of editing every module.

$script:DecomInstanceSuffix    = '\SQL01'
$script:DecomArchiveBasePath   = '\\ucles.internal\DBArchive'
$script:DecomLocalBackupRoot   = 'N:\'
$script:DecomInventoryInstance = 'DBAPRDAG01\SQL01'
$script:DecomLogDir            = 'C:\Temp\DecomLogs'
