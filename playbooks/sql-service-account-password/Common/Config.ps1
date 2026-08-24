# Editable defaults for the SQL service-account password playbook.
# Change this once per environment instead of editing every stage script.

$script:SsaDefaultOutputFolder = '\\SERVERNAME\C$\Temp\SqlServiceAccountRotation\'
$script:SsaServiceTypes = @('Engine', 'Agent', 'SSRS', 'SSIS')

# AD node validation: slow poll avoids lockouts (production lesson).
$script:SsaDefaultNodePollSeconds = 300
$script:SsaDefaultNodeTimeoutSeconds = 3600
$script:SsaDefaultMgmtTimeoutSeconds = 300
