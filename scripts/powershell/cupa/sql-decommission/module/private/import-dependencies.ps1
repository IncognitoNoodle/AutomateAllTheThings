function Import-DecomDependencies {
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name dbatools)) {
        Install-Module dbatools -Scope CurrentUser -Force
    }
    Import-Module dbatools

    Set-DbatoolsConfig sql.connection.encrypt $true
    Set-DbatoolsConfig sql.connection.trustcert $true
}

