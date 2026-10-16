function Resolve-DecomSqlInstance {
    <#
    Normalizes a target name to a plain host name and a full SQL instance
    connection string. Accepts either a bare "server" (the configured
    instance suffix is appended) or an already-qualified "server\instance"
    name (used as-is).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    if ($Name -match '\\') {
        $hostName    = ($Name -split '\\')[0]
        $sqlInstance = $Name
    }
    else {
        $hostName    = $Name
        $sqlInstance = "$Name$($script:DecomInstanceSuffix)"
    }

    [pscustomobject]@{
        HostName    = $hostName
        SqlInstance = $sqlInstance
    }
}

function Test-DecomSqlConnection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SqlInstance)

    try {
        Connect-DbaInstance -SqlInstance $SqlInstance -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        Write-Warning "[WARN] SQL connect failed for $SqlInstance : $($_.Exception.Message)"
        return $false
    }
}

function Test-DecomExcludedDatabase {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    if ($Name -like '*_Decom_RFC*') { return $true }
    foreach ($ex in $script:DecomExcludeDatabases) {
        if ($Name -eq $ex) { return $true }
    }
    return $false
}

