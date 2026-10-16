function Import-DecomHostListRows {
    <#
    Reads a decom host list from .csv or .xlsx.
    Required columns (aliases accepted):
      ServerName | Hostname | Server | Name
      ExpectedIP | IP | IPAddress | IpAddress
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Host list file not found: $Path"
    }

    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    switch ($ext) {
        '.csv' {
            return @(Import-Csv -LiteralPath $Path)
        }
        '.xlsx' {
            if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
                throw @"
Excel host list '$Path' requires the ImportExcel module.
Install with: Install-Module ImportExcel -Scope CurrentUser
Or save the sheet as CSV (columns ServerName, ExpectedIP) and pass that path to -HostList.
"@
            }
            Import-Module ImportExcel -ErrorAction Stop
            return @(Import-Excel -Path $Path)
        }
        '.xls' {
            throw "Unsupported .xls format. Save as .xlsx or .csv and pass that path to -HostList."
        }
        default {
            throw "Unsupported host list extension '$ext'. Use .csv or .xlsx."
        }
    }
}

function Get-DecomRowProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Row,
        [Parameter(Mandatory)][string[]]$Names
    )

    foreach ($name in $Names) {
        $prop = $Row.PSObject.Properties |
            Where-Object { $_.Name -eq $name -or $_.Name -ieq $name } |
            Select-Object -First 1
        if ($prop -and "$($prop.Value)".Trim()) {
            return "$($prop.Value)".Trim()
        }
    }
    return $null
}

function Import-DecomHostInventory {
    [CmdletBinding()]
    param()

    $script:DecomHostInventory = @{}

    $rows = Import-DecomHostListRows -Path $script:DecomHostListPath
    foreach ($row in $rows) {
        $name = Get-DecomRowProperty -Row $row -Names @('ServerName', 'Hostname', 'Server', 'Name')
        $ip   = Get-DecomRowProperty -Row $row -Names @('ExpectedIP', 'IPAddress', 'IpAddress', 'IP')
        if (-not $name -or -not $ip) { continue }
        $script:DecomHostInventory[$name.ToLowerInvariant()] = [pscustomobject]@{
            ServerName = $name
            ExpectedIP = $ip
        }
    }

    if ($script:DecomHostInventory.Count -eq 0) {
        throw "Host list is empty or missing ServerName/ExpectedIP columns: $($script:DecomHostListPath)"
    }

    Write-Host "[INFO] Loaded $($script:DecomHostInventory.Count) hosts from $($script:DecomHostListPath)"
}

function Get-DecomExpectedIp {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ServerName)

    $key = $ServerName.ToLowerInvariant()
    if ($script:DecomHostInventory.ContainsKey($key)) {
        return $script:DecomHostInventory[$key].ExpectedIP
    }

    # Bidirectional short/FQDN match:
    # - inventory short + lookup FQDN
    # - inventory FQDN + lookup short / different FQDN same host
    $short = ($ServerName -split '\.')[0].ToLowerInvariant()
    if ($script:DecomHostInventory.ContainsKey($short)) {
        return $script:DecomHostInventory[$short].ExpectedIP
    }

    foreach ($entry in $script:DecomHostInventory.GetEnumerator()) {
        $invShort = ($entry.Value.ServerName -split '\.')[0].ToLowerInvariant()
        if ($invShort -eq $short) {
            return $entry.Value.ExpectedIP
        }
    }

    return $null
}

function Test-DecomHostIpIdentity {
    <#
    Resolves ServerName via DNS and compares to ExpectedIP from the decom team inventory.
    Also attempts reverse lookup of the expected IP.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ServerName,
        [string]$ExpectedIP
    )

    $result = [ordered]@{
        ServerName     = $ServerName
        ExpectedIP     = $ExpectedIP
        ResolvedIPs    = @()
        ReverseNames   = @()
        ForwardMatch   = $false
        ReverseMatch   = $false
        InInventory    = [bool]$ExpectedIP
        Status         = 'Unknown'
        Message        = ''
    }

    if (-not $ExpectedIP) {
        $result.Status  = 'MissingInventory'
        $result.Message = "No ExpectedIP in host inventory for '$ServerName'"
        return [pscustomobject]$result
    }

    try {
        $entry = [System.Net.Dns]::GetHostEntry($ServerName)
        $result.ResolvedIPs = @(
            $entry.AddressList |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                ForEach-Object { $_.IPAddressToString }
        )
    }
    catch {
        $result.Status  = 'DnsFailed'
        $result.Message = "DNS forward lookup failed for '$ServerName': $($_.Exception.Message)"
        return [pscustomobject]$result
    }

    $result.ForwardMatch = ($ExpectedIP -in $result.ResolvedIPs)

    try {
        $rev = [System.Net.Dns]::GetHostEntry($ExpectedIP)
        $names = @($rev.HostName) + @($rev.Aliases)
        $result.ReverseNames = @($names | Where-Object { $_ } | Select-Object -Unique)
        $short = ($ServerName -split '\.')[0]
        $result.ReverseMatch = [bool](
            $result.ReverseNames | Where-Object {
                $_ -eq $ServerName -or
                $_ -like "$ServerName.*" -or
                $_ -eq $short -or
                $_ -like "$short.*"
            }
        )
    }
    catch {
        $result.ReverseNames = @()
        $result.ReverseMatch = $false
    }

    if ($result.ForwardMatch) {
        $result.Status = if ($result.ReverseMatch) { 'Ok' } else { 'OkForwardOnly' }
        $result.Message = "Forward DNS for '$ServerName' includes ExpectedIP $ExpectedIP"
        if (-not $result.ReverseMatch) {
            $result.Message += ' (reverse lookup did not confirm hostname)'
        }
    }
    else {
        $result.Status  = 'Mismatch'
        $resolved = if ($result.ResolvedIPs) { $result.ResolvedIPs -join ', ' } else { '(none)' }
        $result.Message = "IP mismatch for '$ServerName': expected $ExpectedIP, DNS has $resolved"
    }

    return [pscustomobject]$result
}

