function Export-DecomAgConfiguration {
    <#
    Rich AG configuration backup (Approach A):
      - AG_Config_{Ag}.json  structured inventory
      - AG_Config_{Ag}.txt   human-readable
      - AG_Rollback_{Ag}.sql rebuild script with fuller replica options
    Returns $true only when all three artifacts exist and JSON parses.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrimaryInstance,
        [Parameter(Mandatory)][string]$AgName,
        [Parameter(Mandatory)][string]$OutputFolder
    )

    $configDir = Join-Path $OutputFolder 'AgConfig'
    New-Item -Path $configDir -ItemType Directory -Force | Out-Null

    $jsonFile = Join-Path $configDir "AG_Config_${AgName}.json"
    $txtFile  = Join-Path $configDir "AG_Config_${AgName}.txt"
    $sqlFile  = Join-Path $configDir "AG_Rollback_${AgName}.sql"

    $agObj    = Get-DbaAvailabilityGroup -SqlInstance $PrimaryInstance -AvailabilityGroup $AgName
    $replicas = @(Get-DbaAgReplica -SqlInstance $PrimaryInstance -AvailabilityGroup $AgName)
    $agDbs    = @(Get-DbaAgDatabase -SqlInstance $PrimaryInstance -AvailabilityGroup $AgName)
    $listeners = @(Get-DbaAgListener -SqlInstance $PrimaryInstance -AvailabilityGroup $AgName -ErrorAction SilentlyContinue)

    $listenerQuery = @"
SELECT
    l.dns_name,
    l.port,
    l.is_conformant,
    ip.ip_address,
    ip.ip_subnet_mask AS subnet_mask,
    ip.state_desc,
    ip.type_desc
FROM sys.availability_group_listeners l
INNER JOIN sys.availability_group_listener_ip_addresses ip
    ON l.listener_id = ip.listener_id
INNER JOIN sys.availability_groups ag
    ON ag.group_id = l.group_id
WHERE ag.name = @AgName;
"@

    $listenerRows = @(
        Invoke-DbaQuery `
            -SqlInstance $PrimaryInstance `
            -Database master `
            -Query $listenerQuery `
            -SqlParameters @{ AgName = $AgName }
    )

    # Prefer STRING_AGG (SQL 2017+); fall back to FOR XML PATH for older engines.
    $routingQueryModern = @"
SELECT
    ar.replica_server_name,
    ar.secondary_role_allow_connections_desc,
    ar.session_timeout,
    ar.seeding_mode_desc,
    ar.read_only_routing_url,
    (
        SELECT STRING_AGG(ror.routing_replica_server_name, ', ')
        WITHIN GROUP (ORDER BY ror.routing_priority)
        FROM sys.availability_read_only_routing_lists ror
        WHERE ror.replica_id = ar.replica_id
    ) AS read_only_routing_list
FROM sys.availability_replicas ar
INNER JOIN sys.availability_groups ag ON ag.group_id = ar.group_id
WHERE ag.name = @AgName;
"@

    $routingQueryLegacy = @"
SELECT
    ar.replica_server_name,
    ar.secondary_role_allow_connections_desc,
    ar.session_timeout,
    ar.seeding_mode_desc,
    ar.read_only_routing_url,
    STUFF((
        SELECT ', ' + ror.routing_replica_server_name
        FROM sys.availability_read_only_routing_lists ror
        WHERE ror.replica_id = ar.replica_id
        ORDER BY ror.routing_priority
        FOR XML PATH(''), TYPE
    ).value('.', 'nvarchar(max)'), 1, 2, '') AS read_only_routing_list
FROM sys.availability_replicas ar
INNER JOIN sys.availability_groups ag ON ag.group_id = ar.group_id
WHERE ag.name = @AgName;
"@

    $routingRows = @()
    try {
        $routingRows = @(
            Invoke-DbaQuery `
                -SqlInstance $PrimaryInstance `
                -Database master `
                -Query $routingQueryModern `
                -SqlParameters @{ AgName = $AgName }
        )
    }
    catch {
        try {
            $routingRows = @(
                Invoke-DbaQuery `
                    -SqlInstance $PrimaryInstance `
                    -Database master `
                    -Query $routingQueryLegacy `
                    -SqlParameters @{ AgName = $AgName }
            )
        }
        catch {
            Write-Warning "[WARN] Could not capture read-only routing details: $($_.Exception.Message)"
        }
    }

    $replicaConfigs = foreach ($rep in $replicas) {
        $route = $routingRows | Where-Object { $_.replica_server_name -eq $rep.Name } | Select-Object -First 1
        [ordered]@{
            Name                         = $rep.Name
            Role                         = "$($rep.Role)"
            AvailabilityMode             = "$($rep.AvailabilityMode)"
            FailoverMode                 = "$($rep.FailoverMode)"
            EndpointUrl                  = "$($rep.EndpointUrl)"
            BackupPriority               = $rep.BackupPriority
            SessionTimeout               = if ($route) { $route.session_timeout } else { $null }
            SeedingMode                  = if ($route) { "$($route.seeding_mode_desc)" } else { "$($rep.SeedingMode)" }
            SecondaryRoleAllowConnections = if ($route) { "$($route.secondary_role_allow_connections_desc)" } else { $null }
            ReadOnlyRoutingUrl           = if ($route) { "$($route.read_only_routing_url)" } else { $null }
            ReadOnlyRoutingList          = if ($route) { "$($route.read_only_routing_list)" } else { $null }
        }
    }

    $config = [ordered]@{
        AvailabilityGroup = $AgName
        CapturedAt        = (Get-Date -Format o)
        RFCNumber         = $script:DecomRFCNumber
        PrimaryInstance   = $PrimaryInstance
        PrimaryReplica    = "$($agObj.PrimaryReplica)"
        ClusterType       = "$($agObj.ClusterType)"
        BasicAvailabilityGroup = "$($agObj.BasicAvailabilityGroup)"
        Replicas          = @($replicaConfigs)
        Databases         = @(
            $agDbs | ForEach-Object {
                [ordered]@{
                    Name                 = $_.Name
                    SynchronizationState = "$($_.SynchronizationState)"
                    IsSuspended          = $_.IsSuspended
                }
            }
        )
        Listeners         = @(
            $listenerRows | ForEach-Object {
                [ordered]@{
                    DnsName    = $_.dns_name
                    Port       = $_.port
                    IpAddress  = $_.ip_address
                    SubnetMask = $_.subnet_mask
                    State      = $_.state_desc
                    Type       = $_.type_desc
                }
            }
        )
        DbatoolsListeners = @(
            $listeners | ForEach-Object {
                [ordered]@{
                    Name = $_.Name
                    Port = $_.PortNumber
                }
            }
        )
    }

    $config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonFile -Encoding UTF8

    @"
Availability Group : $AgName
Generated          : $(Get-Date)
Primary            : $($agObj.PrimaryReplica)
ClusterType        : $($agObj.ClusterType)

===== REPLICAS =====

$($replicaConfigs | ForEach-Object { $_ | Out-String } | Out-String)

===== DATABASES =====

$($agDbs | Format-Table Name, SynchronizationState, IsSuspended -AutoSize | Out-String)

===== LISTENERS =====

$($listenerRows | Format-Table -AutoSize | Out-String)
"@ | Set-Content -LiteralPath $txtFile -Encoding UTF8

    $sql = New-Object System.Collections.Generic.List[string]
    $sql.Add('/*')
    $sql.Add('AG configuration rebuild script (review before use)')
    $sql.Add("RFC: $($script:DecomRFCNumber)")
    $sql.Add("Generated: $(Get-Date)")
    $sql.Add('NOTE: Endpoints, certificates, permissions, and database data movement are NOT included.')
    $sql.Add('*/')
    $sql.Add('')
    $sql.Add(@"
IF EXISTS (SELECT 1 FROM sys.availability_groups WHERE name = N'$AgName')
BEGIN
    DROP AVAILABILITY GROUP [$AgName];
END
GO
"@)

    $replicaDefinitions = foreach ($rep in $replicaConfigs) {
        $seed = if ($rep.SeedingMode) { ",`r`n    SEEDING_MODE = $($rep.SeedingMode)" } else { '' }
        $session = if ($rep.SessionTimeout) { ",`r`n    SESSION_TIMEOUT = $($rep.SessionTimeout)" } else { '' }
        $secondaryConn = if ($rep.SecondaryRoleAllowConnections) {
            ",`r`n    SECONDARY_ROLE (ALLOW_CONNECTIONS = $($rep.SecondaryRoleAllowConnections))"
        } else { '' }

        @"
N'$($rep.Name)'
WITH (
    ENDPOINT_URL = N'$($rep.EndpointUrl)',
    FAILOVER_MODE = $($rep.FailoverMode),
    AVAILABILITY_MODE = $($rep.AvailabilityMode),
    BACKUP_PRIORITY = $($rep.BackupPriority)$session$seed$secondaryConn
)
"@
    }

    $sql.Add("CREATE AVAILABILITY GROUP [$AgName]")
    $sql.Add('FOR REPLICA ON')
    $sql.Add(($replicaDefinitions -join ",`r`n"))
    $sql.Add('GO')

    foreach ($listener in $listenerRows) {
        $sql.Add(@"

ALTER AVAILABILITY GROUP [$AgName]
ADD LISTENER N'$($listener.dns_name)'
(
    WITH IP
    (
        ('$($listener.ip_address)','$($listener.subnet_mask)')
    ),
    PORT=$($listener.port)
);
GO
"@)
    }

    $sql.Add('')
    $sql.Add('/* Re-add databases after restoring data to every replica:')
    foreach ($db in $agDbs) {
        $sql.Add("ALTER AVAILABILITY GROUP [$AgName] ADD DATABASE [$($db.Name)];")
    }
    $sql.Add('*/')

    $sql | Set-Content -LiteralPath $sqlFile -Encoding UTF8

    # Gate: all artifacts must exist and JSON must parse
    foreach ($f in @($jsonFile, $txtFile, $sqlFile)) {
        if (-not (Test-Path -LiteralPath $f) -or (Get-Item -LiteralPath $f).Length -le 0) {
            Write-Warning "[ERROR] AG config artifact missing/empty: $f"
            return $false
        }
    }

    try {
        Get-Content -LiteralPath $jsonFile -Raw | ConvertFrom-Json | Out-Null
    }
    catch {
        Write-Warning "[ERROR] AG config JSON failed to parse: $jsonFile"
        return $false
    }

    Write-Host '[INFO] AG configuration backup created:'
    Write-Host "       $jsonFile"
    Write-Host "       $txtFile"
    Write-Host "       $sqlFile"
    return $true
}

# Back-compat alias used by older call sites

function Export-DecomAgRollbackPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrimaryInstance,
        [Parameter(Mandatory)][string]$AgName,
        [Parameter(Mandatory)][string]$OutputFolder
    )

    Export-DecomAgConfiguration -PrimaryInstance $PrimaryInstance -AgName $AgName -OutputFolder $OutputFolder
}

