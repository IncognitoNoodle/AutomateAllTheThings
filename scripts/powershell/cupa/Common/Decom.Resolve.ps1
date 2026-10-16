# Target resolution: classify each input as standalone or Availability Group,
# discover AG replica nodes, and skip unreachable / duplicate entries.

function Resolve-DecomTargets {
    [CmdletBinding()]
    param()

    Write-Host "`n===== RESOLVING TARGETS =====" -ForegroundColor Cyan

    foreach ($t in $script:DecomTargets) {

        # Already resolved as part of another entry in this same list
        # (e.g. an AG's listener name AND one of its node names both present)?
        if ($script:DecomResolvedAgs.Keys | Where-Object {
                $script:DecomResolvedAgs[$_].Replicas -contains $t -or $_ -eq $t
            }) {
            Write-Host "[INFO] '$t' already covered by a previously resolved AG - skipping duplicate."
            continue
        }
        if ($t -in $script:DecomResolvedStandalone) { continue }

        if (-not (Test-Connection $t -Count 1 -Quiet)) {
            Write-Warning "[WARN] '$t' is unreachable - skipping."
            $script:DecomUnreachableOrUnresolved.Add($t) | Out-Null
            continue
        }

        try {
            $resolvedTarget = Resolve-DecomSqlInstance -Name $t
            $instance       = $resolvedTarget.SqlInstance

            try {
                Connect-DbaInstance -SqlInstance $instance -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Warning "[WARN] Cannot connect to SQL instance $instance"
                $script:DecomUnreachableOrUnresolved.Add($t) | Out-Null
                continue
            }

            # Determine whether this target is a member of an Availability Group.
            $ag = Get-DbaAvailabilityGroup -SqlInstance $instance -ErrorAction SilentlyContinue |
                Select-Object -First 1

            if ($ag) {
                $agName = $ag.Name
                if ($script:DecomResolvedAgs.ContainsKey($agName)) {
                    Write-Host "[INFO] '$t' resolves to already-queued AG '$agName' - skipping duplicate."
                    continue
                }
                $replicas = (Get-DbaAgReplica -SqlInstance $instance -AvailabilityGroup $agName).Name
                $script:DecomResolvedAgs[$agName] = @{
                    Primary      = $ag.PrimaryReplica
                    Replicas     = $replicas
                    SeedInstance = $instance
                }
                Write-Host "[AG] '$t' -> AG '$agName' (primary: $($ag.PrimaryReplica), replicas: $($replicas -join ', '))" -ForegroundColor Green
            }
            else {
                $script:DecomResolvedStandalone.Add($t) | Out-Null
                Write-Host "[STANDALONE] '$t'" -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "[WARN] Could not resolve '$t' (connection/query failed): $($_.Exception.Message)"
            $script:DecomUnreachableOrUnresolved.Add($t) | Out-Null
        }
    }

    # Sanity-check every AG's replicas are reachable before touching anything.
    foreach ($agName in @($script:DecomResolvedAgs.Keys)) {
        $info = $script:DecomResolvedAgs[$agName]
        $offline = $info.Replicas | Where-Object {
            $serverName = (Resolve-DecomSqlInstance -Name $_).HostName
            -not (Test-Connection $serverName -Count 1 -Quiet)
        }
        if ($offline) {
            Write-Warning "[SKIP] AG '$agName' has unreachable replica(s): $($offline -join ', ') - skipping for safety."
            $script:DecomFailedAgs.Add($agName) | Out-Null
            continue
        }
        $script:DecomValidAgs[$agName] = $info
    }

    Write-Host "`n[INFO] Resolved -> AGs: $($script:DecomValidAgs.Keys -join ', ') | Standalone: $($script:DecomResolvedStandalone -join ', ')"
    if ($script:DecomUnreachableOrUnresolved.Count -gt 0) {
        Write-Warning "[INFO] Unreachable/unresolved entries (excluded): $($script:DecomUnreachableOrUnresolved -join ', ')"
    }

    [pscustomobject]@{
        Standalone = @($script:DecomResolvedStandalone)
        Ags        = $script:DecomValidAgs
        Unreachable = @($script:DecomUnreachableOrUnresolved)
    }
}
