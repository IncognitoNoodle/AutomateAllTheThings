# Target resolution: classify each input as standalone or Availability Group,
# discover AG replica nodes, prefer SQL connectivity over ICMP.

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

        $resolvedTarget = Resolve-DecomSqlInstance -Name $t
        $hostName       = $resolvedTarget.HostName
        $instance       = $resolvedTarget.SqlInstance

        # Soft ICMP hint only - SQL connect is the hard gate
        if (-not (Test-Connection $hostName -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            Write-Warning "[WARN] '$hostName' did not respond to ping - still attempting SQL connect."
        }

        if (-not (Test-DecomSqlConnection -SqlInstance $instance)) {
            Write-Warning "[WARN] Cannot connect to SQL instance $instance"
            $script:DecomUnreachableOrUnresolved.Add($t) | Out-Null
            continue
        }

        try {
            $ags = @(Get-DbaAvailabilityGroup -SqlInstance $instance -ErrorAction SilentlyContinue)

            if ($ags.Count -gt 0) {
                $selected = $ags

                if ($script:DecomAvailabilityGroupFilter.Count -gt 0) {
                    $selected = @(
                        $ags | Where-Object { $_.Name -in $script:DecomAvailabilityGroupFilter }
                    )
                    if ($selected.Count -eq 0) {
                        Write-Warning "[WARN] '$t' has AG(s) $($ags.Name -join ', ') but none match -AvailabilityGroup filter."
                        $script:DecomUnreachableOrUnresolved.Add($t) | Out-Null
                        continue
                    }
                }
                elseif ($ags.Count -gt 1 -and -not $script:DecomAllAvailabilityGroups) {
                    $msg = "Instance $instance has multiple AGs ($($ags.Name -join ', ')). Pass -AvailabilityGroup <name> or -AllAvailabilityGroups."
                    Write-Warning "[WARN] $msg"
                    $script:DecomPreflightHardFailures.Add($msg) | Out-Null
                    $script:DecomHadFailures = $true
                    $script:DecomUnreachableOrUnresolved.Add($t) | Out-Null
                    continue
                }

                foreach ($ag in $selected) {
                    $agName = $ag.Name
                    if ($script:DecomResolvedAgs.ContainsKey($agName)) {
                        Write-Host "[INFO] '$t' resolves to already-queued AG '$agName' - skipping duplicate."
                        continue
                    }

                    $replicas = @((Get-DbaAgReplica -SqlInstance $instance -AvailabilityGroup $agName).Name)
                    $script:DecomResolvedAgs[$agName] = @{
                        Primary      = $ag.PrimaryReplica
                        Replicas     = $replicas
                        SeedInstance = $instance
                    }
                    Write-Host "[AG] '$t' -> AG '$agName' (primary: $($ag.PrimaryReplica), replicas: $($replicas -join ', '))" -ForegroundColor Green
                }
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

    # Sanity-check every AG replica with SQL connect (not just ping) before touching anything.
    foreach ($agName in @($script:DecomResolvedAgs.Keys)) {
        $info = $script:DecomResolvedAgs[$agName]
        $offline = @()

        foreach ($rep in $info.Replicas) {
            $repResolved = Resolve-DecomSqlInstance -Name $rep
            if (-not (Test-DecomSqlConnection -SqlInstance $repResolved.SqlInstance)) {
                $offline += $rep
            }
        }

        if ($offline.Count -gt 0) {
            Write-Warning "[SKIP] AG '$agName' has unreachable replica SQL instance(s): $($offline -join ', ') - skipping for safety."
            $script:DecomFailedAgs.Add($agName) | Out-Null
            $script:DecomHadFailures = $true
            continue
        }
        $script:DecomValidAgs[$agName] = $info
    }

    Write-Host "`n[INFO] Resolved -> AGs: $($script:DecomValidAgs.Keys -join ', ') | Standalone: $($script:DecomResolvedStandalone -join ', ')"
    if ($script:DecomUnreachableOrUnresolved.Count -gt 0) {
        Write-Warning "[INFO] Unreachable/unresolved entries (excluded): $($script:DecomUnreachableOrUnresolved -join ', ')"
    }

    [pscustomobject]@{
        Standalone  = @($script:DecomResolvedStandalone)
        Ags         = $script:DecomValidAgs
        Unreachable = @($script:DecomUnreachableOrUnresolved)
    }
}
