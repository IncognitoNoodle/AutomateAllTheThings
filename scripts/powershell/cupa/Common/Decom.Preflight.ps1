# Read-only preflight: hostname <-> ExpectedIP validation, SQL connect on all
# planned nodes, AG sync snapshot, and a written execution plan.

function Invoke-DecomPreflight {
    [CmdletBinding()]
    param()

    Write-Host "`n===== PREFLIGHT =====" -ForegroundColor Cyan

    $hostsToCheck = [System.Collections.Generic.List[string]]::new()

    foreach ($srv in $script:DecomResolvedStandalone) {
        if ($srv -notin $hostsToCheck) { $hostsToCheck.Add($srv) | Out-Null }
    }

    foreach ($agName in @($script:DecomValidAgs.Keys)) {
        $info = $script:DecomValidAgs[$agName]
        foreach ($rep in $info.Replicas) {
            $hostName = (Resolve-DecomSqlInstance -Name $rep).HostName
            if ($hostName -notin $hostsToCheck) { $hostsToCheck.Add($hostName) | Out-Null }
        }
    }

    # --- IP identity validation against decom team inventory ---
    if ($script:DecomSkipIpValidation) {
        Write-Warning '[WARN] Skipping hostname/IP validation (-SkipIpValidation).'
    }
    else {
        Write-Host "`n----- Host identity (DNS vs ExpectedIP) -----" -ForegroundColor Cyan
        foreach ($hostName in $hostsToCheck) {
            $expected = Get-DecomExpectedIp -ServerName $hostName
            $result = Test-DecomHostIpIdentity -ServerName $hostName -ExpectedIP $expected
            $script:DecomIpValidationResults.Add($result) | Out-Null

            switch ($result.Status) {
                'Ok' {
                    Write-Host "[OK] $($result.ServerName) -> $($result.ExpectedIP)" -ForegroundColor Green
                }
                'OkForwardOnly' {
                    Write-Warning "[WARN] $($result.Message)"
                    $script:DecomPreflightWarnings.Add($result.Message) | Out-Null
                }
                'MissingInventory' {
                    $msg = $result.Message
                    if ($script:DecomRequireHostInventory) {
                        Write-Host "[FAIL] $msg" -ForegroundColor Red
                        $script:DecomPreflightHardFailures.Add($msg) | Out-Null
                        $script:DecomHadFailures = $true
                    }
                    else {
                        Write-Warning "[WARN] $msg"
                        $script:DecomPreflightWarnings.Add($msg) | Out-Null
                    }
                }
                default {
                    # Mismatch / DnsFailed
                    if ($script:DecomForceIpMismatch) {
                        Write-Warning "[WARN] $($result.Message) (continuing due to -ForceIpMismatch)"
                        $script:DecomPreflightWarnings.Add($result.Message) | Out-Null
                    }
                    else {
                        Write-Host "[FAIL] $($result.Message)" -ForegroundColor Red
                        $script:DecomPreflightHardFailures.Add($result.Message) | Out-Null
                        $script:DecomHadFailures = $true
                    }
                }
            }
        }
    }

    # --- SQL connectivity on every planned node (hard requirement) ---
    Write-Host "`n----- SQL connectivity -----" -ForegroundColor Cyan
    foreach ($hostName in $hostsToCheck) {
        $sqlInstance = (Resolve-DecomSqlInstance -Name $hostName).SqlInstance
        if (Test-DecomSqlConnection -SqlInstance $sqlInstance) {
            Write-Host "[OK] SQL connect $sqlInstance" -ForegroundColor Green
        }
        else {
            $msg = "SQL connectivity failed for $sqlInstance (host $hostName)"
            $script:DecomPreflightHardFailures.Add($msg) | Out-Null
            $script:DecomHadFailures = $true
        }
    }

    # --- AG health snapshot (warn on non-healthy sync; hard-fail if primary unreachable already caught) ---
    Write-Host "`n----- AG health snapshot -----" -ForegroundColor Cyan
    $agPlan = [ordered]@{}
    foreach ($agName in @($script:DecomValidAgs.Keys)) {
        $info = $script:DecomValidAgs[$agName]
        $primaryInstance = (Resolve-DecomSqlInstance -Name $info.Primary).SqlInstance
        try {
            $dbs = @(Get-DbaAgDatabase -SqlInstance $primaryInstance -AvailabilityGroup $agName)
            $notHealthy = @(
                $dbs | Where-Object {
                    "$($_.SynchronizationState)" -notmatch 'Synchronized|Synchronizing'
                }
            )
            if ($notHealthy.Count -gt 0) {
                $msg = "AG '$agName' has databases not Synchronized/Synchronizing: $($notHealthy.Name -join ', ')"
                Write-Warning "[WARN] $msg"
                $script:DecomPreflightWarnings.Add($msg) | Out-Null
            }
            else {
                Write-Host "[OK] AG '$agName' databases look healthy ($($dbs.Count) DB(s))" -ForegroundColor Green
            }

            $agPlan[$agName] = [ordered]@{
                Primary      = $info.Primary
                Replicas     = @($info.Replicas)
                Databases    = @($dbs.Name)
                NotHealthy   = @($notHealthy.Name)
            }
        }
        catch {
            $msg = "Failed to inspect AG '$agName': $($_.Exception.Message)"
            $script:DecomPreflightHardFailures.Add($msg) | Out-Null
            $script:DecomHadFailures = $true
        }
    }

    # --- Archive path writability hint ---
    if ($script:DecomEffectiveBasePath) {
        try {
            $probe = Join-Path $script:DecomEffectiveBasePath ("_decom_probe_$($script:DecomRFCNumber).tmp")
            'ok' | Set-Content -LiteralPath $probe -ErrorAction Stop
            Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
            Write-Host "[OK] Archive share writable: $($script:DecomEffectiveBasePath)" -ForegroundColor Green
        }
        catch {
            $msg = "Archive share not writable from this host: $($script:DecomEffectiveBasePath) ($($_.Exception.Message))"
            Write-Warning "[WARN] $msg - backups may fall back to N`$ (SQL service account still needs access)."
            $script:DecomPreflightWarnings.Add($msg) | Out-Null
        }
    }

    $plan = [ordered]@{
        RFCNumber            = $script:DecomRFCNumber
        GeneratedAt          = (Get-Date -Format o)
        PlanOnly             = $script:DecomPlanOnly
        Targets              = @($script:DecomTargets)
        Standalone           = @($script:DecomResolvedStandalone)
        AvailabilityGroups   = $agPlan
        Unreachable          = @($script:DecomUnreachableOrUnresolved)
        IpValidation         = @($script:DecomIpValidationResults)
        PreflightHardFailures = @($script:DecomPreflightHardFailures)
        PreflightWarnings    = @($script:DecomPreflightWarnings)
        ExcludeDatabases     = @($script:DecomExcludeDatabases)
        ArchiveBasePath      = $script:DecomEffectiveBasePath
        HostList             = $script:DecomHostListPath
    }

    $plan | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $script:DecomPlanPath -Encoding UTF8

    Write-Host "`n[INFO] Execution plan written: $($script:DecomPlanPath)" -ForegroundColor Cyan

    return [pscustomobject]@{
        Ok       = ($script:DecomPreflightHardFailures.Count -eq 0)
        PlanPath = $script:DecomPlanPath
    }
}
