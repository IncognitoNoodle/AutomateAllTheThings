function Write-DecomSummary {
    [CmdletBinding()]
    param()

    Write-Host "`n===== SUMMARY =====" -ForegroundColor Cyan
    Write-Host "RFC                  : $($script:DecomRFCNumber)"
    Write-Host "Host list file       : $($script:DecomHostListPath)"
    Write-Host "Hosts from file      : $($script:DecomTargets -join ', ')"
    Write-Host "PlanOnly             : $($script:DecomPlanOnly)"
    Write-Host 'Unreachable/unresolved:'
    if ($script:DecomUnreachableOrUnresolved.Count -gt 0) {
        $script:DecomUnreachableOrUnresolved | ForEach-Object { Write-Host "  - $_" }
    }
    else {
        Write-Host '  (none)'
    }

    Write-Host 'IP validation:'
    if ($script:DecomIpValidationResults.Count -eq 0) {
        Write-Host '  (not run / skipped)'
    }
    else {
        foreach ($r in $script:DecomIpValidationResults) {
            $color = switch ($r.Status) {
                'Ok'             { 'Green' }
                'OkForwardOnly'  { 'Yellow' }
                default          { 'Red' }
            }
            Write-Host "  [$($r.Status)] $($r.ServerName) expected=$($r.ExpectedIP) dns=$($r.ResolvedIPs -join '|')" -ForegroundColor $color
        }
    }

    if ($script:DecomPreflightHardFailures.Count -gt 0) {
        Write-Host 'Preflight hard failures:' -ForegroundColor Red
        $script:DecomPreflightHardFailures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    }

    Write-Host "Standalone processed : $($script:DecomProcessedServers.Count)"
    if ($script:DecomFailedServers.Count -gt 0) {
        Write-Host 'Standalone failed     :'
        $script:DecomFailedServers | ForEach-Object { Write-Host "  - $_" }
    }
    Write-Host "AG databases removed : $($script:DecomProcessedAgs.Count) ($($script:DecomProcessedAgs -join ', '))"
    if ($script:DecomFailedAgs.Count -gt 0) {
        Write-Host 'AGs failed / skipped  :'
        $script:DecomFailedAgs | ForEach-Object { Write-Host "  - $_" }
    }

    $anyRenameFailures = $script:DecomRenameFailures.GetEnumerator() | Where-Object { $_.Value.Count -gt 0 }
    if ($anyRenameFailures) {
        Write-Host "`nDatabases that failed (require manual follow-up):" -ForegroundColor Yellow
        foreach ($entry in $anyRenameFailures) {
            Write-Host "  $($entry.Key): $($entry.Value -join ', ')"
        }
    }

    $summary = [ordered]@{
        RFCNumber            = $script:DecomRFCNumber
        PlanOnly             = $script:DecomPlanOnly
        HadFailures          = [bool]$script:DecomHadFailures
        Unreachable          = @($script:DecomUnreachableOrUnresolved)
        IpValidation         = @($script:DecomIpValidationResults)
        PreflightHardFailures = @($script:DecomPreflightHardFailures)
        ProcessedServers     = @($script:DecomProcessedServers)
        FailedServers        = @($script:DecomFailedServers)
        ProcessedAgs         = @($script:DecomProcessedAgs)
        FailedAgs            = @($script:DecomFailedAgs)
        RenameFailures       = $script:DecomRenameFailures
        PlanPath             = $script:DecomPlanPath
        ManifestPath         = $script:DecomManifestPath
        TranscriptPath       = $script:DecomTranscriptPath
        FinishedAt           = (Get-Date -Format o)
    }

    $summary | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $script:DecomSummaryPath -Encoding UTF8

    Write-Host "`nPlan      : $($script:DecomPlanPath)"
    Write-Host "Manifest  : $($script:DecomManifestPath)"
    Write-Host "Summary   : $($script:DecomSummaryPath)"
    Write-Host "Transcript: $($script:DecomTranscriptPath)"
}

