function Initialize-DecomSession {
    <#
    Sets run-scoped state used by resolve / preflight / standalone / AG / inventory modules.

    Hosts are loaded entirely from -HostList (CSV or XLSX). There is no separate -Targets list.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RFCNumber,

        [Parameter(Mandatory)]
        [string]$HostList,

        [string[]]$AvailabilityGroup,
        [switch]$AllAvailabilityGroups,
        [string[]]$ExcludeDatabase,
        [switch]$PlanOnly,
        [switch]$SkipIpValidation,
        [switch]$RequireHostInventory,
        [switch]$ForceIpMismatch
    )

    $script:DecomRFCNumber               = $RFCNumber
    $script:DecomHostListPath            = $HostList
    $script:DecomAvailabilityGroupFilter = @($AvailabilityGroup | Where-Object { $_ })
    $script:DecomAllAvailabilityGroups   = [bool]$AllAvailabilityGroups
    $script:DecomPlanOnly                = [bool]$PlanOnly
    $script:DecomSkipIpValidation        = [bool]$SkipIpValidation
    $script:DecomRequireHostInventory    = [bool]$RequireHostInventory
    $script:DecomForceIpMismatch         = [bool]$ForceIpMismatch

    $script:DecomExcludeDatabases = @(
        $script:DecomExcludeDatabases + @($ExcludeDatabase | Where-Object { $_ }) |
            Select-Object -Unique
    )

    if (Test-Path $script:DecomArchiveBasePath) {
        $script:DecomEffectiveBasePath = $script:DecomArchiveBasePath
        Write-Host "[INFO] Using archive share: $($script:DecomArchiveBasePath)" -ForegroundColor Green
    }
    else {
        $script:DecomEffectiveBasePath = $null
        Write-Warning "[WARN] Archive share unavailable: $($script:DecomArchiveBasePath)"
        Write-Warning "[WARN] Backups will use target server N`$ shares."
    }

    New-Item $script:DecomLogDir -ItemType Directory -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $script:DecomTranscriptPath = Join-Path $script:DecomLogDir "Decom_RFC${RFCNumber}_$stamp.log"
    $script:DecomPlanPath       = Join-Path $script:DecomLogDir "DecomPlan_RFC${RFCNumber}_$stamp.json"
    $script:DecomManifestPath   = Join-Path $script:DecomLogDir "DecomManifest_RFC${RFCNumber}_$stamp.json"
    $script:DecomSummaryPath    = Join-Path $script:DecomLogDir "DecomSummary_RFC${RFCNumber}_$stamp.json"

    Start-Transcript -Path $script:DecomTranscriptPath -Append | Out-Null

    Write-Host "`n[INFO] Initializing for RFC $RFCNumber..." -ForegroundColor Cyan
    Write-Host "[INFO] Host list file: $($script:DecomHostListPath)"
    if ($script:DecomPlanOnly) {
        Write-Host '[INFO] PlanOnly mode - no backups/renames/inventory updates will run.' -ForegroundColor Yellow
    }

    Import-DecomDependencies
    Import-DecomHostInventory

    $script:DecomTargets = @(
        $script:DecomHostInventory.Values |
            ForEach-Object { $_.ServerName } |
            Sort-Object -Unique
    )
    Write-Host "[INFO] Loaded $($script:DecomTargets.Count) host(s) from file: $($script:DecomTargets -join ', ')"

    $script:DecomDbatoolsVersion = (Get-Module dbatools).Version.ToString()
    $script:DecomPsVersion       = $PSVersionTable.PSVersion.ToString()
    $script:DecomRunBy           = "$env:USERDOMAIN\$env:USERNAME"

    # Tracking collections used throughout the run
    $script:DecomUnreachableOrUnresolved = [System.Collections.Generic.List[string]]::new()
    $script:DecomResolvedAgs             = @{}   # AgName -> @{ Primary; Replicas; SeedInstance }
    $script:DecomResolvedStandalone      = [System.Collections.Generic.List[string]]::new()
    $script:DecomValidAgs                = @{}
    $script:DecomProcessedServers        = [System.Collections.Generic.List[string]]::new()
    $script:DecomProcessedAgs            = [System.Collections.Generic.List[string]]::new()
    $script:DecomFailedServers           = [System.Collections.Generic.List[string]]::new()
    $script:DecomFailedAgs               = [System.Collections.Generic.List[string]]::new()
    $script:DecomRenameFailures          = @{}   # key (server or AG) -> list of db names
    $script:DecomIpValidationResults     = [System.Collections.Generic.List[object]]::new()
    $script:DecomPreflightHardFailures   = [System.Collections.Generic.List[string]]::new()
    $script:DecomPreflightWarnings       = [System.Collections.Generic.List[string]]::new()
    $script:DecomHadFailures             = $false

    $script:DecomManifest = [ordered]@{
        RFCNumber          = $RFCNumber
        StartedAt          = (Get-Date -Format o)
        RunBy              = $script:DecomRunBy
        HostList           = $script:DecomHostListPath
        Targets            = $script:DecomTargets
        PlanOnly           = $script:DecomPlanOnly
        ExcludeDatabases   = $script:DecomExcludeDatabases
        Standalone         = [ordered]@{}
        AvailabilityGroups = [ordered]@{}
        Steps              = [System.Collections.Generic.List[object]]::new()
    }

    # Return a caller-safe snapshot (module $script: scope is not visible to the entry script).
    [pscustomobject]@{
        RFCNumber    = $script:DecomRFCNumber
        HostList     = $script:DecomHostListPath
        PlanOnly     = $script:DecomPlanOnly
        TargetCount  = $script:DecomTargets.Count
        PlanPath     = $script:DecomPlanPath
        ManifestPath = $script:DecomManifestPath
    }
}

