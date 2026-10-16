function Get-DecomExitCode {
    [CmdletBinding()]
    param()

    # Preflight aborts first (documented exit 2), even though those also set HadFailures.
    if ($script:DecomPreflightHardFailures.Count -gt 0) { return 2 }
    if ($script:DecomHadFailures) { return 1 }
    if ($script:DecomFailedServers.Count -gt 0 -or $script:DecomFailedAgs.Count -gt 0) { return 1 }
    if ($script:DecomUnreachableOrUnresolved.Count -gt 0) { return 3 }
    return 0
}

