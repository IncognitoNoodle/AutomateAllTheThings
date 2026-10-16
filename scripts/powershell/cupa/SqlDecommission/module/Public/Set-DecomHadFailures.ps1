function Set-DecomHadFailures {
    <#
    Marks the run as failed from the orchestrator catch path (module script scope).
    #>
    [CmdletBinding()]
    param(
        [bool]$Value = $true
    )

    $script:DecomHadFailures = $Value
}
