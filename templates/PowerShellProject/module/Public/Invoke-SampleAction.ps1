function Invoke-SampleAction {
    <#
    .SYNOPSIS
        Sample exported command.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $msg = Format-SampleMessage -Name $Name
    Write-Output $msg
}
