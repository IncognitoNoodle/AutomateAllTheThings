function Format-SampleMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    "Hello, $Name (from private helper)."
}
