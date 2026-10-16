function Complete-DecomSession {
    [CmdletBinding()]
    param()

    if ($script:DecomTranscriptPath) {
        try { Stop-Transcript | Out-Null } catch { }
    }
}

