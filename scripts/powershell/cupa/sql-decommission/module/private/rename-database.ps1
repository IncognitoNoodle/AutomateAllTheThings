function Invoke-DecomRenameDatabase {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$SqlInstance,
        [Parameter(Mandatory)][string]$ServerName,
        [Parameter(Mandatory)][string]$OriginalName,
        [Parameter(Mandatory)][string]$FailureKey
    )

    if ($OriginalName -like '*_Decom_RFC*') { return $true }
    $newName = "$OriginalName`_Decom_RFC$($script:DecomRFCNumber)"

    try {
        if ($PSCmdlet.ShouldProcess($OriginalName, "Rename to $newName on $ServerName")) {
            Invoke-DbaQuery -SqlInstance $SqlInstance -ErrorAction Stop -Query @"
ALTER DATABASE [$OriginalName] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
ALTER DATABASE [$OriginalName] MODIFY NAME = [$newName];
ALTER DATABASE [$newName] SET MULTI_USER;
"@
            Write-Host "[RENAMED] $OriginalName -> $newName ($ServerName)"
        }
        return $true
    }
    catch {
        Write-Warning "[ERROR] Rename failed for $OriginalName on $ServerName : $($_.Exception.Message)"
        Add-DecomFailure -FailureKey $FailureKey -DatabaseName $OriginalName
        return $false
    }
}

