function Get-DecomServerInfoBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SqlInstance,
        [Parameter(Mandatory)][string]$ServerName
    )

    $conn = Connect-DbaInstance -SqlInstance $SqlInstance

    [ordered]@{
        ServerName        = $ServerName
        FQDN              = $conn.ComputerNamePhysicalNetBIOS
        SqlInstance       = $SqlInstance
        SqlVersion        = $conn.Version.ToString()
        SqlEdition        = $conn.Edition
        SqlProductLevel   = $conn.ProductLevel
        SqlBuildNumber    = $conn.VersionString
        Collation         = $conn.Collation
        IsClustered       = $conn.IsClustered
        IsHadrEnabled     = $conn.IsHadrEnabled
        OsVersion         = (Get-DbaOperatingSystem -ComputerName $ServerName -ErrorAction SilentlyContinue).OSVersion
        TotalMemoryMB     = $conn.PhysicalMemory
        ExpectedIP        = (Get-DecomExpectedIp -ServerName $ServerName)
        RFCNumber         = $script:DecomRFCNumber
        RunBy             = $script:DecomRunBy
        PowerShellVersion = $script:DecomPsVersion
        DbatoolsVersion   = $script:DecomDbatoolsVersion
        Timestamp         = (Get-Date -Format o)
    }
}

function Get-DecomDatabaseInfoBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)][string]$AgRole
    )

    [ordered]@{
        Name              = $Database.Name
        SizeMB            = [math]::Round($Database.Size, 2)
        RecoveryModel     = $Database.RecoveryModel
        Owner             = $Database.Owner
        Collation         = $Database.Collation
        CreateDate        = $Database.CreateDate
        Status            = $Database.Status
        LastFullBackup    = $Database.LastBackupDate
        AvailabilityGroup = $Database.AvailabilityGroupName
        AgRole            = $AgRole
    }
}

function Write-DecomInfoFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable[]]$Blocks,
        [Parameter(Mandatory)][string]$Header
    )

    $lines = @("===== $Header =====")
    foreach ($b in $Blocks) {
        $name = if ($b.Contains('ServerName')) { $b.ServerName } else { $b.Name }
        $lines += "--- $name ---"
        foreach ($k in $b.Keys) {
            if ($k -ne 'ServerName' -and $k -ne 'Name') {
                $lines += "  $k`: $($b[$k])"
            }
        }
    }
    $lines | Add-Content $Path -ErrorAction Stop
}

