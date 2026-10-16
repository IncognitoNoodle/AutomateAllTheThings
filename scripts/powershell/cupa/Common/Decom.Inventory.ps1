# Inventory update - mark successfully processed standalone servers inactive.
# AG replica nodes are intentionally NOT auto-marked inactive (AG left intact).

function Update-DecomInventory {
    [CmdletBinding()]
    param()

    Write-Host "`n===== INVENTORY UPDATE =====" -ForegroundColor Cyan

    # Only standalone servers that completed processing.
    # AG replicas stay active because the AG / listener are left intact.
    $serversToMarkInactive = @($script:DecomProcessedServers)

    if ($serversToMarkInactive.Count -eq 0) {
        Write-Host '[INFO] No servers to mark inactive in inventory.'
        return
    }

    foreach ($srv in $serversToMarkInactive) {
        try {
            Invoke-DbaQuery `
                -SqlInstance $script:DecomInventoryInstance `
                -Database dba_inv `
                -SqlParameters @{ srv = $srv } `
                -Query @"
DECLARE @id INT = (SELECT ServerID FROM dba_inv.dbo.Servers WHERE servername = @srv);
IF @id IS NOT NULL
BEGIN
    UPDATE dba_inv.dbo.Servers   SET Active = 0 WHERE ServerID = @id;
    UPDATE dba_inv.dbo.Instances SET Active = 0 WHERE ServerID = @id;
END
"@ `
                -ErrorAction Stop
            Write-Host "[UPDATED] $srv marked inactive"
        }
        catch {
            Write-Warning "[FAILED INVENTORY] $srv : $($_.Exception.Message)"
        }
    }
}
