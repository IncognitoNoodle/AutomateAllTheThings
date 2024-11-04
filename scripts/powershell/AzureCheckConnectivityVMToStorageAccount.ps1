#Connect-AzAccount

Set-AzContext -Subscription "c48890b7-53c1-42f0-a7ad-6433a48e8929"

$rgName = 'au1-5rgp-sql001'
$sourceVMName = 'au1-5vmc-sql001'

$RG = Get-AzResourceGroup -Name $rgName

$VM1 = Get-AzVM -ResourceGroupName $rgName | Where-Object -Property Name -EQ $sourceVMName

$networkWatcher = Get-AzNetworkWatcher | Where-Object -Property Location -EQ -Value $VM1.Location

Test-AzNetworkWatcherConnectivity -NetworkWatcher $networkWatcher -SourceId $VM1.Id -DestinationAddress https://au1clientsqlbackup.blob.core.windows.net/ -DestinationPort 443