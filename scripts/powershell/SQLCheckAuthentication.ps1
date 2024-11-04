$serverName = ""
$databaseName = ""
$connectionString = ""
Add-Type -AssemblyName "System.Data"
$connection = New-Object System.Data.SqlClient.SqlConnection
$connection.ConnectionString = $connectionString
$connection.Open()
$command = $connection.CreateCommand()
$command.CommandText = "SELECT DB_NAME()"
$reader = $command.ExecuteReader()
while ($reader.Read()) {    Write-Output $reader[0]}
$reader.Close()
$connection.Close()
