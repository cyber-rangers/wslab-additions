#protect
$PasswordText = 'P@ssw0rd'
$SecuredPasswordText = ConvertTo-SecureString -String $PasswordText -AsPlainText -Force
$Key = 1..32 | ForEach-Object {Get-Random -Maximum 256 -Minimum 0}
$ProtectedData = ConvertFrom-SecureString -SecureString $SecuredPasswordText -Key $Key
$ProtectedData | Out-File C:\protecteddata.txt
$Key | Out-File C:\key.txt


#use
$ProtectedDataToUse = ConvertTo-SecureString -String (Get-Content C:\protecteddata.txt) -Key (Get-Content C:\Key.txt)
$credential = New-Object System.Management.Automation.PSCredential('RANGERS\corpadmin',$ProtectedDataToUse)

Get-WmiObject -Class win32_bios -ComputerName dc.cyber-rangers.lab -Credential $credential