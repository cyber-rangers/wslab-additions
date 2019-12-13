 $credential = New-Object System.Management.Automation.PSCredential('RANGERS\corpadmin',$(ConvertTo-SecureString -AsPlainText -Force -String 'P@ssw0rd'))

 Get-WmiObject -Class win32_computersystem -ComputerName dc.cyber-rangers.lab -Credential $credential