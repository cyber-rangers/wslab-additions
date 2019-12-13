#DEMO prep
New-Item -Path HKLM:\SOFTWARE\DEMO
New-ItemProperty -Path HKLM:\SOFTWARE\DEMO -Name Username -Value 'rangers\corpadmin'
New-ItemProperty -Path HKLM:\SOFTWARE\DEMO -Name Password -Value 'P@ssw0rd'



#DEMO
$UserName = Get-ItemPropertyValue -Path HKLM:\SOFTWARE\DEMO -Name Username
$Password = Get-ItemPropertyValue -Path HKLM:\SOFTWARE\DEMO -Name Password

$credential = New-Object System.Management.Automation.PSCredential($UserName,$(ConvertTo-SecureString -AsPlainText -Force -String $Password))

#still password "visible"
$credential.GetNetworkCredential().Password

#but unprotected servername :)
Get-WmiObject -Class win32_computersystem -ComputerName dc.cyber-rangers.lab -Credential $credential



#DEMO cleanup
Remove-ItemProperty -Path HKLM:\SOFTWARE\DEMO -Name Username
Remove-ItemProperty -Path HKLM:\SOFTWARE\DEMO -Name Password
Remove-Item -Path HKLM:\SOFTWARE\DEMO