#DEMO prep
New-Item -Path HKLM:\SOFTWARE\DEMO
New-ItemProperty -Path HKLM:\SOFTWARE\DEMO -Name ServerForInvokeCommand -Value 'dc.cyber-rangers.lab'





#DEMO
#protected
$ComputerName = Get-ItemPropertyValue -Path HKLM:\SOFTWARE\DEMO -Name ServerForInvokeCommand
Invoke-Command -ComputerName $ComputerName -ScriptBlock {gip | select InterfaceAlias,IPv4Address}

#or interactive
$ComputerName = Read-Host "Enter server name FQDN"
Invoke-Command -ComputerName $ComputerName -ScriptBlock {gip | select InterfaceAlias,IPv4Address}






#DEMO cleanup
Remove-ItemProperty -Path HKLM:\SOFTWARE\DEMO -Name ServerForInvokeCommand
Remove-Item -Path HKLM:\SOFTWARE\DEMO