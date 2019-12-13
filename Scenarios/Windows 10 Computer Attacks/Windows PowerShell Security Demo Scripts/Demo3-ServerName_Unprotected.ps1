#unprotected
Invoke-Command -ComputerName dc.cyber-rangers.lab -ScriptBlock {gip | select InterfaceAlias,IPv4Address}