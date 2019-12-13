Get-ChildItem C:\Demo\IR-Tools -Recurse | Unblock-File

Import-Module C:\Demo\IR-Tools\Get-ShellContent.ps1

<#
cmd.exe
procdump -ma 2372
Get-ShellContent -ProcDump C:\DEMO\ProcDump\conhost.exe_190513_224818.dmp
#>

Get-ShellContent -ProcessID 2372 -Deep