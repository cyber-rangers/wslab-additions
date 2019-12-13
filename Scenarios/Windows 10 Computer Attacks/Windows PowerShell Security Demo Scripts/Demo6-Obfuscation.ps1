Get-ChildItem C:\Demo\Invoke-Obfuscation -Recurse | Unblock-File

Import-Module C:\Demo\Invoke-Obfuscation\Invoke-Obfuscation.psd1 -Force

Invoke-Obfuscation

<#
SET SCRIPTPATH C:\Demo\Demo2-signed.ps1
ENCODE
6
SHOW
TEST
EXEC
COPY
#>