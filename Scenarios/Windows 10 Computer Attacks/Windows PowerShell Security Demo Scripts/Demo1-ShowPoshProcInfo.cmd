powershell -version 2 -noprofile -command "(Get-Item ([PSObject].Assembly.Location)).VersionInfo"
pause

powershell -noprofile -command "(Get-Item ([PSObject].Assembly.Location)).VersionInfo"
pause

powershell -version 2 -noprofile -command "(Get-Item (Get-Process -id $pid -mo | ? { $_.FileName -match 'System.Management.Automation.ni.dll' } | % { $_.FileName })).VersionInfo"
pause

powershell -noprofile -command "(Get-Item (Get-Process -id $pid -mo | ? { $_.FileName -match 'System.Management.Automation.ni.dll' } | % { $_.FileName })).VersionInfo"
pause