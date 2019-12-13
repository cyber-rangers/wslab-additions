param($processname)
Invoke-Expression "Get-Process -ProcessName $ProcessName"

$constructedScriptBlock = [scriptblock]::Create("Get-Process -ProcessName $ProcessName")
& $constructedScriptBlock