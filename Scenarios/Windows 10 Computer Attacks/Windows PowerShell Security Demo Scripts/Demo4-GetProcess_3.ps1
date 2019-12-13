param($processname)

$processname = $processname -replace "'","''"

$expression = "Get-Process -ProcessName '$ProcessName'"
Invoke-Expression $expression