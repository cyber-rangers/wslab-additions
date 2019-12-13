Write-Host "Looking for PowerShell version 2 launches"

Get-WinEvent -LogName "Windows PowerShell" | Where-Object Id -eq 400 | Foreach-Object {
        $version = [Version] ($_.Message -replace '(?s).*EngineVersion=([\d\.]+)*.*','$1')
        if($version -lt ([Version] "5.0")) { $_ }
}

pause