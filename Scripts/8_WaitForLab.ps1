# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    exit
}

#region Functions

    function WriteInfo($message){
        Write-Host $message
    }

    function WriteInfoHighlighted($message){
        Write-Host $message -ForegroundColor Cyan
    }

    function WriteSuccess($message){
        Write-Host $message -ForegroundColor Green
    }

    function WriteError($message){
        Write-Host $message -ForegroundColor Red
    }

    function WriteErrorAndExit($message){
        Write-Host $message -ForegroundColor Red
        Write-Host "Press enter to continue ..."
        Stop-Transcript
        Read-Host | Out-Null
        Exit
    }
#endregion

#region Initialization

    Start-Transcript -Path "$PSScriptRoot\WaitForLab.log"

    $StartDateTime = get-date
    WriteInfoHighlighted "Script started at $StartDateTime"


    ##Load LabConfig....
        . "$PSScriptRoot\LabConfig.ps1"

#endregion

#region Set variables
    WriteInfoHighlighted "List of variables used"
    WriteInfo "`t Prefix used in lab is $($labconfig.prefix)"
#endregion

#region Some Additional checks and prereqs configuration

    #checking if Prefix is not empty
        if (!$LabConfig.Prefix){
            WriteErrorAndExit "`t Prefix is empty. Exiting"
        }

#endregion

#region Are all VMs running?
    if ($(get-vm goc206-* | where-object {$_.state -ne 'Running'} | Measure-Object | Select-Object -ExpandProperty count) -gt 0) {
        WriteErrorAndExit "`t Some VMs are not running. Exiting"
    }
#endregion

#region Wait
    #wait for all lab VMs
    WriteInfoHighlighted "Waiting for all lab VMs."
    Get-VM -Name "$($labconfig.prefix)*" | Wait-VM -For Heartbeat

    #write how much it took to deploy
        WriteInfo "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"

    Stop-Transcript

    WriteSuccess "Press enter to continue ..."
    Read-Host | Out-Null
#endregion
