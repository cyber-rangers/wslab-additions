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
        $exit=Read-Host
        Exit
    }

#endregion

#load LabConfig
        . "$PSScriptRoot\LabConfig.ps1"
        $prefix=$LabConfig.Prefix

        #just to be sure, not clean all VMs
        if (!$prefix){
            WriteErrorAndExit "Prefix is empty. Exiting"
        }

    #grab all VMs, switches and DC
        $VMs=get-vm -Name $prefix* | Sort-Object -Property Name

            #List VMs
        If ($VMs){
            WriteInfoHighlighted "VMs:"
            $VMS | ForEach-Object {
                WriteInfo "`t $($_.Name)"
            }
        }

            #just one more space
        WriteInfo ""

        #ask for checkpointing
    if ($VMs){
        WriteInfoHighlighted "This script will restore checkpoints on all VMs listed above. Do you want to do it?"
        if ((read-host "(type Y or N)") -eq "Y"){
            WriteSuccess "You typed Y .. Restoring the lab"
            WriteInfo "Stopping VMs..."
            $VMs | Stop-VM -TurnOff -Force -Confirm:$false -Passthru
            WriteInfo "Restoring VMs..."
            $VMs | Get-VMCheckpoint -Name 'Master CheckPoint' | Restore-VMCheckpoint -confirm:$false
            #finishing    
                WriteSuccess "Job Done! Press enter to continue ..."
                $exit=Read-Host
            }else {
            WriteErrorAndExit "You did not type Y"
        }
    }else{
        WriteErrorAndExit "No VMs with prefix $prefix detected. Exitting"
    }