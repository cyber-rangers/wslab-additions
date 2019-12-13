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

#region Do some clenaup

    #load LabConfig
        . "$PSScriptRoot\LabConfig.ps1"
        $prefix=$LabConfig.Prefix

    #just to be sure, not clean all VMs
        if (!$prefix){
            WriteErrorAndExit "Prefix is empty. Exiting"
        }

    #grab all VMs
        $VMs=get-vm -Name $prefix* | where Name -ne "$($prefix)DC" -ErrorAction SilentlyContinue | Sort-Object -Property Name
        $DC=get-vm "$($prefix)DC" -ErrorAction SilentlyContinue

    #List VMs, Switches and DC
        If ($VMs){
            WriteInfoHighlighted "VMs:"
            $VMS | ForEach-Object {
                WriteInfo "`t $($_.Name)"
            }
        }

        if ($DC){
            WriteInfoHighlighted "DC:"
            WriteInfo "`t $($DC.Name)"
        }

    #just one more space
        WriteInfo ""

    if ($($VMs | Where-Object {$_.State -ne 'Off'}).count -gt 0) {
        WriteErrorAndExit "Some VMs are running. Please turn them off first."
    }
    if ($($DC | Where-Object {$_.State -ne 'Off'}).count -gt 0) {
        WriteErrorAndExit "Some DCs are running. Please turn them off first."
    }

    #just one more space
        WriteInfo ""
#ask for cleanup and clean all if confirmed.
    if (($VMs) -or ($DC)){
        WriteInfoHighlighted "This script will optimize all items listed above. Do you want to do it?"
        if ((read-host "(type Y or N)") -eq "Y"){
            WriteSuccess "You typed Y .. Optimizing lab"
            if ($DC){
                WriteInfoHighlighted "Optimizing DC"
                $DC | Set-VM -AutomaticStopAction ShutDown
            }
            if ($VMs){
                WriteInfoHighlighted "Optimizing VMs"
                foreach ($VM in $VMs){
                WriteInfo "`t Reconfiguring VM $($VM.Name)"
                WriteInfo "`t`tAutomatic Stop Action `= Shutdown"
                $VM | Set-VM -AutomaticStopAction ShutDown
                WriteInfo "`t`tEnable Host Resource Protection `= Falses"
                $VM | Set-VMProcessor -EnableHostResourceProtection $false
                }
            }

            #finishing    
                WriteSuccess "Job Done! Press enter to continue ..."
                $exit=Read-Host
        }else {
            WriteErrorAndExit "You did not type Y"
        }
    }else{
        WriteErrorAndExit "No VMs with prefix $prefix detected. Exitting"
    }
#endregion