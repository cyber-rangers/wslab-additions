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

    Start-Transcript -Path "$PSScriptRoot\StartLab.log"

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

#region start DC
    #if DC was present, just grab it
            $DC=get-vm -Name ($labconfig.prefix+"DC")

    #Start DC if it is not running
    if ($DC.State -ne "Running"){
        WriteInfo "DC was not started. Starting now..."
        $DC | Start-VM -Verbose
    }
#endregion

#region Test DC to come up

    #Credentials for Session
        $username = "$($Labconfig.DomainNetbiosName)\Administrator"
        $password = $LabConfig.AdminPassword
        $secstr = New-Object -TypeName System.Security.SecureString
        $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
        $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr

    #wait for DC to start
        WriteInfoHighlighted "Waiting for Active Directory on $($DC.name) to be Started."
        do{
            $test=Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $Labconfig -ErrorAction SilentlyContinue -ScriptBlock {
                param($labconfig);
                Get-ADComputer -Filter * -ErrorAction SilentlyContinue
            }
            Start-Sleep 5
        }until ($test -ne $Null)
        WriteSuccess "Active Directory on $($DC.name) is up."

    #start all remaining VMs
    WriteInfoHighlighted "Starting all remaining VMs."
    $VMs_except_MainDC = Get-VM -Name "$($labconfig.prefix)*" | Where-Object {$_.name -ne $($labconfig.prefix+"DC")}
    $VMs_except_MainDC | Start-VM -Verbose

    #write how much it took to deploy
        WriteInfo "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"

    Stop-Transcript

    WriteSuccess "Press enter to continue ..."
    Read-Host | Out-Null
#endregion
