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

    function WriteSuccess($message)
    {
        Write-Host $message -ForegroundColor Green
    }

    function WriteError($message)
    {
        Write-Host $message -ForegroundColor Red
    }

    function WriteErrorAndExit($message){
        Write-Host $message -ForegroundColor Red
        Write-Host "Press enter to continue ..."
        Stop-Transcript
        Read-Host | Out-Null
        Exit
    }

    #Create Unattend for VHD 
    Function CreateUnattendFileVHD{
        param (
            [parameter(Mandatory=$true)]
            [string]
            $Computername,
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $Path,
            [parameter(Mandatory=$true)]
            [string]
            $TimeZone
        )

        if ( Test-Path "$path\Unattend.xml" ) {
            Remove-Item "$Path\Unattend.xml"
        }
        $unattendFile = New-Item "$Path\Unattend.xml" -type File
        $fileContent =  @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

  <settings pass="offlineServicing">
   <component
        xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        language="neutral"
        name="Microsoft-Windows-PartitionManager"
        processorArchitecture="amd64"
        publicKeyToken="31bf3856ad364e35"
        versionScope="nonSxS"
        >
      <SanPolicy>1</SanPolicy>
    </component>
 </settings>
 <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ComputerName>$Computername</ComputerName>
        <RegisteredOwner>PFE</RegisteredOwner>
        <RegisteredOrganization>Contoso</RegisteredOrganization>
    </component>
 </settings>
 <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        <AdministratorPassword>
           <Value>$AdminPassword</Value>
           <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <SkipMachineOOBE>true</SkipMachineOOBE> 
        <SkipUserOOBE>true</SkipUserOOBE> 
      </OOBE>
      <TimeZone>$TimeZone</TimeZone>
    </component>
  </settings>
</unattend>

"@

        Set-Content -path $unattendFile -value $fileContent

        #return the file object
        Return $unattendFile 
    }

#endregion

#region notification for cleanup
WriteInfoHighlighted 'This script will regenerate ToolsVHD. Be sure it is not used by any VM at this time. Consider cleanup first.'
pause
#endregion

#region Initialization
    #Start Log
        Start-Transcript -Path "$PSScriptRoot\CreateParentDisks_RebuildToolsVHD.log"
        $StartDateTime = get-date
        WriteInfo "Script started at $StartDateTime"

    #Load LabConfig....
        . "$PSScriptRoot\LabConfig.ps1"

    #create variables if not already in LabConfig
        If (!$LabConfig.DomainNetbiosName){
            $LabConfig.DomainNetbiosName="Corp"
        }

        If (!$LabConfig.DomainName){
            $LabConfig.DomainName="Corp.contoso.com"
        }

        If (!$LabConfig.DefaultOUName){
            $LabConfig.DefaultOUName="Workshop"
        }

        If ($LabConfig.PullServerDC -eq $null){
            $LabConfig.PullServerDC=$true
        }

        If (!$LabConfig.DHCPscope){
            $LabConfig.DHCPscope="10.0.0.0"
        }


    #create some built-in variables
        $DN=$null
        $LabConfig.DomainName.Split(".") | ForEach-Object {
            $DN+="DC=$_,"
        }
        
        $LabConfig.DN=$DN.TrimEnd(",")

        $AdminPassword=$LabConfig.AdminPassword
        $Switchname="DC_HydrationSwitch_$([guid]::NewGuid())"
        $DCName='DC'

    #Grab TimeZone
    $TimeZone=(Get-TimeZone).id

    #Grab Installation type
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType

    #DCHP scope
    $DHCPscope = $LabConfig.DHCPscope
    $ReverseDNSrecord = $DHCPscope -replace '^(\d+)\.(\d+)\.\d+\.(\d+)$','$3.$2.$1.in-addr.arpa'
    $DHCPscope = $DHCPscope.Substring(0,$DHCPscope.Length-1) 

#endregion

#region Check prerequisites

    #check Hyper-V    
        WriteInfoHighlighted "Checking if Hyper-V is installed"
        if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state -eq "Enabled"){
            WriteSuccess "`t Hyper-V is Installed"
        }else{
            WriteErrorAndExit "`t Hyper-V not installed. Please install hyper-v feature including Hyper-V management tools. Exiting"
        }

        WriteInfoHighlighted "Checking if Hyper-V Powershell module is installed"
        if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell).state -eq "Enabled"){
            WriteSuccess "`t Hyper-V is Installed"
        }else{
            WriteErrorAndExit "`t Hyper-V tools are not installed. Please install Hyper-V management tools. Exiting"
        }

    #check if VMM prereqs files are present if InstallSCVMM or SCVMM prereq is requested and tools.vhdx not present
        if (-not (Get-ChildItem -Path "$PSScriptRoot\ParentDisks" -ErrorAction SilentlyContinue).name -contains "tools.vhdx"){
            if ($LabConfig.InstallSCVMM -eq "Yes"){
                "Temp\ToolsVHD\SCVMM\ADK\ADKsetup.exe","Temp\ToolsVHD\SCVMM\SCVMM\setup.exe","Temp\ToolsVHD\SCVMM\SQL\setup.exe","Temp\ToolsVHD\SCVMM\ADK\Installers\Windows PE x86 x64-x86_en-us.msi" | ForEach-Object {
                    if(!(Test-Path -Path "$PSScriptRoot\$_")){
                        WriteErrorAndExit "file $_ needed for SCVMM install not found. Exitting"
                    }
                }    
            }

            if ($LabConfig.InstallSCVMM -eq "Prereqs"){
                "Temp\ToolsVHD\SCVMM\ADK\ADKsetup.exe","Temp\ToolsVHD\SCVMM\SQL\setup.exe","Temp\ToolsVHD\SCVMM\ADK\Installers\Windows PE x86 x64-x86_en-us.msi" | ForEach-Object {
                    if(!(Test-Path -Path "$PSScriptRoot\$_")){
                        WriteErrorAndExit "file $_ needed for SCVMM Prereqs install not found. Exitting"
                    }
                } 
            }
        
            if ($LabConfig.InstallSCVMM -eq "SQL"){
                "Temp\ToolsVHD\SCVMM\ADK\ADKsetup.exe","Temp\ToolsVHD\SCVMM\SQL\setup.exe" | ForEach-Object {
                    if(!(Test-Path -Path "$PSScriptRoot\$_")){
                        WriteErrorAndExit "file $_ needed for SQL install not found. Exitting"
                    }
                }
            }    

            if ($LabConfig.InstallSCVMM -eq "ADK"){
                "Temp\ToolsVHD\SCVMM\ADK\ADKsetup.exe" | ForEach-Object {
                    if(!(Test-Path -Path "$PSScriptRoot\$_")){
                        WriteErrorAndExit "file $_ needed for ADK install not found. Exitting"
                    }
                }
            }
        }

    #check if parent images already exist (this is useful if you have parent disks from another lab and you want to rebuild for example scvmm)
        WriteInfoHighlighted "Testing if some parent disk already exists and can be used"
        
        #grab all files in parentdisks folder
            $ParentDisksNames=(Get-ChildItem -Path "$PSScriptRoot\ParentDisks" -ErrorAction SilentlyContinue).Name

    #check if running on Core Server and check proper values in LabConfig
        If ($WindowsInstallationType -eq "Server Core"){
            If (!$LabConfig.ServerISOFolder){
                WriteErrorAndExit "Server Core detected. Please use ServerISOFolder variable in LabConfig to specify Server iso location"
            }
        }

#endregion

#region Rebuild ToolsVHD
#create Tools VHDX from .\Temp\ToolsVHD
    if (Test-Path "$PSScriptRoot\ParentDisks\tools.vhdx"){
        WriteInfoHighlighted "Tools.vhdx found. Will be deleted."
        Remove-Item "$PSScriptRoot\ParentDisks\tools.vhdx" -Force -Confirm:$false
        }
    WriteInfoHighlighted "Creating Tools.vhdx"
    $toolsVHD=New-VHD -Path "$PSScriptRoot\ParentDisks\tools.vhdx" -SizeBytes 100GB -Dynamic
    #mount and format VHD
        $VHDMount = Mount-VHD $toolsVHD.Path -Passthru
        $vhddisk = $VHDMount| get-disk 
        $vhddiskpart = $vhddisk | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter |Format-Volume -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel ToolsDisk 

    $VHDPathTest=Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\"
    if (!$VHDPathTest){
        New-Item -Type Directory -Path "$PSScriptRoot\Temp\ToolsVHD"
    }
    if ($VHDPathTest){
        WriteInfo "Found $PSScriptRoot\Temp\ToolsVHD\*, copying files into VHDX"
        Copy-Item -Path "$PSScriptRoot\Temp\ToolsVHD\*" -Destination "$($vhddiskpart.DriveLetter):\" -Recurse -Force
    }else{
        WriteInfo "Files not found" 
        WriteInfoHighlighted "Add required tools into $PSScriptRoot\Temp\ToolsVHD and Press any key to continue..."
        $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
        Copy-Item -Path "$PSScriptRoot\Temp\ToolsVHD\*" -Destination ($vhddiskpart.DriveLetter+':\') -Recurse -Force
    }

    Dismount-VHD $vhddisk.Number
#endregion

# finishing 
WriteInfo "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
Stop-Transcript
WriteSuccess "Press enter to continue..."
Read-Host | Out-Null