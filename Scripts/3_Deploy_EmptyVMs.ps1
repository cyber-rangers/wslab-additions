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

    function  Get-WindowsBuildNumber { 
        $os = Get-WmiObject -Class Win32_OperatingSystem 
        return [int]($os.BuildNumber) 
    } 

    function WrapProcess{
        #Using this function you can run legacy program and search in output string 
        #Example: WrapProcess -filename fltmc.exe -arguments "attach svhdxflt e:" -outputstring "Success"
        [CmdletBinding()]
        [Alias()]
        [OutputType([bool])]
        Param (
            # process name. For example fltmc.exe
            [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0)]
            $filename,

            # arguments. for example "attach svhdxflt e:"
            [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=1)]
            $arguments,

            # string to search. for example "attach svhdxflt e:"
            [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=1)]
            $outputstring
        )
        Process {
            $procinfo = New-Object System.Diagnostics.ProcessStartInfo
            $procinfo.FileName = $filename
            $procinfo.Arguments = $arguments
            $procinfo.UseShellExecute = $false
            $procinfo.CreateNoWindow = $true
            $procinfo.RedirectStandardOutput = $true
            $procinfo.RedirectStandardError = $true


            # Create a process object using the startup info
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $procinfo
            # Start the process
            $process.Start() | Out-Null

            # test if process is still running
            if(!$process.HasExited){
                do{
                   Start-Sleep 1 
                }until ($process.HasExited -eq $true)
            }

            # get output 
            $out = $process.StandardOutput.ReadToEnd()

            if ($out.Contains($outputstring)) {
                $output=$true
            } else {
                $output=$false
            }
            return, $output
        }
    }

    Function BuildEmptyVM {
        [cmdletbinding()]
        param(
            [PSObject]$VMConfig,
            [PSObject]$LabConfig,
            [string]$LabFolder
        )
        WriteInfoHighlighted "Creating VM $($VMConfig.VMName)"
            
        $VMname=$Labconfig.Prefix+$VMConfig.VMName
        $vhdpath="$LabFolder\VMs\$VMname\Virtual Hard Disks\$VMname.vhdx"
        WriteInfo "`t Creating OS Empty VHD"
        New-VHD -Path $vhdpath -SizeBytes 60GB -Dynamic
        WriteInfo "`t Creating VM"
        if ($VMConfig.Generation -eq 1){
            $VMTemp=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes $VMConfig.MemoryStartupBytes -path "$LabFolder\VMs" -SwitchName $SwitchName -Generation 1
        }else{
            $VMTemp=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes $VMConfig.MemoryStartupBytes -path "$LabFolder\VMs" -SwitchName $SwitchName -Generation 2    
        }
        $VMTemp | Set-VMMemory -DynamicMemoryEnabled $true
        $VMTemp | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management1
        if ($VMTemp.AutomaticCheckpointsEnabled -eq $True){
            $VMTemp | Set-VM -AutomaticCheckpointsEnabled $False
        }

        $MGMTNICs=$VMConfig.MGMTNICs
        If($MGMTNICs -eq $null){
            $MGMTNICs = 2
        }

        If($MGMTNICs -gt 8){
            $MGMTNICs=8
        }

        If($MGMTNICs -ge 2){
            2..$MGMTNICs | ForEach-Object {
                WriteInfo "`t Adding Network Adapter Management$_"
                $VMTemp | Add-VMNetworkAdapter -Name "Management$_"
            }
        }
        WriteInfo "`t Connecting vNIC to $switchname"
        $VMTemp | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $SwitchName

        if ($LabConfig.Secureboot -eq $False) {
            WriteInfo "`t Disabling Secureboot"
            $VMTemp | Set-VMFirmware -EnableSecureBoot Off
        }

        if ($VMConfig.AdditionalNetworks -eq $True){
            WriteInfoHighlighted "`t Configuring Additional networks"
            foreach ($AdditionalNetworkConfig in $Labconfig.AdditionalNetworksConfig){
                WriteInfo "`t Adding Adapter $($AdditionalNetworkConfig.NetName) with IP $($AdditionalNetworkConfig.NetAddress)$global:IP"
                $VMTemp | Add-VMNetworkAdapter -SwitchName $SwitchName -Name $AdditionalNetworkConfig.NetName
                $VMTemp | Get-VMNetworkAdapter -Name $AdditionalNetworkConfig.NetName  | Set-VMNetworkConfiguration -IPAddress "$($AdditionalNetworkConfig.NetAddress)$global:IP" -Subnet $AdditionalNetworkConfig.Subnet
                if($AdditionalNetworkConfig.NetVLAN -ne 0){ $VMTemp | Get-VMNetworkAdapter -Name $AdditionalNetworkConfig.NetName | Set-VMNetworkAdapterVlan -VlanId $AdditionalNetworkConfig.NetVLAN -Access }
            }
            $global:IP++
        }

        #Generate DSC Config
        if ($VMConfig.DSCMode -eq 'Pull'){
            WriteInfo "`t Setting DSC Mode to Pull"
            PullClientConfig -ComputerName $VMConfig.VMName -DSCConfig $VMConfig.DSCConfig -OutputPath "$PSScriptRoot\temp\dscconfig" -DomainName $LabConfig.DomainName
        }

        #configure nested virt
        if ($VMConfig.NestedVirt -eq $True){
            WriteInfo "`t Enabling NestedVirt"
            $VMTemp | Set-VMProcessor -ExposeVirtualizationExtensions $true
            $VMTemp | Set-VMMemory -DynamicMemoryEnabled $False
        }

        #configure vTPM
        if ($VMConfig.vTPM -eq $True){
            if ($VMConfig.Generation -eq 1){
                WriteError "`t vTPM requested. But vTPM is not compatible with Generation 1"
            }else{
                WriteInfo "`t Enabling vTPM"
                $keyprotector = New-HgsKeyProtector -Owner $guardian -AllowUntrustedRoot
                Set-VMKeyProtector -VM $VMTemp -KeyProtector $keyprotector.RawData
                Enable-VMTPM -VM $VMTemp
            }
        }

        #set MemoryMinimumBytes
        if ($VMConfig.MemoryMinimumBytes -ne $null){
            WriteInfo "`t Configuring MemoryMinimumBytes to $($VMConfig.MemoryMinimumBytes/1MB)MB"
            if ($VMConfig.NestedVirt){
                "`t `t Skipping! NestedVirt configured"
            }else{
                Set-VM -VM $VMTemp -MemoryMinimumBytes $VMConfig.MemoryMinimumBytes
            }
        }

        #Set static Memory
        if ($VMConfig.StaticMemory -eq $true){
            WriteInfo "`t Configuring StaticMemory"
            $VMTemp | Set-VMMemory -DynamicMemoryEnabled $false
        }

        #configure number of processors
        if ($VMConfig.VMProcessorCount){
            WriteInfo "`t Configuring VM Processor Count to $($VMConfig.VMProcessorCount)"
            if ($VMConfig.VMProcessorCount -le $NumberOfLogicalProcessors){
                $VMTemp | Set-VMProcessor -Count $VMConfig.VMProcessorCount
            }else{
                WriteError "`t `t Number of processors specified in VMProcessorCount is greater than Logical Processors available in Host!"
                WriteInfo  "`t `t Number of logical Processors in Host $NumberOfLogicalProcessors"
                WriteInfo  "`t `t Number of Processors provided in labconfig $($VMConfig.VMProcessorCount)"
                WriteInfo  "`t `t Will configure maximum processors possible instead ($NumberOfLogicalProcessors)"
                $VMTemp | Set-VMProcessor -Count $NumberOfLogicalProcessors
            }
        }else{
            $VMTemp | Set-VMProcessor -Count 2
        }

        #add toolsdisk
        if ($VMConfig.AddToolsVHD -eq $True){
            $VHD=New-VHD -ParentPath "$($toolsparent.fullname)" -Path "$LabFolder\VMs\$VMname\Virtual Hard Disks\tools.vhdx"
            WriteInfoHighlighted "`t Adding Virtual Hard Disk $($VHD.Path)"
            $VMTemp | Add-VMHardDiskDrive -Path $vhd.Path
        }
    }
#endregion

#region Initialization

    Start-Transcript -Path "$PSScriptRoot\Deploy_EmptyVMs.log"

    $StartDateTime = get-date
    WriteInfoHighlighted "Script started at $StartDateTime"


    ##Load LabConfig....
        . "$PSScriptRoot\LabConfig.ps1"

#endregion

#region Set variables

    If (!$LabConfig.DomainNetbiosName){
        $LabConfig.DomainNetbiosName="Corp"
    }

    If (!$LabConfig.DomainName){
        $LabConfig.DomainName="Corp.contoso.com"
    }

    If (!$LabConfig.DefaultOUName){
        $LabConfig.DefaultOUName="Workshop"
    }

    $DN=$null
    $LabConfig.DomainName.Split(".") | ForEach-Object {
        $DN+="DC=$_,"
    }
    $LabConfig.DN=$DN.TrimEnd(",")

    $global:IP=1

    WriteInfoHighlighted "List of variables used"
    WriteInfo "`t Prefix used in lab is $($labconfig.prefix)"

    $SwitchName=($labconfig.prefix+$LabConfig.SwitchName)
    WriteInfo "`t Switchname is $SwitchName" 

    WriteInfo "`t Workdir is $PSScriptRoot"

    $LABfolder="$PSScriptRoot\LAB"
    WriteInfo "`t LabFolder is $LabFolder"

    $LABfolderDrivePath=$LABfolder.Substring(0,3)

    $ExternalSwitchName="$($Labconfig.Prefix)$($LabConfig.Switchname)-External"

    #Grab TimeZone
    $TimeZone=(Get-TimeZone).id

    #Grab number of processors
    (get-wmiobject win32_processor).NumberOfLogicalProcessors  | ForEach-Object { $global:NumberOfLogicalProcessors += $_}

#endregion

#region Some Additional checks and prereqs configuration

    #checking if Prefix is not empty
        if (!$LabConfig.Prefix){
            WriteErrorAndExit "`t Prefix is empty. Exiting"
        }

    # Checking for Compatible OS
        WriteInfoHighlighted "Checking if OS is Windows 10 1511 (10586)/Server 2016 or newer"
        $BuildNumber=Get-WindowsBuildNumber
        if ($BuildNumber -ge 10586){
            WriteSuccess "`t OS is Windows 10 1511 (10586)/Server 2016 or newer"
        }else{
            WriteErrorAndExit "`t Windows 10/ Server 2016 not detected. Exiting"
        }

    # Checking for NestedVirt
        if ($LABConfig.EmptyVMs.NestedVirt -contains $True){
            $BuildNumber=Get-WindowsBuildNumber
            if ($BuildNumber -ge 14393){
                WriteSuccess "`t Windows is build greater than 14393. NestedVirt will work"
            }else{
                WriteErrorAndExit "`t Windows build older than 14393 detected. NestedVirt will not work. Exiting"
            }
        }

    # Checking for vTPM support
        if ($LABConfig.EmptyVMs.vTPM -contains $true){
            $BuildNumber=Get-WindowsBuildNumber
            if ($BuildNumber -ge 14393){
                WriteSuccess "`t Windows is build greater than 14393. vTPM will work"
            }else{
                WriteErrorAndExit "`t Windows build older than 14393 detected. vTPM will not work Exiting"
            }
            <# Not needed anymore as VBS is automatically enabled since 14393 when vTPM is used
            if (((Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus -ne 0) -and ((Get-Process "secure system") -ne $null )){
                WriteSuccess "`t Virtualization Based Security is running. vTPM can be enabled"
            }else{
                WriteErrorAndExit "`t Virtualization based security is not running. Enable VBS, or remove vTPM from configuration"
            }
            #>
            #load Guardian
            $guardian=Get-HgsGuardian | Select-Object -first 1
            if($guardian -eq $null){
                $guardian=New-HgsGuardian -Name LabGuardian -GenerateCertificates
                WriteInfo "`t HGS with name LabGuardian created"
            }
        }

    #Check if Hyper-V is installed
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

    #enable EnableEnhancedSessionMode if not enabled
    if (-not (Get-VMHost).EnableEnhancedSessionMode){
        WriteInfoHighlighted "Enhanced session mode was disabled. Enabling."
        Set-VMHost -EnableEnhancedSessionMode $true
    }

    #Create Switches

        WriteInfoHighlighted "Creating Switch"
        WriteInfo "`t Checking if $SwitchName already exists..."

        if ((Get-VMSwitch -Name $SwitchName -ErrorAction Ignore) -eq $Null){ 
            WriteInfo "`t Creating $SwitchName..."
            New-VMSwitch -SwitchType Private -Name $SwitchName
        }else{
            $SwitchNameExists=$True
            WriteInfoHighlighted "`t $SwitchName exists. Looks like lab with same prefix exists. "
        }

    #Testing if lab already exists.
        WriteInfo "Testing if lab already exists."
        if ($SwitchNameExists){
            if ((Get-vm -Name ($labconfig.prefix+"DC") -ErrorAction SilentlyContinue) -ne $null){
                $LABExists=$True
                WriteInfoHighlighted "`t Lab already exists. If labconfig contains additional VMs, they will be added."
            }
        }

    #Create Mount nd VMs directories
        WriteInfoHighlighted "Creating Mountdir"
        New-Item "$PSScriptRoot\Temp\MountDir" -ItemType Directory -Force

        WriteInfoHighlighted "Creating VMs dir"
        New-Item "$PSScriptRoot\LAB\VMs" -ItemType Directory -Force

#endregion


#region Provision VMs
    #process $LABConfig.EmptyVMs and create VMs (skip if machine already exists)
        WriteInfoHighlighted 'Processing $LABConfig.EmptyVMs, creating VMs'
        foreach ($VMConfig in $LABConfig.EmptyVMs.GetEnumerator()){
            if (!(Get-VM -Name "$($labconfig.prefix)$($VMConfig.vmname)" -ErrorAction SilentlyContinue)){
                #create VM with Simple configuration
                BuildEmptyVM -VMConfig $($VMConfig) -LabConfig $labconfig -LabFolder $LABfolder
            }
        }
#endregion

#region Finishing
    WriteInfoHighlighted "Finishing..." 

    #a bit cleanup
        Remove-Item -Path "$PSScriptRoot\temp" -Force -Recurse
        if (Test-Path "$PSScriptRoot\unattend.xml") {
            remove-item "$PSScriptRoot\unattend.xml"
        }

    #set MacSpoofing and AllowTeaming (for SET switch in VMs to work properly with vNICs)
        WriteInfo "`t Setting MacSpoofing On and AllowTeaming On"
        Set-VMNetworkAdapter -VMName "$($labconfig.Prefix)*" -MacAddressSpoofing On -AllowTeaming On

    #list VMs 
        $LABConfig.EmptyVMs.GetEnumerator()  | ForEach-Object { WriteSuccess "Machine $($_.VMName) provisioned" }

    #configure allowed VLANs (to create nested vNICs with VLANs)
        if ($labconfig.AllowedVLans){
            WriteInfo "`t Configuring AllowedVlanIdList for Management NICs to $($LabConfig.AllowedVlans)"
            Get-VMNetworkAdapter -VMName "$($labconfig.Prefix)*" -Name Management* | Set-VMNetworkAdapterVlan -Trunk -NativeVlanId 0 -AllowedVlanIdList $LabConfig.AllowedVlans
        }else{
            WriteInfo "`t Configuring AllowedVlanIdList for Management NICs to 1-10"
            Get-VMNetworkAdapter -VMName "$($labconfig.Prefix)*" -Name Management* | Set-VMNetworkAdapterVlan -Trunk -NativeVlanId 0 -AllowedVlanIdList "1-10"
        }

    #configure HostResourceProtection on all VM CPUs
        WriteInfo "`t Configuring EnableHostResourceProtection on all VM processors"
        Set-VMProcessor -EnableHostResourceProtection $true -VMName "$($labconfig.Prefix)*" -ErrorAction SilentlyContinue

    #Enable Guest services on all VMs if integration component if configured
    if ($labconfig.EnableGuestServiceInterface){
        WriteInfo "`t Enabling Guest Service Interface"
        Get-VM -VMName "$($labconfig.Prefix)*" | Where-Object {$_.state -eq "Running" -or $_.state -eq "Off"} | Enable-VMIntegrationService -Name "Guest Service Interface"
        $TempVMs=Get-VM -VMName "$($labconfig.Prefix)*" | Where-Object {$_.state -ne "Running" -and $_.state -ne "Off"}
        if ($TempVMs){
            WriteInfoHighlighted "`t `t Following VMs cannot be configured, as the state is not running or off"
            $TempVMs.Name
        }
    }

    #Enable VMNics device naming
        WriteInfo "`t Enabling VMNics device naming"
        Get-VM -VMName "$($labconfig.Prefix)*" | Where-Object Generation -eq 2 | Set-VMNetworkAdapter -DeviceNaming On

    #write how much it took to deploy
        WriteInfo "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"

    Stop-Transcript

    WriteSuccess "Press enter to continue ..."
    Read-Host | Out-Null
#endregion
