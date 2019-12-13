# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    exit
}

# Skipping 10 lines because if running when all prereqs met, statusbar covers powershell output
1..10 |% { Write-Host ""}

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

#endregion

#region Initialization

# grab Time and start Transcript
    Start-Transcript -Path "$PSScriptRoot\Prereq_Additional.log"
    $StartDateTime = get-date
    WriteInfo "Script started at $StartDateTime"

#Load LabConfig....
    . "$PSScriptRoot\LabConfig.ps1"

#define some variables if it does not exist in labconfig
    If (!$LabConfig.DomainNetbiosName){
        $LabConfig.DomainNetbiosName="Corp"
    }

    If (!$LabConfig.DomainName){
        $LabConfig.DomainName="Corp.contoso.com"
    }

#set TLS 1.2 for github downloads
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#endregion

#region prereq check
if (!$(Test-Path 'C:\Program Files\7-Zip\7z.exe')) {
    WriteErrorAndExit "Unable to find 7-zip. Please install it first."
}
#endregion prereq check

#region folder build
# Checking Folder Structure
    "Temp\ToolsVHD\ATAUpgrade","Temp\ToolsVHD\ATA","Temp\ToolsVHD\GPO","Temp\ToolsVHD\Commando-VM","Temp\ToolsVHD\Kansa","Temp\ToolsVHD\SysinternalsSuite","Temp\ToolsVHD\ATOM","Temp\ToolsVHD\Scripts","Temp\ToolsVHD\SCCM","Temp\ToolsVHD\SCCMPrereqs","Temp\ToolsVHD\SCOM","Temp\ToolsVHD\SCOMPrereqs" | ForEach-Object {
        if (!( Test-Path "$PSScriptRoot\$_" )) { New-Item -Type Directory -Path "$PSScriptRoot\$_" } }

    "Temp\ToolsVHD\ATA\Copy_ATA_install_here.txt","Temp\ToolsVHD\SCCM\Copy_SCCM_install_here.txt","Temp\ToolsVHD\SCCMPrereqs\Copy_SCCMPrereqs_here.txt","Temp\ToolsVHD\SCOM\Copy_SCOM_install_here.txt","Temp\ToolsVHD\SCOMPrereqs\Copy_SCOMPrereqs_here.txt" | ForEach-Object {
        if (!( Test-Path "$PSScriptRoot\$_" )) { New-Item -Type File -Path "$PSScriptRoot\$_" } }
#endregion folder build

#region Download Scripts
$Filenames="Install-TAFirst2008R2DomainController"
foreach ($Filename in $filenames){
    $Path="$PSScriptRoot\Temp\ToolsVHD\Scripts\$Filename.ps1"
    WriteInfoHighlighted "Testing $Filename presence"
    If (Test-Path -Path $Path){
        WriteSuccess "`t $Filename is present, skipping download"
    }else{
        $FileContent=$null
        $FileContent = (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/cyber-rangers/WSLab-Additions/master/Tools/$Filename.ps1").Content
        if ($FileContent){
            $script = New-Item "$PSScriptRoot\Temp\ToolsVHD\Scripts\$Filename.ps1" -type File -Force
            Set-Content -path $script -value $FileContent
        }else{
            WriteErrorAndExit "Unable to download $Filename."
        }
    }
}

#endregion

#region some tools to download
# Downloading ConfigMgr Prereqs Tool if its not in ToolsVHD folder
    $Filename="usb-over-network-client-server-5-1-11.zip"
    $Path="$PSScriptRoot\Temp\ToolsVHD\$Filename"
    WriteInfoHighlighted "Testing $Filename presence"
    If (Test-Path -Path $Path){
        WriteSuccess "`t $Filename is present, skipping download"
    }else{
        WriteInfoHighlighted "Downloading $Filename"
        Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/cyber-rangers/WSLab-Additions/raw/master/Tools/$Filename" -OutFile $Path
    }

# Downloading ConfigMgr Prereqs Tool if its not in ToolsVHD folder
    $Filename="ConfigMgrPrerequisitesTool304.zip"
    $Path="$PSScriptRoot\Temp\ToolsVHD\SCCMPrereqs\$Filename"
    WriteInfoHighlighted "Testing $Filename presence"
    If (Test-Path -Path $Path){
        WriteSuccess "`t $Filename is present, skipping download"
    }else{
        WriteInfoHighlighted "Downloading $Filename"
        Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/cyber-rangers/WSLab-Additions/raw/master/Tools/$Filename" -OutFile $Path
    }

# Downloading GPO backup if its not in ToolsVHD folder
    $Filename="GPO-Backup.7z"
    $Path="$PSScriptRoot\Temp\ToolsVHD\GPO\$Filename"
    WriteInfoHighlighted "Testing $Filename presence"
    If (Test-Path -Path $Path){
        WriteSuccess "`t $Filename is present, skipping download"
    }else{
        WriteInfoHighlighted "Downloading $Filename"
        Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/cyber-rangers/WSLab-Additions/raw/master/Tools/$Filename" -OutFile "$PSScriptRoot\Temp\ToolsVHD\GPO\$Filename"
    }
    If (Test-Path -Path $Path){
        WriteSuccess "`t $Filename is present, unzipping..."
        $ZipPassword = ''
        $ZipPassword = Read-Host 'Enter the zip password'

        $arguments = 'x {0} * -p{1} -o{2} -aoa' -f $Path,$ZipPassword,"$PSScriptRoot\Temp\ToolsVHD\GPO"
        Start-Process 'C:\Program Files\7-Zip\7z.exe' -ArgumentList $arguments -NoNewWindow -Wait
    }else{
        WriteErrorAndExit "Unable to unzip $Filename."
    }

# Downloading SCOM Prereqs if its not in ToolsVHD folder
    WriteInfoHighlighted "Testing SCOM Prereqs presence"
    If ( Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\SCOMPrereqs\SQLSysClrTypes2016.msi" ) {
        WriteSuccess "`t SQLSysClrTypes is present, skipping download"
    }else{ 
        WriteInfo "`t SQLSysClrTypes not there - Downloading SQLSysClrTypes 2016"
        try {
            $downloadurl = 'https://download.microsoft.com/download/8/7/2/872BCECA-C849-4B40-8EBE-21D48CDF1456/ENU/x64/SQLSysClrTypes.msi'
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Temp\ToolsVHD\SCOMPrereqs\SQLSysClrTypes2016.msi" -UseBasicParsing
        }catch{
            WriteError "`t Failed to download SQLSysClrTypes 2016!"
        }
    }
    If ( Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\SCOMPrereqs\SQLSysClrTypes2012.msi" ) {
        WriteSuccess "`t SQLSysClrTypes is present, skipping download"
    }else{ 
        WriteInfo "`t SQLSysClrTypes not there - Downloading SQLSysClrTypes 2012"
        try {
            $downloadurl = 'http://go.microsoft.com/fwlink/?LinkID=239644&clcid=0x409'
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Temp\ToolsVHD\SCOMPrereqs\SQLSysClrTypes2012.msi" -UseBasicParsing
        }catch{
            WriteError "`t Failed to download SQLSysClrTypes 2012!"
        }
    }
    If ( Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\SCOMPrereqs\SQLSysClrTypes2014.msi" ) {
        WriteSuccess "`t SQLSysClrTypes is present, skipping download"
    }else{ 
        WriteInfo "`t SQLSysClrTypes not there - Downloading SQLSysClrTypes 2014"
        try {
            $downloadurl = 'https://download.microsoft.com/download/1/3/0/13089488-91FC-4E22-AD68-5BE58BD5C014/ENU/x64/SQLSysClrTypes.msi'
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Temp\ToolsVHD\SCOMPrereqs\SQLSysClrTypes2014.msi" -UseBasicParsing
        }catch{
            WriteError "`t Failed to download SQLSysClrTypes 2014!"
        }
    }
    If ( Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\SCOMPrereqs\ReportViewer.msi" ) {
        WriteSuccess "`t ReportViewer is present, skipping download"
    }else{ 
        WriteInfo "`t ReportViewer not there - Downloading ReportViewer 2015"
        try {
            $downloadurl = 'https://download.microsoft.com/download/A/1/2/A129F694-233C-4C7C-860F-F73139CF2E01/ENU/x86/ReportViewer.msi'
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Temp\ToolsVHD\SCOMPrereqs\ReportViewer.msi" -UseBasicParsing
        }catch{
            WriteError "`t Failed to download ReportViewer 2015!"
        }
    }

# Downloading ATA Upgrade if its not in ToolsVHD folder
    WriteInfoHighlighted "Testing ATA Upgrade 1.9.2 presence"
    If ( Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\ATAUpgrade\ATA1.9.2_Upgrade.exe" ) {
        WriteSuccess "`t ATA1.9.2_Upgrade.exe is present, skipping download"
    }else{ 
        WriteInfo "`t ATA1.9.2_Upgrade.exe not there - Downloading ATA1.9.2_Upgrade.exe"
        try {
            $downloadurl = 'https://download.microsoft.com/download/5/C/6/5C66EF44-2CFC-474A-987A-07681796314B/ATA1.9.2_Upgrade.exe'
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Temp\ToolsVHD\ATAUpgrade\ATA1.9.2_Upgrade.exe" -UseBasicParsing
        }catch{
            WriteError "`t Failed to download ATA1.9.2_Upgrade.exe"
        }
    }


# Downloading SQL Server Management Studio if its not in ToolsVHD folder
    WriteInfoHighlighted "Testing SSMS-Setup-ENU presence"
    If ( Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\SSMS-Setup-ENU.exe" ) {
        WriteSuccess "`t SSMS-Setup-ENU is present, skipping download"
    }else{ 
        WriteInfo "`t SSMS-Setup-ENU not there - Downloading latest SSMS-Setup-ENU"
        $downloadurl = "https://msdn.microsoft.com/en-us/library/mt238290.aspx"
        $url = ((Invoke-WebRequest -uri $downloadurl -UseBasicParsing).Links | Where outerHTML -match "Download SQL Server Management Studio").href | Select -First 1
        $job = Start-BitsTransfer -Source $url -DisplayName SSMS -Destination "$PSScriptRoot\Temp\ToolsVHD\SSMS-Setup-ENU.exe" -Asynchronous
 
        while (($Job.JobState -eq "Transferring") -or ($Job.JobState -eq "Connecting")) { 
            WriteInfo "`t Downloading latest SSMS-Setup-ENU..."
            Start-Sleep 10;
        }
        Switch($Job.JobState) {
            "Transferred" { Complete-BitsTransfer -BitsJob $Job; WriteSuccess "`t Download of the latest SSMS-Setup-ENU completed!" }
            "Error" { $Job | Format-List }
            default { WriteError "`t You need to re-run the script, there is a problem with the proxy or Microsoft has changed the download link!"}
        }
    }


# Downloading ATOM Setup Launcher if its not in ToolsVHD folder
    WriteInfoHighlighted "Testing ATOM Setup Launcher presence"
    If ( Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\ATOM\atom_setup_launcher.exe" ) {
        WriteSuccess "`t ATOM Setup Launcher is present, skipping download"
    }else{ 
        WriteInfo "`t ATOM Setup Launcher not there - Downloading ATOM Setup Launcher"
        try {
            $downloadurl = 'https://www.atom.ms/_download/atom_setup_launcher.exe'
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Temp\ToolsVHD\ATOM\atom_setup_launcher.exe"
        }catch{
            WriteError "`t Failed to download ATOM Setup Launcher!"
        }
    }

# Downloading ATOM Demo Configuration.bin if its not in ToolsVHD folder
    WriteInfoHighlighted "Testing ATOM Configuration.bin presence"
    If ( Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\ATOM\configuration.bin" ) {
        WriteSuccess "`t ATOM Configuration.bin is present, skipping download"
    }else{ 
        WriteInfo "`t ATOM Configuration.bin not there - Downloading Configuration.bin"
        try {
            $downloadurl = 'https://www.atom.ms/_download/configuration.bin'
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Temp\ToolsVHD\ATOM\configuration.bin"
        }catch{
            WriteError "`t Failed to download ATOM Configuration.bin!"
        }
    }

# Downloading sysinternals if its not in ToolsVHD folder
    WriteInfoHighlighted "Testing SysinternalsSuite presence"
    If ( Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\SysinternalsSuite\accesschk.exe" ) {
        WriteSuccess "`t AccessChk is present, skipping download"
    }else{ 
        WriteInfo "`t AccessChk not there - Downloading SysinternalsSuite"
        try {
            $downloadurl = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Temp\ToolsVHD\SysinternalsSuite\SysinternalsSuite.zip"
        }catch{
            WriteError "`t Failed to download SysinternalsSuite!"
        }
        # Unnzipping and extracting
            Expand-Archive "$PSScriptRoot\Temp\ToolsVHD\SysinternalsSuite\SysinternalsSuite.zip" -DestinationPath "$PSScriptRoot\Temp\ToolsVHD\SysinternalsSuite\Unzip"
            Copy-Item -Path (Get-ChildItem -Path "$PSScriptRoot\Temp\ToolsVHD\SysinternalsSuite\Unzip" -Recurse).fullname -Destination "$PSScriptRoot\Temp\ToolsVHD\SysinternalsSuite\"
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\SysinternalsSuite\SysinternalsSuite.zip"
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\SysinternalsSuite\Unzip" -Recurse -Force
    }

# Downloading Kansa if its not in ToolsVHD folder
    WriteInfoHighlighted "Testing Kansa presence"
    If ( Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\Kansa\Kansa.ps1" ) {
        WriteSuccess "`t Kansa is present, skipping download"
    }else{ 
        WriteInfo "`t Kansa not there - Downloading Kansa"
        try {
            $downloadurl = 'https://github.com/davehull/Kansa/archive/master.zip'
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Temp\ToolsVHD\Kansa\Kansa-master.zip"
        }catch{
            WriteError "`t Failed to download Kansa!"
        }
        # Unnzipping and extracting
            Expand-Archive "$PSScriptRoot\Temp\ToolsVHD\Kansa\Kansa-master.zip" -DestinationPath "$PSScriptRoot\Temp\ToolsVHD\Kansa\Unzip"
            Copy-Item -Path "$PSScriptRoot\Temp\ToolsVHD\Kansa\Unzip\Kansa-master\*" -Recurse  -Destination "$PSScriptRoot\Temp\ToolsVHD\Kansa\" -Force
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\Kansa\Kansa-master.zip"
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\Kansa\Unzip" -Recurse -Force
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\Kansa" -Recurse -Include "*.md" -Force
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\Kansa\.gitignore" -Recurse -Force
    }

# Downloading Commando-VM if its not in ToolsVHD folder
    WriteInfoHighlighted "Testing Commando-VM presence"
    If ( Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\Commando-VM\install.ps1" ) {
        WriteSuccess "`t Commando-VM is present, skipping download"
    }else{ 
        WriteInfo "`t Commando-VM not there - Downloading Commando-VM"
        try {
            $downloadurl = 'https://github.com/fireeye/commando-vm/archive/master.zip'
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Temp\ToolsVHD\Commando-VM\Commando-VM-master.zip"
        }catch{
            WriteError "`t Failed to download Commando-VM!"
        }
        # Unnzipping and extracting
            Expand-Archive "$PSScriptRoot\Temp\ToolsVHD\Commando-VM\Commando-VM-master.zip" -DestinationPath "$PSScriptRoot\Temp\ToolsVHD\Commando-VM\Unzip"
            Copy-Item -Path "$PSScriptRoot\Temp\ToolsVHD\Commando-VM\Unzip\Commando-VM-master\*" -Recurse  -Destination "$PSScriptRoot\Temp\ToolsVHD\Commando-VM\" -Force
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\Commando-VM\Commando-VM-master.zip" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\Commando-VM\Unzip" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\Commando-VM" -Recurse -Include "*.md" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\Commando-VM\.gitignore" -Recurse -Force -ErrorAction SilentlyContinue
    }
    
#endregion

# finishing 
WriteInfo "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
Stop-Transcript
WriteSuccess "Press enter to continue..."
Read-Host | Out-Null