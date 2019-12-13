###################################
#Scenario - finish lab preparation#
###################################

#variables definition
$ATAVMName = 'DETECTION'
$ScriptRoot = 'X:\WSLab'
$allpassword = 'P@ssw0rd'
$domainNetBIOS = 'RANGERS'
$domainFQDN = 'cyber-rangers.lab'
$OUPath = 'ou=lab,dc=cyber-rangers,dc=lab'
$CYBERRANGERS_CREDS = New-Object System.Management.Automation.PSCredential ("$domainNetBIOS\Administrator", $(ConvertTo-SecureString $allpassword -AsPlainText -Force))
$LOCALADMIN_CREDS = New-Object System.Management.Automation.PSCredential ('LocalAdmin', $(ConvertTo-SecureString $allpassword -AsPlainText -Force))

#Run the following code on host
. "$ScriptRoot\LabConfig.ps1"
Start-VM -Name "$($LabConfig.Prefix)*"
Wait-VM -Name "$($LabConfig.Prefix)*" -For Heartbeat

#Run the following code on host
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    $path = 'D:\GPO'
    $reportxmls = gci gpreport.xml -path $path -Recurse
    foreach ($reportxml in $reportxmls) {
        [xml]$reportxml_xml = $reportxml | get-content
        New-GPO -Name $($reportxml_xml.gpo.name) -verbose | Out-Null
        Import-GPO -BackupId $($reportxml.FullName | Split-Path -Parent).Split('\')[-1].Replace('{','').Replace('}','') -TargetName $($reportxml_xml.gpo.name) -Path $path -verbose | Out-Null
    }
}
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    Set-DhcpServerv4Scope -ScopeId 10.0.0.0 -StartRange 10.0.0.10 -EndRange 10.0.0.99
}
Invoke-Command -VMName "$($LabConfig.Prefix)DC2" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    param($domainFQDN)
    Set-ExecutionPolicy Unrestricted -Force -Confirm:$false
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 10.0.0.2 -DefaultGateway 10.0.0.1 -AddressFamily IPv4 -PrefixLength 24
    Start-Sleep -Seconds 2
    Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses '10.0.0.1','10.0.0.2','127.0.0.1'
    Start-Sleep -Seconds 2
    Clear-DnsClientCache
    Start-Sleep -Seconds 2
    Install-ADDSDomainController -CreateDnsDelegation:$false -DomainName $domainFQDN -InstallDns:$true -SafeModeAdministratorPassword $(ConvertTo-SecureString -String 'P@ssw0rd' -AsPlainText -Force) -NoGlobalCatalog:$false -NoRebootOnCompletion:$true -Force:$true
} -ArgumentList $domainFQDN
Restart-VM -Name "$($LabConfig.Prefix)DC2" -Wait -For Heartbeat
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses '10.0.0.2','10.0.0.1','127.0.0.1'
    Clear-DnsClientCache
}


#Run the following code inside ATTACK-WIN10 VM
Set-ExecutionPolicy unrestricted;D:\SysinternalsSuite\autologon.exe localadmin localhost 'P@ssw0rd' /accepteula;D:\Commando-VM\install.ps1 -password P@ssw0rd -nocheck $true

#Run the following code inside PARTNER-DC
set-executionpolicy unrestricted -force -confirm:$false
cmd /c netsh interface ip set address "Local Area Connection" static 10.0.0.101 255.255.255.0 10.0.0.1
cmd /c netsh interface ip add dns "Local Area Connection" 10.0.0.1
. D:\Scripts\Install-TAFirst2008R2DomainController.ps1
Install-TAFirst2008R2DomainController -Domain partner.lab -NetBiosDomainName PARTNER -ADSite 'Nebrasca' -Domainlevel 4 -ForestLevel 4 -DSSafeModePassword 'P@ssw0rd'
#!!! wait for PARTNER-DC to have ADDC running

#Run the following code inside PARTNER-WEB
set-executionpolicy unrestricted -force -confirm:$false
cmd /c netsh interface ip set address "Local Area Connection" static 10.0.0.102 255.255.255.0 10.0.0.1
cmd /c netsh interface ip add dns "Local Area Connection" 10.0.0.101
Add-Computer -DomainName partner.lab -Credential $(New-Object System.Management.Automation.PSCredential('PARTNER\Administrator',$(ConvertTo-SecureString -asPlainText -Force -String 'P@ssw0rd')))
Restart-Computer

#Run the following code inside PARTNER-CL72
set-executionpolicy unrestricted -force -confirm:$false
cmd /c netsh interface ip set address "Local Area Connection" static 10.0.0.103 255.255.255.0 10.0.0.1
cmd /c netsh interface ip add dns "Local Area Connection" 10.0.0.101
Add-Computer -DomainName partner.lab -Credential $(New-Object System.Management.Automation.PSCredential('PARTNER\Administrator',$(ConvertTo-SecureString -asPlainText -Force -String 'P@ssw0rd')))
Restart-Computer

#Run the following code inside ATTACK-KALI (root/P@ssw0rd)
apt-get clean
apt-get update
apt-get upgrade -y

#region LAPS
#Run the following code on host
foreach ($TEMP_CL10VM in $(get-vm "$($LabConfig.Prefix)CL10*" | Select-Object -ExpandProperty name)) {
    Invoke-Command -VMName $TEMP_CL10VM -Credential $CYBERRANGERS_CREDS -ScriptBlock {
        net user Administrator P@ssw0rd
        net user Administrator /active:yes
    }
}

foreach ($TEMP_CL10VM in $(get-vm "$($LabConfig.Prefix)CL10*" | Select-Object -ExpandProperty name)) {
    Invoke-Command -VMName $TEMP_CL10VM -Credential $CYBERRANGERS_CREDS -ScriptBlock {
        netsh advfirewall set allprofiles state off
    }
}

foreach ($TEMP_CL10VM in $(get-vm "$($LabConfig.Prefix)CL10*" | Select-Object -ExpandProperty name)) {
    Invoke-Command -VMName $TEMP_CL10VM -Credential $CYBERRANGERS_CREDS -ScriptBlock {
        gpupdate /force
    }
}

Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    #download LAPS install file x64
    Invoke-WebRequest -UseBasicParsing -Uri 'https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/LAPS.x64.msi' -OutFile "$env:UserProfile\Downloads\LAPS.x64.msi"

    #optional: download documentation
    "LAPS_TechnicalSpecification.docx","LAPS_OperationsGuide.docx" | ForEach-Object {
        Invoke-WebRequest -UseBasicParsing -Uri "https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/$_" -OutFile "$env:UserProfile\Downloads\$_"
    }
}

Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    Add-ADGroupMember -Identity "Schema Admins" -Members CorpAdmin
    Add-ADGroupMember -Identity "Enterprise Admins" -Members CorpAdmin
    }

Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    param($OUPath)
    #install PowerShell management tools, Management UI and copy ADMX template to policy store on management machine
    Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\LAPS.x64.msi ADDLOCAL=Management.PS,Management.ADMX,Management.UI /q"

}

 Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    param($OUPath)
    #Create LAPS groups 
        #create groups
        New-ADGroup -Name LAPS_Readers -GroupScope Global -Path $OUPath
        New-ADGroup -Name LAPS_Resetters -GroupScope Global -Path $OUPath

        Add-ADGroupMember -Identity LAPS_Readers   -Members CorpAdmin
    Add-ADGroupMember -Identity LAPS_Resetters -Members CorpAdmin

    #create empty GPO
    New-Gpo -Name 'LAPS' | New-GPLink -Target $OUPath

    #extend AD schema (Schema Admins and Enterprise Admins membership needed)
    Update-AdmPwdADSchema
    
        #Add machine rights to report passwords to AD
        Set-AdmPwdComputerSelfPermission -Identity $OUPath

        #User perms to read and reset passwords
        Set-AdmPwdReadPasswordPermission -Identity $OUPath -AllowedPrincipals LAPS_Readers
        Set-AdmPwdResetPasswordPermission -Identity $OUPath -AllowedPrincipals LAPS_Resetters
    } -ArgumentList $OUPath

#only to fix Winrm and install choco
foreach ($TEMP_CL10VM in $(get-vm "$($LabConfig.Prefix)CL10*" | Select-Object -ExpandProperty name)) {
    Invoke-Command -VMName $TEMP_CL10VM -Credential $CYBERRANGERS_CREDS -ScriptBlock {
        winrm qc -quiet
    }
    Invoke-Command -VMName $TEMP_CL10VM -Credential $CYBERRANGERS_CREDS -ScriptBlock {
        Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
}

#install choco chrome
foreach ($TEMP_CL10VM in $(get-vm "$($LabConfig.Prefix)CL10*" | Select-Object -ExpandProperty name)) {
    Invoke-Command -VMName $TEMP_CL10VM -Credential $CYBERRANGERS_CREDS -ScriptBlock {
        choco install googlechrome -y
    }
}



Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    $Sessions=New-PSSession -ComputerName $(Get-ADComputer -Filter * | Where-Object {$_.name -like "CL10*"} | Select-Object -ExpandProperty Name)

    foreach ($session in $sessions){
        Copy-Item -Path $env:UserProfile\Downloads\LAPS.x64.msi -ToSession $session -Destination $env:temp
    }

    Invoke-Command -Session $sessions -ScriptBlock {
        Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:temp\LAPS.x64.msi /q"
    }
}
#endregion LAPS

#region MONITORING
#Run the following code on host

#SCOMSQL
$SQLServer2016SetupConfigSCOM = @"
;SQL Server 2016 Configuration File
[OPTIONS]

ACTION="Install"
SUPPRESSPRIVACYSTATEMENTNOTICE="True"
IACCEPTROPENLICENSETERMS="True"
ENU="True"
QUIET="True"
QUIETSIMPLE="False"
UpdateEnabled="False"
USEMICROSOFTUPDATE="False"

FEATURES=SQLENGINE,FULLTEXT,RS

UpdateSource="MU"
HELP="False"
INDICATEPROGRESS="False"
X86="False"

INSTANCENAME="MSSQLSERVER"
INSTALLSHAREDDIR="C:\Program Files\Microsoft SQL Server"
INSTALLSHAREDWOWDIR="C:\Program Files (x86)\Microsoft SQL Server"
INSTANCEID="MSSQLSERVER"

SQLTELSVCACCT="NT Service\SQLTELEMETRY"
SQLTELSVCSTARTUPTYPE="Automatic"

INSTANCEDIR="C:\Program Files\Microsoft SQL Server"

AGTSVCACCOUNT="$domainNetBIOS\SQL_Agent"
AGTSVCPASSWORD="P@ssw0rd"
AGTSVCSTARTUPTYPE="Automatic"

COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL="0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"

SQLSVCSTARTUPTYPE="Automatic"

FILESTREAMLEVEL="0"
ENABLERANU="False"

SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"

SQLSVCACCOUNT="$domainNetBIOS\SQL_SA"
SQLSVCPASSWORD="P@ssw0rd"
SQLSVCINSTANTFILEINIT="False"

SQLSYSADMINACCOUNTS="$domainNetBIOS\Domain Admins"

SQLTEMPDBFILECOUNT="6"
SQLTEMPDBFILESIZE="8"
SQLTEMPDBFILEGROWTH="64"
SQLTEMPDBLOGFILESIZE="8"
SQLTEMPDBLOGFILEGROWTH="64"

ADDCURRENTUSERASSQLADMIN="False"

TCPENABLED="1"
NPENABLED="0"

BROWSERSVCSTARTUPTYPE="Automatic"

RSSVCACCOUNT="$domainNetBIOS\SQL_SA"
RSSVCPASSWORD="P@ssw0rd"
RSSVCSTARTUPTYPE="Automatic"
RSINSTALLMODE="DefaultNativeMode"
"@

#prepare MONITORING
Invoke-Command -VMName "$($LabConfig.Prefix)MONITORING" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
Invoke-Command -VMName "$($LabConfig.Prefix)MONITORING" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    choco install googlechrome -y
    }
Invoke-Command -VMName "$($LabConfig.Prefix)MONITORING" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
Install-WindowsFeature -Name "NET-Framework-Features", "NET-Framework-Core", "Web-WebServer", "Web-Mgmt-Console", "Web-Default-Doc", "Web-Dir-Browsing", "Web-Http-Errors", "Web-Http-Logging", "Web-Request-Monitor", "Web-Static-Content", "Web-Stat-Compression", "Web-Filtering", "Web-Windows-Auth", "Web-Metabase", "Web-asp-Net45", "NET-WCF-HTTP-Activation45", "Web-Asp-Net" -Source 'C:\sxs' -IncludeManagementTools
}
Restart-VM -Name "$($LabConfig.Prefix)MONITORING" -Wait -For Heartbeat

Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    do {start-sleep 5; New-ADUser `
        -Name "scom.msaa" `
        -SamAccountName  "scom.msaa" `
        -DisplayName "scom.msaa" `
        -AccountPassword (ConvertTo-SecureString $using:allpassword -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -ea 0
        } until ($?)
    do {start-sleep 5; New-ADUser `
        -Name "scom.dr" `
        -SamAccountName  "scom.dr" `
        -DisplayName "scom.dr" `
        -AccountPassword (ConvertTo-SecureString $using:allpassword -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -ea 0
        } until ($?)
    do {start-sleep 5; New-ADUser `
        -Name "scom.dw" `
        -SamAccountName  "scom.dw" `
        -DisplayName "scom.dw" `
        -AccountPassword (ConvertTo-SecureString $using:allpassword -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -ea 0
        } until ($?)
    do {start-sleep 5; New-ADUser `
        -Name "scom.sdkcfg" `
        -SamAccountName  "scom.sdkcfg" `
        -DisplayName "scom.sdkcfg" `
        -AccountPassword (ConvertTo-SecureString $using:allpassword -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -ea 0
        } until ($?)
}
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    do {start-sleep 5; new-adgroup `
        -GroupCategory Security `
        -GroupScope DomainLocal `
        -Name 'SCOM-Administrators' `
        -DisplayName 'SCOM-Administrators' `
        -SamAccountName 'SCOM-Administrators' `
        -ea 0
        } until ($?)
    Add-ADGroupMember "SCOM-Administrators" "CorpAdmin"
}
Invoke-Command -VMName "$($LabConfig.Prefix)MONITORING" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    param($domainName)
    net localgroup Administrators "$($domainName)\scom.sdkcfg" /add
    net localgroup Administrators "$($domainName)\scom.msaa" /add
} -ArgumentList $domainNetBIOS

'Installing SCOM prerequisites and SQL Server'
Invoke-Command -VMName "$($LabConfig.Prefix)MONITORING" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    param($SQLServer2016SetupConfig,$IAcceptSqlLicenseTerms,$domainAdminPassword)
    Get-Disk | ? IsOffline | Set-Disk -IsOffline:$false | Set-Disk -IsReadOnly:$false | Out-Null
    Get-ScheduledTask "ServerManager" | Disable-ScheduledTask | Out-Null
    cmd.exe /c start /w D:\SCOMPrereqs\SQLSysClrTypes2014.msi /qn /norestart ALLUSERS=2
    $SQLServer2016SetupConfig | Out-File C:\Sql2016ConfigurationFile.ini
    [string]$arguments = "/QUIET /CONFIGURATIONFILE=C:\Sql2016ConfigurationFile.ini /ACTION=Install $IAcceptSqlLicenseTerms"
    Start-Process "D:\SCVMM\SQL\setup.exe" -ArgumentList $arguments.Split(" ") -WorkingDirectory 'D:\SCVMM\SQL' -NoNewWindow -Wait
    $arguments = "/install /quiet /norestart"
    Start-Process "D:\SSMS-Setup-ENU.exe" -ArgumentList $arguments.Split(" ") -WorkingDirectory 'D:\' -NoNewWindow -Wait #dat to tam
    cmd.exe /c start /w D:\SCOMPrereqs\ReportViewer.msi /qn
} -ArgumentList $SQLServer2016SetupConfigSCOM,"/IACCEPTSQLSERVERLICENSETERMS",'P@ssw0rd'

Restart-VM -Name "$($LabConfig.Prefix)MONITORING" -Wait -For Heartbeat

Invoke-Command -VMName "$($LabConfig.Prefix)MONITORING" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    param($domainAdminPassword,$domainName)
    $roles = 'OMServer,OMConsole,OMWebConsole,OMReporting'
    $mgmtGroup = 'SCOM-MG'
    $sqlInstance = 'MONITORING'
    $scomOperationDB = 'OperationsManager'
    $scomDataWarehouseDB = 'OperationsManagerDW'
    $actionAcc = "$($domainName)\scom.msaa"
    $actionAccPwd = $domainAdminPassword
    $dasAcc = "$($domainName)\scom.sdkcfg"
    $dasAccPwd = $domainAdminPassword
    $dataReaderAcc = "$($domainName)\scom.dr"
    $dataReaderAccPwd = $domainAdminPassword
    $dataWriterAcc = "$($domainName)\scom.dw"
    $dataWriterAccPwd = $domainAdminPassword
    $arguments = '/Silent /Install /Components:{0} /ManagementGroupName:{1} /SqlServerInstance:{2} /DatabaseName:{3} /DWSqlServerInstance:{2} /DWDatabaseName:{4} /ActionAccountUser:{5} /ActionAccountPassword:{6} /DASAccountUser:{7} /DASAccountPassword:{8} /DataReaderUser:{9} /DataReaderPassword:{10} /DataWriterUser:{11} /DataWriterPassword:{12} /SRSInstance:{13} /WebSiteName:"Default Web Site" /WebConsoleAuthorizationMode:Mixed /EnableErrorReporting:Never /SendCEIPReports:0 /SendODRReports:0 /UseMicrosoftUpdate:0 /AcceptEndUserLicenseAgreement:1' -f $roles, $mgmtGroup, $sqlInstance, $scomOperationDB, $scomDataWarehouseDB, $actionAcc, $actionAccPwd, $dasAcc, $dasAccPwd, $dataReaderAcc, $dataReaderAccPwd, $dataWriterAcc, $dataWriterAccPwd, $sqlInstance
    Start-Process "D:\SCOM\setup.exe" -ArgumentList $arguments.Split(" ") -WorkingDirectory 'D:\SCOM' -NoNewWindow -Wait
    While (Get-Process 'Setup' -ErrorAction SilentlyContinue | where-object {$_.description -eq 'System Center 2016 Operations Manager Bootstrapper'} ) #nebude to jinak s 2019?
    {
        Write-Host "." -NoNewline -ForegroundColor Magenta
        Start-Sleep -Seconds 5
    }
} -ArgumentList $allpassword,$domainNetBIOS

Invoke-Command -VMName "$($LabConfig.Prefix)MONITORING" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    param($domainName)
    Import-Module "$env:ProgramFiles\Microsoft System Center 2016\Operations Manager\Powershell\OperationsManager\OperationsManager.psm1"
    $scomAdminsRole = Get-SCOMUserRole | ? { $_.Name -eq 'OperationsManagerAdministrators' }
    Set-SCOMUserRole -UserRole $scomAdminsRole -User ($scomAdminsRole.Users + "$($domainName)\SCOM-Administrators")
} -argumentlist $domainNetBIOS
#endregion MONITORING

#region ATA
#Run the following code on host
Invoke-Command -VMName "$($LabConfig.Prefix)$ATAVMName" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
Invoke-Command -VMName "$($LabConfig.Prefix)$ATAVMName" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    choco install googlechrome -y
    }
Invoke-Command -VMName "$($LabConfig.Prefix)$ATAVMName" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    netsh advfirewall set allprofiles state off
    }

Invoke-Command -VMName "$($LabConfig.Prefix)$ATAVMName" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    Get-Disk | ? IsOffline | Set-Disk -IsOffline:$false | Set-Disk -IsReadOnly:$false | Out-Null
    Get-ScheduledTask "ServerManager" | Disable-ScheduledTask | Out-Null
    $arguments = '/q --LicenseAccepted NetFrameworkCommandLineArguments="/q"'
    Start-Process "D:\ATA\Microsoft ATA Center Setup.exe" -ArgumentList $arguments.Split(" ") -WorkingDirectory 'D:\ATA' -NoNewWindow -Wait
}

Invoke-Command -VMName "$($LabConfig.Prefix)$ATAVMName" -Credential $CYBERRANGERS_CREDS -ScriptBlock {
    param($AdministrativeAccountDomainName,$AdministrativeAccountPassword)
    Get-Disk | ? IsOffline | Set-Disk -IsOffline:$false | Set-Disk -IsReadOnly:$false | Out-Null
    Get-ScheduledTask "ServerManager" | Disable-ScheduledTask | Out-Null
    $arguments = '/q NetFrameworkCommandLineArguments="/q" AdministrativeAccountName="{0}\Administrator" AdministrativeAccountPassword="{1}"' -f $AdministrativeAccountDomainName,$AdministrativeAccountPassword
    Start-Process "D:\ATAUpgrade\ATA1.9.2_Upgrade.exe" -ArgumentList $arguments.Split(" ") -WorkingDirectory 'D:\ATAUpgrade' -NoNewWindow -Wait
} -ArgumentList $domainNetBIOS,$allpassword

Write-Host 'To install ATA Lightweight Gateway silently (on Core for example) use the following command:' -ForegroundColor Yellow
Write-Host $('"Microsoft ATA Gateway Setup.exe" /quiet NetFrameworkCommandLineArguments="/q" ConsoleAccountName="{0}" ConsoleAccountPassword="{1}"' -f "$domainNetBIOS\Administrator",$allpassword) -ForegroundColor Black -BackgroundColor White
#endregion ATA