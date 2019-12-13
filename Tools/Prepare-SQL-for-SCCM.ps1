#####################################
#Scenario - SQL for SCCM preparation#
#####################################

# run on the host and from the lab deployment folder!

#variables definition
$SQLComputerNetBIOSName = 'SCCM1'



. ".\LabConfig.ps1"
$SQLVMName = "$($LabConfig.prefix)$SQLComputerNetBIOSName"
$allpassword = $LabConfig.AdminPassword
$domainNetBIOS = $LabConfig.DomainNetbiosName
$domainFQDN = $LabConfig.DomainName
$domainDN = ''; $domainFQDN.split('.') | ForEach-Object {$domainDN += "DC=$_,"}; $domainDN = $domainDN.TrimEnd(',')
$OUPath = "DC=$($LabConfig.DefaultOUName),$domainDN"
$LocalAdminAccountName = $LabConfig.VMs.GetEnumerator().additionallocaladmin | Select-Object -First 1
$DOMAINADMIN_CREDS = New-Object System.Management.Automation.PSCredential ("$domainNetBIOS\Administrator", $(ConvertTo-SecureString $allpassword -AsPlainText -Force))



$SQLServer2016SetupConfigSCCM = @"
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
AGTSVCPASSWORD="$allpassword"
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
SQLSVCPASSWORD="$allpassword"
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
RSSVCPASSWORD="$allpassword"
RSSVCSTARTUPTYPE="Automatic"
RSINSTALLMODE="DefaultNativeMode"
"@


start-vm -Name $SQLVMName
wait-vm -Name $SQLVMName -For Heartbeat

Invoke-Command -VMName $SQLVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    netsh advfirewall set allprofiles state off
}
Invoke-Command -VMName $SQLVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    param($SQLServer2016SetupConfig,$IAcceptSqlLicenseTerms,$domainAdminPassword)
    Get-Disk | ? IsOffline | Set-Disk -IsOffline:$false | Set-Disk -IsReadOnly:$false | Out-Null
    Get-ScheduledTask "ServerManager" | Disable-ScheduledTask | Out-Null
    $SQLServer2016SetupConfig | Out-File C:\Sql2016ConfigurationFile.ini
    [string]$arguments = "/QUIET /CONFIGURATIONFILE=C:\Sql2016ConfigurationFile.ini /ACTION=Install $IAcceptSqlLicenseTerms"
    Start-Process "D:\SCVMM\SQL\setup.exe" -ArgumentList $arguments.Split(" ") -WorkingDirectory 'D:\SCVMM\SQL' -NoNewWindow -Wait
    $arguments = "/install /quiet /norestart"
    Start-Process "D:\SSMS-Setup-ENU.exe" -ArgumentList $arguments.Split(" ") -WorkingDirectory 'D:\' -NoNewWindow -Wait #dat to tam
} -ArgumentList $SQLServer2016SetupConfigSCCM,"/IACCEPTSQLSERVERLICENSETERMS",$allpassword
