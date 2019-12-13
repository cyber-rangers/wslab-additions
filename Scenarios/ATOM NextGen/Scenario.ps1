#0. variables
$ATAVMName = 'S19DE'
$ScriptRoot = 'X:\_Lab'
. "$ScriptRoot\LabConfig.ps1"


$allpassword = $LabConfig.AdminPassword
$domainNetBIOS = $LabConfig.DomainNetbiosName
$domainFQDN = $LabConfig.DomainName
$domainDN = ''; $domainFQDN.split('.') | ForEach-Object {$domainDN += "DC=$_,"}; $domainDN = $domainDN.TrimEnd(',')
$OUPath = "OU=$($LabConfig.DefaultOUName),$domainDN"
$DOMAINADMIN_CREDS = New-Object System.Management.Automation.PSCredential ("$domainNetBIOS\Administrator", $(ConvertTo-SecureString $allpassword -AsPlainText -Force))
$RESEARCHADMIN_CREDS = New-Object System.Management.Automation.PSCredential ("research\Administrator", $(ConvertTo-SecureString $allpassword -AsPlainText -Force))
$ADMIN_CREDS = New-Object System.Management.Automation.PSCredential ("Administrator", $(ConvertTo-SecureString $allpassword -AsPlainText -Force))
try {
    $LocalAdminAccountName = $LabConfig.VMs.GetEnumerator().additionallocaladmin | Select-Object -First 1
    $LOCALADMIN_CREDS = New-Object System.Management.Automation.PSCredential ($LocalAdminAccountName, $(ConvertTo-SecureString $allpassword -AsPlainText -Force))
    }
catch {write-host 'Error defining Local Admin Creds. Probably not defined in labconfig...' -ForegroundColor Yellow}

#start DC VMs
Start-VM -Name "$($LabConfig.Prefix)DC*"
Wait-VM -Name "$($LabConfig.Prefix)DC*" -For Heartbeat
#prep GPOs
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    $path = 'D:\GPO'
    $reportxmls = gci gpreport.xml -path $path -Recurse
    foreach ($reportxml in $reportxmls) {
        [xml]$reportxml_xml = $reportxml | get-content
        New-GPO -Name $($reportxml_xml.gpo.name) -verbose | Out-Null
        Import-GPO -BackupId $($reportxml.FullName | Split-Path -Parent).Split('\')[-1].Replace('{','').Replace('}','') -TargetName $($reportxml_xml.gpo.name) -Path $path -verbose | Out-Null
    }
}
#reconfigure DHCP scope
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    Set-DhcpServerv4Scope -ScopeId 10.0.0.0 -StartRange 10.0.0.10 -EndRange 10.0.0.99
}
#add second domain controller to root domain
Invoke-Command -VMName "$($LabConfig.Prefix)DC2" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    param($domainFQDN)
    Set-ExecutionPolicy Unrestricted -Force -Confirm:$false
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    install-windowsfeature -name RSAT-ADDS-Tools
    New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 10.0.0.2 -DefaultGateway 10.0.0.1 -AddressFamily IPv4 -PrefixLength 24
    Start-Sleep -Seconds 2
    Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses '10.0.0.1','10.0.0.2','127.0.0.1'
    Start-Sleep -Seconds 2
    Clear-DnsClientCache
    Start-Sleep -Seconds 2
    Install-ADDSDomainController -CreateDnsDelegation:$false -DomainName $domainFQDN -InstallDns:$true -SafeModeAdministratorPassword $(ConvertTo-SecureString -String 'P@ssw0rd' -AsPlainText -Force) -NoGlobalCatalog:$false -NoRebootOnCompletion:$true -Force:$true
} -ArgumentList $domainFQDN
Restart-VM -Name "$($LabConfig.Prefix)DC2" -Wait -For Heartbeat -Confirm:$false -Force
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses '10.0.0.2','10.0.0.1','127.0.0.1'
    Clear-DnsClientCache
}

#add subdomain
Invoke-Command -VMName "$($LabConfig.Prefix)DCX" -Credential $ADMIN_CREDS -ScriptBlock {
    Set-ExecutionPolicy Unrestricted -Force -Confirm:$false
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 10.0.0.3 -DefaultGateway 10.0.0.1 -AddressFamily IPv4 -PrefixLength 24
    Start-Sleep -Seconds 2
    Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses '10.0.0.3','10.0.0.1','10.0.0.2','127.0.0.1'
    Start-Sleep -Seconds 2
    Clear-DnsClientCache
    Start-Sleep -Seconds 2
    Install-ADDSDomain -CreateDnsDelegation:$true -ParentDomainName $using:domainFQDN -NewDomainName 'research' -Credential $using:DOMAINADMIN_CREDS -InstallDns:$true -SafeModeAdministratorPassword $(ConvertTo-SecureString -String 'P@ssw0rd' -AsPlainText -Force) -NoGlobalCatalog:$false -NoRebootOnCompletion:$true -Force:$true
}
Restart-VM -Name "$($LabConfig.Prefix)DCX" -Wait -For Heartbeat -Confirm:$false -Force
#todo fix dns zones!

#start remaining VMs and wait for them
Start-VM -Name "$($LabConfig.Prefix)*"
Wait-VM -Name "$($LabConfig.Prefix)*" -For Heartbeat

#Prep-Empty-CA.ps1

#Prepare ATA
Invoke-Command -VMName "$($LabConfig.Prefix)$ATAVMName" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
Invoke-Command -VMName "$($LabConfig.Prefix)$ATAVMName" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    choco install googlechrome -y
    }
Invoke-Command -VMName "$($LabConfig.Prefix)$ATAVMName" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    netsh advfirewall set allprofiles state off
    }

Invoke-Command -VMName "$($LabConfig.Prefix)$ATAVMName" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    Get-Disk | ? IsOffline | Set-Disk -IsOffline:$false | Set-Disk -IsReadOnly:$false | Out-Null
    Get-ScheduledTask "ServerManager" | Disable-ScheduledTask | Out-Null
    $arguments = '/q --LicenseAccepted NetFrameworkCommandLineArguments="/q"'
    Start-Process "D:\ATA\Microsoft ATA Center Setup.exe" -ArgumentList $arguments.Split(" ") -WorkingDirectory 'D:\ATA' -NoNewWindow -Wait
}

Invoke-Command -VMName "$($LabConfig.Prefix)$ATAVMName" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    param($AdministrativeAccountDomainName,$AdministrativeAccountPassword)
    Get-Disk | ? IsOffline | Set-Disk -IsOffline:$false | Set-Disk -IsReadOnly:$false | Out-Null
    Get-ScheduledTask "ServerManager" | Disable-ScheduledTask | Out-Null
    $arguments = '/q NetFrameworkCommandLineArguments="/q" AdministrativeAccountName="{0}\Administrator" AdministrativeAccountPassword="{1}"' -f $AdministrativeAccountDomainName,$AdministrativeAccountPassword
    Start-Process "D:\ATAUpgrade\ATA1.9.2_Upgrade.exe" -ArgumentList $arguments.Split(" ") -WorkingDirectory 'D:\ATAUpgrade' -NoNewWindow -Wait
} -ArgumentList $domainNetBIOS,$allpassword

Write-Host 'To install ATA Lightweight Gateway silently (on Core for example) use the following command:' -ForegroundColor Yellow
Write-Host $('"Microsoft ATA Gateway Setup.exe" /quiet NetFrameworkCommandLineArguments="/q" ConsoleAccountName="{0}" ConsoleAccountPassword="{1}"' -f "$domainNetBIOS\Administrator",$allpassword) -ForegroundColor Black -BackgroundColor White

#6. ATOM agent downloads
foreach ($LabVM in $(Get-VM -Name "$($LabConfig.Prefix)*"))
{
	if ($(Invoke-Command -Verbose -VMName $LabVM.Name -Credential $DOMAINADMIN_CREDS -ScriptBlock { $true }) -eq $true)
	{
		Invoke-Command -Verbose -VMName $LabVM.Name -Credential $DOMAINADMIN_CREDS -ScriptBlock {
			$PSMajorVersion = $PSVersionTable.PSVersion.Major;
			$LocalFolder = "C:\ATOM-PWSH$PSMajorVersion";
			New-Item -ItemType Directory -Path $LocalFolder;
			$(New-Object -TypeName System.Net.WebClient).DownloadFile("https://www.atom.ms/_download/configuration-marek.bin", "$LocalFolder\configuration.bin");
			$(New-Object -TypeName System.Net.WebClient).DownloadFile("https://www.atom.ms/_download/_pwsh$PSMajorVersion/atom_setup_launcher.exe", "$LocalFolder\atom_setup_launcher.exe");
			$(New-Object -TypeName System.Net.WebClient).DownloadFile("https://www.atom.ms/_download/atom_setup_launcher.exe", "$LocalFolder\atom_setup_launcher_old.exe");
			$(New-Object -TypeName System.Net.WebClient).DownloadFile("https://www.atom.ms/_download/_pwsh2/atom_setup.exe", "$LocalFolder\atom_setup2.exe");
			$(New-Object -TypeName System.Net.WebClient).DownloadFile("https://www.atom.ms/_download/_pwsh3/atom_setup.exe", "$LocalFolder\atom_setup3.exe");
			$(New-Object -TypeName System.Net.WebClient).DownloadFile("https://www.atom.ms/_download/_pwsh5/atom_setup.exe", "$LocalFolder\atom_setup5.exe");
			New-Item -ItemType File -Path $LocalFolder -Name 'atom_setup_launcher.exe.private';
			'm706a661a403e166' | Out-File "$LocalFolder\atom-license-marek.txt";
		}
	}
	else
	{
		Write-Output "VM $($LabVM.Name) probably does not support Powershell direct..."
	}
}

#7. Install ATOM Agents
foreach ($LabVM in $(Get-VM -Name "$($LabConfig.Prefix)*"))
{
	if ($(Invoke-Command -Verbose -VMName $LabVM.Name -Credential $DOMAINADMIN_CREDS -ScriptBlock { $true }) -eq $true)
	{
		Invoke-Command -Verbose -VMName $LabVM.Name -Credential $DOMAINADMIN_CREDS -ScriptBlock {
			$PSMajorVersion = $PSVersionTable.PSVersion.Major;
			$LocalFolder = "C:\ATOM-PWSH$PSMajorVersion";
			Set-Location $LocalFolder
			Set-ExecutionPolicy Bypass -Scope Process -Force; (New-Object System.Net.WebClient).DownloadFile('https://www.atom.ms/_download/atom_setup_helper.ps1', "$((Get-Location).path)\atom_setup_helper.ps1"); & "$((Get-Location).path)\atom_setup_helper.ps1" -Unattended -AcceptEULA -ProductKey m706a661a403e166 -ProductBranch Public
		}
	}
	else
	{
		Write-Output "VM $($LabVM.Name) probably does not support Powershell direct..."
	}
}

#8. Reconfigure ATOM Agents to different brach
$ATOMBranch = 'private'
foreach ($LabVM in $(Get-VM -Name "$($LabConfig.Prefix)*"))
{
	if ($(Invoke-Command -Verbose -VMName $LabVM.Name -Credential $DOMAINADMIN_CREDS -ScriptBlock { $true }) -eq $true)
	{
		Invoke-Command -Verbose -VMName $LabVM.Name -Credential $DOMAINADMIN_CREDS -ArgumentList $ATOMBranch -ScriptBlock {
			param($ATOMBranch)
			Set-ItemProperty -Path HKLM:\SOFTWARE\ATOM\Agent -Name ATOMBranch -Value $ATOMBranch
		}
	}
	else
	{
		Write-Output "VM $($LabVM.Name) probably does not support Powershell direct..."
	}
}


#8. Disable Firewall
foreach ($LabVM in $(Get-VM -Name "$($LabConfig.Prefix)*")) {
    if ($(Invoke-Command -Verbose  -VMName $LabVM.Name -Credential $DOMAINADMIN_CREDS -ScriptBlock {$true}) -eq $true) {
		Invoke-Command -Verbose  -VMName $LabVM.Name -Credential $DOMAINADMIN_CREDS -ScriptBlock {
            netsh advfirewall set allprofiles state off
        }
    } else {
        Write-Output "VM $($LabVM.Name) probably does not support Powershell direct..."
    }
}