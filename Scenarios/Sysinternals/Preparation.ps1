###################################
#Scenario - finish lab preparation#
###################################


# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    exit
}


write-host -ForegroundColor Yellow -Object 'Loading variables'
#variables definition

do {$ScriptRoot = Read-Host 'Enter the path of folder containing the lab (i.e. E:\WSLab)'
    if (!$(Test-Path -path $(Join-Path $ScriptRoot 'labconfig.ps1'))) {
        write-host -ForegroundColor Red -Object "Cannot find $(Join-Path $ScriptRoot 'labconfig.ps1'). Select the right lab folder!"
    }
}
until (Test-Path -path $(Join-Path $ScriptRoot 'labconfig.ps1'))
write-host -ForegroundColor Yellow -Object 'Loading labconfig variables'
. "$ScriptRoot\LabConfig.ps1"


$allpassword = $LabConfig.AdminPassword
$domainNetBIOS = $LabConfig.DomainNetbiosName
$domainFQDN = $LabConfig.DomainName
$domainDN = ''; $domainFQDN.split('.') | ForEach-Object {$domainDN += "DC=$_,"}; $domainDN = $domainDN.TrimEnd(',')
$OUPath = "OU=$($LabConfig.DefaultOUName),$domainDN"
$LocalAdminAccountName = $LabConfig.VMs.GetEnumerator().additionallocaladmin | Select-Object -First 1
$DOMAINADMIN_CREDS = New-Object System.Management.Automation.PSCredential ("$domainNetBIOS\Administrator", $(ConvertTo-SecureString $allpassword -AsPlainText -Force))
$LOCALADMIN_CREDS = New-Object System.Management.Automation.PSCredential ($LocalAdminAccountName, $(ConvertTo-SecureString $allpassword -AsPlainText -Force))
$VMs_Win10Domain = Get-VM -Name "$($LabConfig.Prefix)CL10*" | Where-Object {$_.name -notlike "*WG"} | Select-Object -ExpandProperty Name

write-host -ForegroundColor Yellow -Object 'Preparing secondary DC'
#region domain
Start-VM -Name "$($LabConfig.Prefix)DC"
Wait-VM -Name "$($LabConfig.Prefix)DC" -For Heartbeat
Start-VM -Name "$($LabConfig.Prefix)DC2"
Wait-VM -Name "$($LabConfig.Prefix)DC2" -For Heartbeat

Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    $path = 'D:\GPO'
    $reportxmls = gci gpreport.xml -path $path -Recurse
    foreach ($reportxml in $reportxmls) {
        [xml]$reportxml_xml = $reportxml | get-content
        New-GPO -Name $($reportxml_xml.gpo.name) -verbose | Out-Null
        Import-GPO -BackupId $($reportxml.FullName | Split-Path -Parent).Split('\')[-1].Replace('{','').Replace('}','') -TargetName $($reportxml_xml.gpo.name) -Path $path -verbose | Out-Null
    }
}
Invoke-Command -VMName "$($LabConfig.Prefix)DC2" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    param($domainFQDN)
    Set-ExecutionPolicy Unrestricted -Force -Confirm:$false
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 10.0.0.2 -DefaultGateway 10.0.0.1 -AddressFamily IPv4 -PrefixLength 24
    Start-Sleep -Seconds 2
    Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses '10.0.0.1','10.0.0.2','127.0.0.1' -Verbose
    Start-Sleep -Seconds 2
    Clear-DnsClientCache -Verbose
    Start-Sleep -Seconds 2
    Install-ADDSDomainController -CreateDnsDelegation:$false -DomainName $domainFQDN -InstallDns:$true -SafeModeAdministratorPassword $(ConvertTo-SecureString -String 'P@ssw0rd' -AsPlainText -Force) -NoGlobalCatalog:$false -NoRebootOnCompletion:$true -Force:$true
} -ArgumentList $domainFQDN
Restart-VM -Name "$($LabConfig.Prefix)DC2" -Wait -For Heartbeat -Force
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses '10.0.0.2','10.0.0.1','127.0.0.1' -Verbose
    Clear-DnsClientCache -Verbose
}
#endregion domain

write-host -ForegroundColor Yellow -Object 'Starting remaining VMs'
Start-VM -Name "$($LabConfig.Prefix)*"
Wait-VM -Name "$($LabConfig.Prefix)*" -For Heartbeat

#manually disable sign in animation using domain GPO

write-host -ForegroundColor Yellow -Object 'Configuring DATA server'
#region SERVER
Invoke-Command -VMName "$($LabConfig.Prefix)DATA" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    New-Item -Path C:\ -Name Files -ItemType Directory
    New-SmbShare -Path C:\Files -Name Files -FullAccess "NT AUTHORITY\Authenticated Users"
    $Acl = Get-Acl "C:\Files"
    $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule("$using:domainNetBIOS\Domain Users","Modify","Allow")
    $Acl.SetAccessRule($Ar)
    Set-Acl "C:\Files" $Acl
    'text' | Out-File C:\Files\small.txt -Encoding ascii -Force -NoNewline
    'text ' * 100000 | out-file C:\Files\big.txt -Encoding ascii -force -nonewline
    netsh advfirewall set allprofiles state off
} 
#endregion SERVER

write-host -ForegroundColor Yellow -Object 'Creating AD users'
#region AD
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    param($OUPath,$password)
    New-ADUser -Path $OUPath -Name 'Daniel Hejda' -DisplayName 'Daniel Hejda' -GivenName Daniel -Surname Hejda -PasswordNeverExpires $true -Enabled $true -AccountPassword (ConvertTo-SecureString -AsPlainText -Force -String $password) -SamAccountName 'Daniel'
    New-ADUser -Path $OUPath -Name 'Jan Marek' -DisplayName 'Jan Marek' -GivenName Jan -Surname Marek -PasswordNeverExpires $true -Enabled $true -AccountPassword (ConvertTo-SecureString -AsPlainText -Force -String $password) -SamAccountName 'Jan'
} -ArgumentList $OUPath,$allpassword
#endregion AD

write-host -ForegroundColor Yellow -Object 'Configuring W10 domain clients'
#region cl10domain
foreach ($VM_Win10Domain in $VMs_Win10Domain) {
    Invoke-Command -VMName $VM_Win10Domain -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        Add-LocalGroupMember -Group 'Administrators' -Member "$using:domainNetBIOS\jan"
        Add-LocalGroupMember -Group 'Remote Desktop Users' -Member "$using:domainNetBIOS\daniel"
    }
    Invoke-Command -VMName $VM_Win10Domain -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        net user Administrator $using:allpassword
        net user Administrator /active:yes
    }
    Invoke-Command -VMName $VM_Win10Domain -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        netsh advfirewall set allprofiles state off
    }
    Invoke-Command -VMName $VM_Win10Domain -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        winrm qc -quiet
    }
    Invoke-Command -VMName $VM_Win10Domain -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
    Invoke-Command -VMName $VM_Win10Domain -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        choco install googlechrome -y
    }
}
#endregion cl10domain

write-host -ForegroundColor Yellow -Object 'Completed.'
pause