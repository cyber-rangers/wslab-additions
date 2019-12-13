###################################
#Scenario - finish lab preparation#
###################################

#variables definition
$ScriptRoot = 'X:\WSLab'
. "$ScriptRoot\LabConfig.ps1"


$allpassword = $LabConfig.AdminPassword
$domainNetBIOS = $LabConfig.DomainNetbiosName
$domainFQDN = $LabConfig.DomainName
$domainDN = ''; $domainFQDN.split('.') | ForEach-Object {$domainDN += "DC=$_,"}; $domainDN = $domainDN.TrimEnd(',')
$OUPath = "OU=$($LabConfig.DefaultOUName),$domainDN"
$LocalAdminAccountName = $LabConfig.VMs.GetEnumerator().additionallocaladmin | Select-Object -First 1
$DOMAINADMIN_CREDS = New-Object System.Management.Automation.PSCredential ("$domainNetBIOS\Administrator", $(ConvertTo-SecureString $allpassword -AsPlainText -Force))
$LOCALADMIN_CREDS = New-Object System.Management.Automation.PSCredential ($LocalAdminAccountName, $(ConvertTo-SecureString $allpassword -AsPlainText -Force))




#Run all the remaing code on host

Start-VM -Name "$($LabConfig.Prefix)*"
Wait-VM -Name "$($LabConfig.Prefix)*" -For Heartbeat

#Run the following code inside ATTACK-WIN10 VM
Set-ExecutionPolicy unrestricted;D:\SysinternalsSuite\autologon.exe localadmin localhost 'P@ssw0rd' /accepteula;D:\Commando-VM\install.ps1 -password P@ssw0rd -nocheck $true

#Run the following code inside ATTACK-KALI (root/P@ssw0rd)
apt-get clean && apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y




#Run the following code on host
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
    Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses '10.0.0.1','10.0.0.2','127.0.0.1'
    Start-Sleep -Seconds 2
    Clear-DnsClientCache
    Start-Sleep -Seconds 2
    Install-ADDSDomainController -CreateDnsDelegation:$false -DomainName $domainFQDN -InstallDns:$true -SafeModeAdministratorPassword $(ConvertTo-SecureString -String 'P@ssw0rd' -AsPlainText -Force) -NoGlobalCatalog:$false -NoRebootOnCompletion:$true -Force:$true
} -ArgumentList $domainFQDN
Restart-VM -Name "$($LabConfig.Prefix)DC2" -Wait -For Heartbeat
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses '10.0.0.2','10.0.0.1','127.0.0.1'
    Clear-DnsClientCache
}

#region LAPS
#Run the following code on host
foreach ($TEMP_CL10VM in $(get-vm "$($LabConfig.Prefix)CL10*" | Where-Object {$_.name -notlike "*WG"} | Select-Object -ExpandProperty name)) {
    Invoke-Command -VMName $TEMP_CL10VM -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        net user Administrator P@ssw0rd
        net user Administrator /active:yes
    }
}

foreach ($TEMP_CL10VM in $(get-vm "$($LabConfig.Prefix)CL10*" | Where-Object {$_.name -notlike "*WG"} | Select-Object -ExpandProperty name)) {
    Invoke-Command -VMName $TEMP_CL10VM -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        netsh advfirewall set allprofiles state off
    }
}

foreach ($TEMP_CL10VM in $(get-vm "$($LabConfig.Prefix)CL10*" | Where-Object {$_.name -notlike "*WG"} | Select-Object -ExpandProperty name)) {
    Invoke-Command -VMName $TEMP_CL10VM -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        gpupdate /force
    }
}

Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    #download LAPS install file x64
    Invoke-WebRequest -UseBasicParsing -Uri 'https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/LAPS.x64.msi' -OutFile "$env:UserProfile\Downloads\LAPS.x64.msi"

    #optional: download documentation
    "LAPS_TechnicalSpecification.docx","LAPS_OperationsGuide.docx" | ForEach-Object {
        Invoke-WebRequest -UseBasicParsing -Uri "https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/$_" -OutFile "$env:UserProfile\Downloads\$_"
    }
}

Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    Add-ADGroupMember -Identity "Schema Admins" -Members CorpAdmin
    Add-ADGroupMember -Identity "Enterprise Admins" -Members CorpAdmin
    }

Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    param($OUPath)
    #install PowerShell management tools, Management UI and copy ADMX template to policy store on management machine
    Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\LAPS.x64.msi ADDLOCAL=Management.PS,Management.ADMX,Management.UI /q"

}

 Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
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
foreach ($TEMP_CL10VM in $(get-vm "$($LabConfig.Prefix)CL10*" | Where-Object {$_.name -notlike "*WG"} | Select-Object -ExpandProperty name)) {
    Invoke-Command -VMName $TEMP_CL10VM -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        winrm qc -quiet
    }
    Invoke-Command -VMName $TEMP_CL10VM -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
}
foreach ($TEMP_CL10VM in $(get-vm "$($LabConfig.Prefix)CL10*WG" | Select-Object -ExpandProperty name)) {
    Invoke-Command -VMName $TEMP_CL10VM -Credential $LOCALADMIN_CREDS -ScriptBlock {
        Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
}

#install choco chrome
foreach ($TEMP_CL10VM in $(get-vm "$($LabConfig.Prefix)CL10*" | Where-Object {$_.name -notlike "*WG"} | Select-Object -ExpandProperty name)) {
    Invoke-Command -VMName $TEMP_CL10VM -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        choco install googlechrome -y
    }
}
foreach ($TEMP_CL10VM in $(get-vm "$($LabConfig.Prefix)CL10*WG" | Select-Object -ExpandProperty name)) {
    Invoke-Command -VMName $TEMP_CL10VM -Credential $LOCALADMIN_CREDS -ScriptBlock {
        choco install googlechrome -y
    }
}


#install GP extensions on all domain joined W10 clients
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    $Sessions=New-PSSession -ComputerName $(Get-ADComputer -Filter * | Where-Object {$_.name -like "CL10*"} | Select-Object -ExpandProperty Name)

    foreach ($session in $sessions){
        Copy-Item -Path $env:UserProfile\Downloads\LAPS.x64.msi -ToSession $session -Destination $env:temp
    }

    Invoke-Command -Session $sessions -ScriptBlock {
        Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:temp\LAPS.x64.msi /q"
    }
}
#endregion LAPS


# todo not working on 19H1+
#region WALLPAPERS
foreach ($VMtoSetWallpaper in $($LabConfig.vms.GetEnumerator() | where-object {$_.wallpaper -ne $null})) {
    if ($VMtoSetWallpaper.AdditionalLocalAdmin) {
        $VMtoSetWallpaper_Credentials = $LOCALADMIN_CREDS
    } else {
        $VMtoSetWallpaper_Credentials = $DOMAINADMIN_CREDS
    }

    icm -VMName "$($LabConfig.Prefix)$($VMtoSetWallpaper.VMName)" -Credential $VMtoSetWallpaper_Credentials {
        param([string]$Wallpaper)
        if (Test-Path "D:\Wallpapers\$Wallpaper.jpg") {
            Write-Output "[$($env:computername)]:: Setting Wallpaper"
            Rename-Item "C:\Windows\Web\Screen" "C:\Windows\Web\Screen-old"
            md "C:\Windows\Web\Screen"
            Copy-Item "D:\Wallpapers\$Wallpaper.jpg" -Destination "C:\Windows\Web\Screen\img100.jpg" -Force
        } else {
            Write-Output "[$($env:computername)]:: Cannot find wallpaper file D:\Wallpapers\$Wallpaper.jpg"
        }
    } -ArgumentList $VMtoSetWallpaper.Wallpaper
}
#endregion WALLPAPERS


<#
GENERAL
- disable host resource protection ? keyboard problem?
TODO SERVER19
- add cname server19: www
- install iis
- deploy sample html web
TODO w10 blue
- ps restricted
- do nto disable wf
- enalbe cifs,ping, etc. on wf inbound
- applocker - default rules + enforce
- bitlocker C:
- enroll virtual smart card
TODO W10 red
- disable defender av
- ps unrestricted
TODO AD
- create user CORPUSER
#>
