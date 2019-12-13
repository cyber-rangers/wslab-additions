###################################
#Scenario - finish lab preparation#
###################################

#variables definition
$ScriptRoot = 'X:\_Lab'
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


#Run all the remaing code on host

Start-VM -Name "$($LabConfig.Prefix)*"
Wait-VM -Name "$($LabConfig.Prefix)*" -For Heartbeat

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

#manually disable sign in animation using domain GPO

#region LAPS
#Run the following code on host
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
    New-Gpo -Name 'LAPS'

    #extend AD schema (Schema Admins and Enterprise Admins membership needed)
    Update-AdmPwdADSchema
    
        #Add machine rights to report passwords to AD
        Set-AdmPwdComputerSelfPermission -Identity $OUPath

        #User perms to read and reset passwords
        Set-AdmPwdReadPasswordPermission -Identity $OUPath -AllowedPrincipals LAPS_Readers
        Set-AdmPwdResetPasswordPermission -Identity $OUPath -AllowedPrincipals LAPS_Resetters
    } -ArgumentList $OUPath

foreach ($VM_Win10Domain in $VMs_Win10Domain) {
    #only to fix Winrm and install choco
    Invoke-Command -VMName $VM_Win10Domain -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        winrm qc -quiet
    }
    Invoke-Command -VMName $VM_Win10Domain -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }

    #install choco chrome
    Invoke-Command -VMName $VM_Win10Domain -Credential $DOMAINADMIN_CREDS -ScriptBlock {
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

#region SERVER
Invoke-Command -VMName "$($LabConfig.Prefix)SERVER19" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    New-Item -Path C:\ -Name Files -ItemType Directory
    New-SmbShare -Path C:\Files -Name Files -FullAccess "NT AUTHORITY\Authenticated Users"
    $Acl = Get-Acl "C:\Files"
    $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule("RANGERS\Domain Users","Modify","Allow")
    $Acl.SetAccessRule($Ar)
    Set-Acl "C:\Files" $Acl
    'Test text.' | Out-File C:\Files\test.txt -Encoding ascii -Force -NoNewline
} 
#endregion SERVER

#region AD
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    param($OUPath,$password)
    New-ADUser -Path $OUPath -Name 'Daniel Hejda' -DisplayName 'Daniel Hejda' -GivenName Daniel -Surname Hejda -PasswordNeverExpires $true -Enabled $true -AccountPassword (ConvertTo-SecureString -AsPlainText -Force -String $password) -SamAccountName 'Daniel'
    New-ADUser -Path $OUPath -Name 'Jan Marek' -DisplayName 'Jan Marek' -GivenName Jan -Surname Marek -PasswordNeverExpires $true -Enabled $true -AccountPassword (ConvertTo-SecureString -AsPlainText -Force -String $password) -SamAccountName 'Jan'
} -ArgumentList $OUPath,$allpassword
#endregion AD

#region cl10domain
foreach ($VM_Win10Domain in $VMs_Win10Domain) {
    Invoke-Command -VMName $VM_Win10Domain -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        Initialize-Tpm
        Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -SkipHardwareTest
        do {Start-Sleep -Seconds 5
        write-host "waiting for C to be encrypted on $($env:computername). $(Get-BitLockerVolume -MountPoint c: | Select-Object -ExpandProperty encryptionpercentage)% encrypted."}
        until ($(Get-BitLockerVolume -MountPoint "C:" | Select-Object -ExpandProperty ProtectionStatus) -eq 'On')
    } -Verbose

    Invoke-Command -VMName $VM_Win10Domain -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        Add-LocalGroupMember -Group 'Administrators' -Member 'RANGERS\jan'
    }

    Invoke-Command -VMName $VM_Win10Domain -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        Add-LocalGroupMember -Group 'Remote Desktop Users' -Member 'RANGERS\daniel'
    }
}

<#
#region disable Defender on W10
Invoke-Command -VMName $VM_Win10Domain -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true -DisableBlockAtFirstSeen $true
}
#endregion disable Defender on W10

#region enable Defender on W10
Invoke-Command -VMName $VM_Win10Domain -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -DisableBlockAtFirstSeen $false
}
#endregion enable Defender on W10
#>
#endregion cl10domain

