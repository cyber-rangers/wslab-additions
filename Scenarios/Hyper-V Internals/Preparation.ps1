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

#variables definition
$ScriptRoot = Read-Host 'Enter the path of folder containing the lab (i.e. E:\WSLab)'
if (Test-Path $ScriptRoot) {
. "$ScriptRoot\LabConfig.ps1"
} else {
    Write-Host "Unable to find Lab folder $ScriptRoot" -ForegroundColor Red
    break
}


$allpassword = $LabConfig.AdminPassword
$domainNetBIOS = $LabConfig.DomainNetbiosName
$domainFQDN = $LabConfig.DomainName
$domainDN = ''; $domainFQDN.split('.') | ForEach-Object {$domainDN += "DC=$_,"}; $domainDN = $domainDN.TrimEnd(',')
$OUPath = "OU=$($LabConfig.DefaultOUName),$domainDN"
$LocalAdminAccountName = $LabConfig.VMs.GetEnumerator().additionallocaladmin | Select-Object -First 1
$DOMAINADMIN_CREDS = New-Object System.Management.Automation.PSCredential ("$domainNetBIOS\Administrator", $(ConvertTo-SecureString $allpassword -AsPlainText -Force))

#Run on host
Write-Host "Starting lab VMs..." -ForegroundColor Yellow
Start-VM -Name "$($LabConfig.Prefix)*"
Write-Host "Waiting for all lab VMs..." -ForegroundColor Yellow
Wait-VM -Name "$($LabConfig.Prefix)*" -For Heartbeat

#region Guarded Fabric
#Variables
$SafeModeAdministratorPlainPassword=$allpassword #SafeModePassword for HGS Domain
$HGSDomainName='bastion.local'
$HGSServiceName = 'MyHGS'

#Create creds
$FabricPassword = ConvertTo-SecureString $allpassword -AsPlainText -Force
$HGSPassword = ConvertTo-SecureString $allpassword -AsPlainText -Force

$FabricCreds = $DOMAINADMIN_CREDS
$HGSCreds = New-Object System.Management.Automation.PSCredential ("Administrator", $HGSPassword)
$HGSDomainCreds = New-Object System.Management.Automation.PSCredential ("$HGSDomainName\Administrator", $HGSPassword)

Write-Host -ForegroundColor Yellow extending disk on Compute1/2 to have enough space to store VMs
Get-VM "$($LabConfig.Prefix)Compute*" | Get-VMHardDiskDrive | Get-VHD | Resize-VHD -SizeBytes 100GB
Invoke-Command -VMName "$($LabConfig.Prefix)Compute1","$($LabConfig.Prefix)Compute2" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    $maxsize = Get-Partition -DriveLetter c | Get-PartitionSupportedSize | Select-Object -ExpandProperty sizemax
    Get-Partition -DriveLetter c | Resize-Partition -Size $maxsize
}

Write-Host -ForegroundColor Yellow waiting until machines are up and grab IPs
do{
    $HGSServerIPs=Invoke-Command -VMName "$($LabConfig.Prefix)HGS1", "$($LabConfig.Prefix)HGS2", "$($LabConfig.Prefix)HGS3" -Credential $HGSCreds -ScriptBlock {(Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4).IPAddress} -ErrorAction SilentlyContinue
    Start-Sleep 5
}until ($HGSServerIPs.count -eq 3)

Write-Host -ForegroundColor Yellow Installing required HGS feature on HGS VMs
Invoke-Command -VMName "$($LabConfig.Prefix)HGS1","$($LabConfig.Prefix)HGS2","$($LabConfig.Prefix)HGS3" -Credential $HGSCreds -ScriptBlock {
    Install-WindowsFeature -Name HostGuardianServiceRole -IncludeManagementTools
}

#restart VMs
Restart-VM -VMName "$($LabConfig.Prefix)HGS*" -Type Reboot -Force -Wait -For HeartBeat

Write-Host -ForegroundColor Yellow Installing HGS on first node
Invoke-Command -VMName "$($LabConfig.Prefix)HGS1" -Credential $HGSCreds -scriptblock {
    $SafeModeAdministratorPassword = ConvertTo-SecureString -AsPlainText $using:SafeModeAdministratorPlainPassword -Force
    Install-HgsServer -HgsDomainName $using:HGSDomainName -SafeModeAdministratorPassword $SafeModeAdministratorPassword #-Restart
}

#restart HGS1
Restart-VM -VMName "$($LabConfig.Prefix)HGS1" -Type Reboot -Force -Wait -For HeartBeat

#Set the DNS forwarder on the fabric DC so other nodes can find the new domain
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $FabricCreds -ScriptBlock {
    Add-DnsServerConditionalForwarderZone -Name $using:HGSDomainName -ReplicationScope Forest -MasterServers $using:HgsServerIPs
}

Write-Host -ForegroundColor Yellow waiting for DC to be initialized
#Note: Sometimes DC starts for quite some time (Please wait for the Group Policy Client or Applying Computer settings).
$Result=$null
do {
    $Result=Invoke-Command -VMName "$($LabConfig.Prefix)HGS1" -Credential $HGSDomainCreds -ScriptBlock {
        Get-ADComputer -Filter * -Server HGS1 -ErrorAction SilentlyContinue
        Start-Sleep 5
    } -ErrorAction SilentlyContinue
}until($Result)

Read-host 'Is HGS1 really ready? press enter to continue' | Out-Null

#configure DNS IP addresses
Invoke-Command -VMName "$($LabConfig.Prefix)HGS1" -Credential $HGSDomainCreds -ScriptBlock {
    Set-DnsClientServerAddress -ServerAddresses $using:HGSServerIPs -InterfaceAlias Ethernet
}
Invoke-Command -VMName "$($LabConfig.Prefix)HGS2","$($LabConfig.Prefix)HGS3" -Credential $HGSCreds -ScriptBlock {
    Set-DnsClientServerAddress -ServerAddresses $using:HGSServerIPs -InterfaceAlias Ethernet
}

Write-Host -ForegroundColor Yellow adding HGS2 and HGS3
Invoke-Command -VMName "$($LabConfig.Prefix)HGS2","$($LabConfig.Prefix)HGS3" -Credential $HGSCreds -ScriptBlock {
    $SafeModeAdministratorPassword = ConvertTo-SecureString -AsPlainText $using:SafeModeAdministratorPlainPassword -Force
    Install-HgsServer -HgsDomainName $using:HGSDomainName -HgsDomainCredential $using:HGSDomainCreds -SafeModeAdministratorPassword $SafeModeAdministratorPassword #-Restart
}

#restart HGS2 and HGS3
Restart-VM -VMName "$($LabConfig.Prefix)HGS2","$($LabConfig.Prefix)HGS3" -Type Reboot -Force -Wait -For HeartBeat

#you can create CA in Bastion forest https://docs.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-obtain-certs#request-certificates-from-your-certificate-authority

#or just create self signed cert
Invoke-Command -VMName "$($LabConfig.Prefix)HGS1" -Credential $HGSDomainCreds -ScriptBlock {
    $certificatePassword = ConvertTo-SecureString -AsPlainText -String "LS1setup!" -Force

    $signCert = New-SelfSignedCertificate -Subject "CN=HGS Signing Certificate"
    Export-PfxCertificate -FilePath $env:temp\signCert.pfx -Password $certificatePassword -Cert $signCert
    Remove-Item $signCert.PSPath

    $encCert = New-SelfSignedCertificate -Subject "CN=HGS Encryption Certificate"
    Export-PfxCertificate -FilePath $env:temp\encCert.pfx -Password $certificatePassword -Cert $encCert
    Remove-Item $encCert.PSPath

    Initialize-HgsServer -HgsServiceName $using:HGSServiceName -SigningCertificatePath "$env:temp\signCert.pfx" -SigningCertificatePassword $certificatePassword -EncryptionCertificatePath "$env:Temp\encCert.pfx" -EncryptionCertificatePassword $certificatePassword -TrustTpm -hgsversion V1
}

Write-Host -ForegroundColor Yellow  Waiting for HGS2, HGS3 to finish dcpromo
$Result=$null
do {
    $Result=Invoke-Command -VMName "$($LabConfig.Prefix)HGS2" -Credential $HGSDomainCreds -ScriptBlock {
        Get-ADComputer -Filter * -Server HGS2
        Start-Sleep 5
    }
}until($Result)

$Result=$null
do {
    $Result=Invoke-Command -VMName "$($LabConfig.Prefix)HGS3" -Credential $HGSDomainCreds -ScriptBlock {
        Get-ADComputer -Filter * -Server HGS3
        Start-Sleep 5
    }
}until($Result)


Write-Host -ForegroundColor Yellow  Joining HGS2 and HGS3 to the cluster
Invoke-Command -VMName "$($LabConfig.Prefix)HGS2","$($LabConfig.Prefix)HGS3" -Credential $HGSDomainCreds -ScriptBlock {
    Initialize-HgsServer -HgsServerIPAddress $using:HGSServerIPs[0]
}

Write-Host -ForegroundColor Yellow  Setting HGS configuration to support VMs so we remove the IOMMU requirement
Invoke-Command -VMName "$($LabConfig.Prefix)HGS1" -Credential $HGSDomainCreds -ScriptBlock {
    Disable-HgsAttestationPolicy Hgs_IommuEnabled
}

Write-Host -ForegroundColor Yellow  Installing HostGuardian Hyper-V Support on compute nodes
Invoke-Command -VMName "$($LabConfig.Prefix)Compute1","$($LabConfig.Prefix)Compute2" -Credential $FabricCreds -ScriptBlock {
    Install-WindowsFeature HostGuardian -IncludeManagementTools
}

# Restart compute nodes
Restart-VM -VMName "$($LabConfig.Prefix)Compute1","$($LabConfig.Prefix)Compute2" -Type Reboot -Force -Wait -For HeartBeat

Write-Host -ForegroundColor Yellow  Waiting for installation to complete
$result = $null
do {
    $result = Invoke-Command -VMName "$($LabConfig.Prefix)Compute1" -Credential $FabricCreds -ScriptBlock {$true}
    Start-Sleep -Seconds 1
} until ($result)
$result = $null
do {
    $result = Invoke-Command -VMName "$($LabConfig.Prefix)Compute2" -Credential $FabricCreds -ScriptBlock {$true}
    Start-Sleep -Seconds 1
} until ($result)
Write-Host -foregroundcolor Yellow Waiting additional 2 minutes for Compute1 and Compute2 to be ready

# Set registry key to not require IOMMU for VBS in VMs and apply default CI policy
# Also generate attestation artifacts (CI policy, TPM EK, and TPM baseline)
# You should also include https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules

#grab recommended xml blocklist from GitHub
#[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$content=Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/master/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules.md
#find start and end
$XMLStart=$content.Content.IndexOf("<?xml version=")
$XMLEnd=$content.Content.IndexOf("</SiPolicy>")+11 # 11 is lenght of string
#create xml
[xml]$XML=$content.Content.Substring($xmlstart,$XMLEnd-$XMLStart) #find XML part


Write-Host -ForegroundColor Yellow Configuring attestation for Compute hosts
Invoke-Command -VMName "$($LabConfig.Prefix)Compute1","$($LabConfig.Prefix)Compute2" -Credential $FabricCreds -ScriptBlock {
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard -Name RequirePlatformSecurityFeatures -Value 0
    md C:\attestationdata
    $cipolicy = "C:\attestationdata\CI_POLICY_AUDIT.xml"
    Copy-Item "$env:SystemRoot\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" $cipolicy -Force
    #add recommended XML blocklist
    #($using:XML).Save("$env:TEMP\blocklist.xml")
    #add to MyPolicy.xml
    #$mergedPolicyRules = Merge-CIPolicy -PolicyPaths "$env:TEMP\blocklist.xml",$cipolicy -OutputFilePath $cipolicy
    #Write-Host ('Merged policy contains {0} rules' -f $mergedPolicyRules.Count)
    # For testing, convert the policy to an audit policy to avoid constrained language mode in PS
    Set-RuleOption -FilePath $cipolicy -Option 3
    # Allowing a CI policy to be updated without a reboot can allow someone to pass attestation and replace with a bad policy, so we disallow that
    Set-RuleOption -FilePath $cipolicy -Option 16 -Delete
    ConvertFrom-CIPolicy -XmlFilePath $cipolicy -BinaryFilePath "C:\attestationdata\CI_POLICY_AUDIT.bin"
    Copy-Item "C:\attestationdata\CI_POLICY_AUDIT.bin" "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b" -Force
    Initialize-Tpm
    (Get-PlatformIdentifier -Name $env:COMPUTERNAME).Save("C:\attestationdata\TPM_EK_$env:COMPUTERNAME.xml")
    Get-HgsAttestationBaselinePolicy -Path "C:\attestationdata\TPM_Baseline_$env:COMPUTERNAME.xml" -SkipValidation
}

# Reboot VMs again for setting to take effect
Restart-VM -Name "$($LabConfig.Prefix)Compute1","$($LabConfig.Prefix)Compute2" -Type Reboot -Force -Wait -For HeartBeat

# Collect attestation artifacts from hosts

$HGS1Session = New-PSSession -VMName "$($LabConfig.Prefix)HGS1" -Credential $HGSDomainCreds
$Compute1Session = New-PSSession -VMName "$($LabConfig.Prefix)Compute1" -Credential $FabricCreds
$Compute2Session = New-PSSession -VMName "$($LabConfig.Prefix)Compute2" -Credential $FabricCreds

#Create folder on HGS1
Invoke-Command -Session $HGS1Session -ScriptBlock {
    New-Item -Name AttestationData -Path c:\ -ItemType Directory
}

#Copy files
Copy-Item -Path "C:\attestationdata\TPM_EK_COMPUTE1.xml" -Destination $env:Temp -FromSession $Compute1Session
Copy-Item -Path "$env:temp\TPM_EK_COMPUTE1.xml" -Destination C:\attestationdata\ -ToSession $HGS1Session
Copy-Item -Path "C:\attestationdata\TPM_EK_COMPUTE2.xml" -Destination $env:Temp -FromSession $Compute2Session
Copy-Item -Path "$env:temp\TPM_EK_COMPUTE2.xml" -Destination C:\attestationdata\ -ToSession $HGS1Session
Copy-Item -Path "C:\attestationdata\TPM_Baseline_COMPUTE1.xml" -Destination $env:Temp -FromSession $Compute1Session
Copy-Item -Path "$env:temp\TPM_Baseline_COMPUTE1.xml" -Destination C:\attestationdata\ -ToSession $HGS1Session
Copy-Item -Path "C:\attestationdata\CI_POLICY_AUDIT.bin" -Destination $env:Temp -FromSession $Compute1Session
Copy-Item -Path "$env:temp\CI_POLICY_AUDIT.bin" -Destination C:\attestationdata\ -ToSession $HGS1Session


# Import the attestation policies on HGS
Invoke-Command -VMName "$($LabConfig.Prefix)HGS1" -Credential $HGSDomainCreds -ScriptBlock {
    # Every individual EK needs to be added
    Add-HgsAttestationTpmHost -Path C:\attestationdata\TPM_EK_COMPUTE1.xml -Force
    Add-HgsAttestationTpmHost -Path C:\attestationdata\TPM_EK_Compute2.xml -Force

    # But only one copy of the baseline and CI policy, since they should be identical on both hosts
    Add-HgsAttestationTpmPolicy -Path C:\attestationdata\TPM_Baseline_COMPUTE1.xml -Name "Hyper-V TPM Baseline"
    Add-HgsAttestationCIPolicy -Path C:\attestationdata\CI_POLICY_AUDIT.bin -Name "AllowMicrosoft-AUDIT-CI"
}

# Now, have the hosts try to attest
Invoke-Command -VMName "$($LabConfig.Prefix)Compute1", "$($LabConfig.Prefix)Compute2" -Credential $FabricCreds -ScriptBlock {
    Set-HgsClientConfiguration -AttestationServerUrl "http://$using:HGSServiceName.$using:HGSDomainName/Attestation" -KeyProtectionServerUrl "http://$using:HGSServiceName.$using:HGSDomainName/KeyProtection"
}

Write-Host -ForegroundColor Yellow  Collecting HGS Trace logs
Invoke-Command -VMName "$($LabConfig.Prefix)Compute1", "$($LabConfig.Prefix)Compute2" -Credential $FabricCreds -ScriptBlock {
    Get-HgsTrace -RunDiagnostics -Detailed
}

Write-Host -ForegroundColor Yellow  copying parent disk for future secured VMs
Copy-Item "$ScriptRoot\ParentDisks\Win2019Core_G2.vhdx" -Destination 'C:\Win2019Core_G2.vhdx' -ToSession $Compute1Session

# install shielded Vm tools (confirm nuget installation manually) and restart
Invoke-Command -VMName "$($LabConfig.Prefix)Compute1", "$($LabConfig.Prefix)compute2", "$($LabConfig.Prefix)Management" -Credential $FabricCreds -ScriptBlock {
	Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
	Install-Module GuardedFabricTools -Repository PSGallery -MinimumVersion 1.0.0 -Force -Confirm:$false
    Install-WindowsFeature RSAT-Shielded-VM-Tools,RSAT-Hyper-V-Tools -IncludeAllSubFeature
    }
Restart-VM -Name "$($LabConfig.Prefix)Compute1", "$($LabConfig.Prefix)compute2", "$($LabConfig.Prefix)Management" -Type Reboot -Force -Wait -For HeartBeat


Write-Host -ForegroundColor Yellow  creating protected template disk and save VSC
Invoke-Command -VMName "$($LabConfig.Prefix)Compute1" -Credential $FabricCreds -ScriptBlock {
    New-SelfSignedCertificate -DnsName publisher.fabrikam.com
    $certificate = gci cert:\localmachine\my | Where-Object {$_.Subject -like "*publisher.fabrikam.com"} | select -First 1
    Protect-TemplateDisk -Certificate $certificate -Path C:\Win2019Core_G2.vhdx -TemplateName "Windows Server 2019" -Version 1.0.0.0
    Save-VolumeSignatureCatalog -TemplateDiskPath 'C:\Win2019Core_G2.vhdx' -VolumeSignatureCatalogPath 'C:\Win2019Core_G2.vsc'
    }

#copy VSC from compute1 to management
$Compute1Session = New-PSSession -VMName "$($LabConfig.Prefix)Compute1" -Credential $FabricCreds
$ManagementSession = New-PSSession -VMName "$($LabConfig.Prefix)Management" -Credential $FabricCreds
Copy-Item -Path "C:\Win2019Core_G2.vsc" -Destination $env:Temp -FromSession $Compute1Session
Copy-Item -Path "$env:temp\Win2019Core_G2.vsc" -Destination C:\ -ToSession $ManagementSession



#create unattend file for shielding data file
Invoke-Command -VMName "$($LabConfig.Prefix)Management" -Credential $FabricCreds -ScriptBlock {
    $password = ConvertTo-SecureString -AsPlainText -Force -String 'P@ssw0rd'
    $adminCred = New-Object System.Management.Automation.PSCredential ("Administrator",$password) #local administrator
    $domainCred = New-Object System.Management.Automation.PSCredential ("rangers\Administrator",$password)#"Domain join credentials"

    New-ShieldingDataAnswerFile -Path 'C:\ShieldedVMAnswerFile.xml' -AdminCredentials $adminCred -DomainName 'cyber-rangers.lab' -DomainJoinCredentials $domainCred -Force #It is not recommended to enable the built-in 'Administrator' account in the VM. Select a different username or use -Force if you are sure you want to use this account.
}

# create shielding data file
Invoke-Command -VMName "$($LabConfig.Prefix)Management" -Credential $FabricCreds -ScriptBlock {
    $Owner = New-HgsGuardian –Name 'Owner' –GenerateCertificates

    # download and Import the HGS guardian for each fabric you want to run your shielded VM
    Invoke-WebRequest "http://$using:HGSServiceName.$using:HGSDomainName/KeyProtection/service/metadata/2014-07/metadata.xml" -OutFile C:\HGSGuardian.xml -UseBasicParsing
    $Guardian = Import-HgsGuardian -Path C:\HGSGuardian.xml -Name 'Fabric' -AllowUntrustedRoot

    # Create the PDK file
    # The "Policy" parameter describes whether the admin can see the VM's console or not
    # Use "EncryptionSupported" if you are testing out shielded VMs and want to debug any issues during the specialization process
    New-ShieldingDataFile -ShieldingDataFilePath 'C:\Contoso.pdk' -Owner $Owner –Guardian $guardian –VolumeIDQualifier (New-VolumeIDQualifier -VolumeSignatureCatalogFilePath 'C:\Win2019Core_G2.vsc' -VersionRule Equals) -WindowsUnattendFile 'C:\ShieldedVMAnswerFile.xml' -Policy Shielded
    New-ShieldingDataFile -ShieldingDataFilePath 'C:\ContosoES.pdk' -Owner $Owner –Guardian $guardian –VolumeIDQualifier (New-VolumeIDQualifier -VolumeSignatureCatalogFilePath 'C:\Win2019Core_G2.vsc' -VersionRule Equals) -WindowsUnattendFile 'C:\ShieldedVMAnswerFile.xml' -Policy encryptionsupported
}

#copy PDK from management to compute1
$Compute1Session = New-PSSession -VMName "$($LabConfig.Prefix)Compute1" -Credential $FabricCreds
$ManagementSession = New-PSSession -VMName "$($LabConfig.Prefix)Management" -Credential $FabricCreds
Copy-Item -Path "C:\contoso.pdk" -Destination $env:Temp -FromSession $ManagementSession
Copy-Item -Path "$env:temp\contoso.pdk" -Destination C:\ -ToSession $Compute1Session
Copy-Item -Path "C:\ContosoES.pdk" -Destination $env:Temp -FromSession $ManagementSession
Copy-Item -Path "$env:temp\ContosoES.pdk" -Destination C:\ -ToSession $Compute1Session

#optional disable firewall
Invoke-Command -VMName "$($LabConfig.Prefix)Compute1","$($LabConfig.Prefix)Compute2" -Credential $FabricCreds -ScriptBlock {
    netsh advfirewall set allprofiles state off
}


Write-Host -ForegroundColor Yellow  creating shielded vm and encryption supported vm
Invoke-Command -VMName "$($LabConfig.Prefix)Compute1" -Credential $FabricCreds -ScriptBlock {
    if (Get-VMswitch -Name LabSwitch -ErrorAction SilentlyContinue) {} else { New-VMSwitch -Name 'LabSwitch' -AllowManagementOS $true -NetAdapterName Ethernet }
    if (Test-Path C:\Hyper-V) {} else {New-Item -Path C:\Hyper-V -ItemType Directory}
    New-ShieldedVM -TemplateDiskPath 'C:\Win2019Core_G2.vhdx' -ShieldingDataFilePath 'C:\Contoso.pdk' -Wait -Name "ShieldedVM1" -SwitchName 'LabSwitch' -SpecializationValues @{ '@ComputerName@' = 'ShieldedVM1' } -MemoryStartupBytes 1GB -CpuCount 2 -VMPath C:\Hyper-V -Verbose
    New-ShieldedVM -TemplateDiskPath 'C:\Win2019Core_G2.vhdx' -ShieldingDataFilePath 'C:\ContosoES.pdk' -Wait -Name "EncrSuppVM1" -SwitchName 'LabSwitch' -SpecializationValues @{ '@ComputerName@' = 'EncrSuppVM1' } -MemoryStartupBytes 1GB -CpuCount 2 -VMPath C:\Hyper-V -Verbose
}

Write-Host -ForegroundColor Yellow waiting for nested vms to heartbeat
Invoke-Command -VMName "$($LabConfig.Prefix)Compute1" -Credential $FabricCreds -ScriptBlock {
    Wait-VM -Name ShieldedVM1 -For Heartbeat
    Wait-VM -Name EncrSuppVM1 -For Heartbeat
}

Write-Host -ForegroundColor Yellow waiting for nested vms to be off
Invoke-Command -VMName "$($LabConfig.Prefix)Compute1" -Credential $FabricCreds -ScriptBlock {
    $VMNameTemp = 'ShieldedVM1'
    do {Start-Sleep -Seconds 1
        Write-Host "Waiting for $VMNameTemp to stop..."
    }
    until ($(Get-VM -Name $VMNameTemp | select-object -ExpandProperty State) -eq 'Off')
}
Invoke-Command -VMName "$($LabConfig.Prefix)Compute1" -Credential $FabricCreds -ScriptBlock {
    $VMNameTemp = 'EncrSuppVM1'
    do {Start-Sleep -Seconds 1
        Write-Host "Waiting for $VMNameTemp to stop..."
    }
    until ($(Get-VM -Name $VMNameTemp | select-object -ExpandProperty State) -eq 'Off')
}
#endregion Guarded Fabric

#region CA
Write-Host "Installing and Configuring Certificate Authority on DC..." -ForegroundColor Yellow
$CAName = 'Cyber-Rangers-CA'
$CAComputerNetBIOSName = 'DC'
$CAVMName = "$($LabConfig.prefix)$CAComputerNetBIOSName"

#Install IIS
Invoke-Command -VMName $CAVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    Install-WindowsFeature RSAT-ADCS,Web-WebServer -IncludeManagementTools
}

Invoke-Command -VMName $CAVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    #Create a CertData Folder and CPS Text File
    New-Item -Path C:\inetpub\wwwroot\CertData -Type Directory
    Write-Output "Placeholder for Certificate Policy Statement (CPS). Modify as needed by your organization." | Out-File C:\inetpub\wwwroot\CertData\cps.txt

    #New IIS Virtual Directory
    $vDirProperties = @{
        Site         = "Default Web Site"
        Name         = "CertData"
        PhysicalPath = 'C:\inetpub\wwwroot\CertData'
    }
    New-WebVirtualDirectory @vDirProperties

    #Allow IIS Directory Browsing & Double Escaping
    Set-WebConfigurationProperty -filter /system.webServer/directoryBrowse -name enabled -Value $true -PSPath "IIS:\Sites\$($vDirProperties.site)\$($vDirProperties.name)"
    Set-WebConfigurationProperty -filter /system.webServer/Security/requestFiltering -name allowDoubleEscaping -value $true -PSPath "IIS:\Sites\$($vDirProperties.site)"

    #New Share for the CertData Directory
    New-SmbShare -Name CertData -Path C:\inetpub\wwwroot\CertData -ReadAccess "$using:domainNetBIOS\domain users" -ChangeAccess "$using:domainNetBIOS\cert publishers"
    #configure NTFS Permissions
    (Get-SmbShare CertData).PresetPathAcl | Set-Acl
}

Invoke-Command -VMName $CAVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
#Create DC Policy file
$Content=@"
[Version]
Signature='`$Windows NT$'

[PolicyStatementExtension]
Policies=AllIssuancePolicy
Critical=False

[AllIssuancePolicy]
OID=2.5.29.32.0
URL=http://$using:CAComputerNetBIOSName.$using:domainFQDN/certdata/cps.txt

[BasicConstraintsExtension]
PathLength=0
Critical=True

[certsrv_server]
RenewalKeyLength=4096
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=5
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
"@

    Set-Content -Value $Content -Path C:\windows\CAPolicy.inf

    #Install ADCS
    Install-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
}


Invoke-Command -VMName $CAVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    #Install ADCS Certification Authority Role Services
    $CaProperties = @{
        CACommonName        = "$using:CAName"
        CAType              = "EnterpriseRootCA"
        CryptoProviderName  = "ECDSA_P256#Microsoft Software Key Storage Provider"
        HashAlgorithmName   = "SHA256"
        KeyLength           = 256
        ValidityPeriod      = "Years"
        ValidityPeriodUnits = 10
    }
    Install-AdcsCertificationAuthority @CaProperties -force
}

Invoke-Command -VMName $CAVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    #Configure Max Validity Period of Certificates Issued by this DC
    Certutil -setreg CA\ValidityPeriodUnits 5
    Certutil -setreg CA\ValidityPeriod "Years"

    #Configure the CRL Validity Periods
    Certutil -setreg CA\CRLPeriodUnits 6
    Certutil -setreg CA\CRLPeriod "Days"
    Certutil -setreg CA\CRLDeltaPeriodUnits 0
    Certutil -setreg CA\CRLDeltaPeriod "Hours"
    Certutil -setreg CA\CRLOverlapUnits 3
    Certutil -setreg CA\CRLOverlapPeriod "Days"

    #Configure the CDP Locations
    ## Remove Existing CDP URIs
    $CrlList = Get-CACrlDistributionPoint
    ForEach ($Crl in $CrlList) { Remove-CACrlDistributionPoint $Crl.uri -Force }

    ## Add New CDP URIs
    Add-CACRLDistributionPoint -Uri C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl -PublishToServer -PublishDeltaToServer -Force
    Add-CACRLDistributionPoint -Uri C:\inetpub\wwwroot\CertData\%3%8.crl -PublishToServer -PublishDeltaToServer -Force
    Add-CACRLDistributionPoint -Uri "http://$using:CAComputerNetBIOSName.$using:domainFQDN/certdata/%3%8.crl" -AddToCertificateCDP -AddToFreshestCrl -Force

    #Configure the AIA Locations
    ## Remove Existing AIA URIs
    $AiaList = Get-CAAuthorityInformationAccess
    ForEach ($Aia in $AiaList) { Remove-CAAuthorityInformationAccess $Aia.uri -Force }
    ## Add New AIA URIs
    Certutil -setreg CA\CACertPublicationURLs "1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt"
    Add-CAAuthorityInformationAccess -AddToCertificateAia -uri "http://$using:CAComputerNetBIOSName.$using:domainFQDN/certdata/%3%4.crt" -Force

    #Restart the DC Service & Publish a New CRL
    Restart-Service certsvc
    Start-Sleep 10
    Certutil -crl
}

Invoke-Command -VMName $CAVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    #Copy the Root Certificate File to the CertData Folder
    Copy-Item "C:\Windows\System32\Certsrv\CertEnroll\$using:CAComputerNetBIOSName.$using:domainFQDN`_$using:CAName.crt" "C:\inetpub\wwwroot\CertData\$using:CAComputerNetBIOSName.$using:domainFQDN`_$using:CAName.crt"

    #Rename the Root Certificate File
    Rename-Item "C:\inetpub\wwwroot\CertData\$using:CAComputerNetBIOSName.$using:domainFQDN`_$using:CAName.crt" "$using:CAName.crt"

    #Export the Root Certificate in PEM Format
    $CACert=Get-ChildItem -Path Cert:\LocalMachine\CA | where Subject -Like "*$using:CAName*" | select -First 1
    $CACert |Export-Certificate -Type CERT -FilePath "C:\inetpub\wwwroot\CertData\$using:CAName.cer"
    Rename-Item "C:\inetpub\wwwroot\CertData\$using:CAName.cer" "$using:CAName.pem"
}

Invoke-Command -VMName $CAVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    #Add mime type
    Start-Sleep -Seconds 2
    & $Env:WinDir\system32\inetsrv\appcmd.exe set config /section:staticContent /+"[fileExtension='.pem',mimeType='text/plain']"
}


Invoke-Command -VMName $CAVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    #Add mime type
    Start-Sleep -Seconds 2
    & $Env:WinDir\system32\inetsrv\appcmd.exe set config /section:staticContent /-"[fileExtension='.pem']"
}

#endregion CA

#region WAC

#Manually: Create new Certificate Template on DC for WAC (will run on Management)
#Manually: Request certificate on Management
Write-Host "Dowloading WAC on Management..." -ForegroundColor Yellow
Invoke-Command -VMName "$($LabConfig.Prefix)Management" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "C:\WindowsAdminCenter.msi"
    }
#Manually: Install WAC on Management and use CA certificate
Write-Host "Configuring delegation for all Windows Server OSE lab VMs..." -ForegroundColor Yellow
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    $gateway = "Management" # Machine where Windows Admin Center is installed
    $gatewayObject = Get-ADComputer -Identity $gateway
    $nodes = (Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"}).Name# | Out-GridView -OutputMode Multiple # Machines that you want to manage

    foreach ($Node in $Nodes){
        $nodeObject = Get-ADComputer -Identity $node
        Set-ADComputer -Identity $nodeObject -PrincipalsAllowedToDelegateToAccount $gatewayObject -verbose
    }
}
Write-Host "Installing Chocolatey on Win10..." -ForegroundColor Yellow
Invoke-Command -VMName "$($LabConfig.Prefix)Win10" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
Write-Host "Installing Google Chrome using Chocolatey on Win10..." -ForegroundColor Yellow
Invoke-Command -VMName "$($LabConfig.Prefix)Win10" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        choco install googlechrome -y
    }
#Manually: Enjoy WAC from the chrome browser on Win10 [update extensions; add servers etc.]
#endregion WAC

Write-Host "All DONE..." -ForegroundColor Green

pause