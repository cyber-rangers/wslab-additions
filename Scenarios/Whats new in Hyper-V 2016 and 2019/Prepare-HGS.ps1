#variables definition
$ScriptRoot = 'X:\WSLab'
. "$ScriptRoot\LabConfig.ps1"
Set-Location $ScriptRoot


$allpassword = $LabConfig.AdminPassword
$domainNetBIOS = $LabConfig.DomainNetbiosName
$domainFQDN = $LabConfig.DomainName
$domainDN = ''; $domainFQDN.split('.') | ForEach-Object {$domainDN += "DC=$_,"}; $domainDN = $domainDN.TrimEnd(',')
$OUPath = "OU=$($LabConfig.DefaultOUName),$domainDN"
$LocalAdminAccountName = $LabConfig.VMs.GetEnumerator().additionallocaladmin | Select-Object -First 1
$DOMAINADMIN_CREDS = New-Object System.Management.Automation.PSCredential ("$domainNetBIOS\Administrator", $(ConvertTo-SecureString $allpassword -AsPlainText -Force))
$LOCALADMIN_CREDS = New-Object System.Management.Automation.PSCredential ($LocalAdminAccountName, $(ConvertTo-SecureString $allpassword -AsPlainText -Force))


#Start all VMs
Start-VM *HGS*,*Compute*,*Management
Wait-VM *HGS*,*Compute*,*Management -For Heartbeat

#Variables
$FabricPlainPassword=$allpassword #password to access fabric nodes Compute1 and Compute2
$HGSPlainPassword   =$allpassword #password to access HGS cluster nodes. In production environments it should be different

$SafeModeAdministratorPlainPassword=$allpassword #SafeModePassword for HGS Domain
$HGSDomainName='bastion.local'
$HGSServiceName = 'MyHGS'

#Create creds
$FabricPassword = ConvertTo-SecureString $FabricPlainPassword -AsPlainText -Force
$HGSPassword = ConvertTo-SecureString $HGSPlainPassword -AsPlainText -Force

$FabricCreds = $DOMAINADMIN_CREDS
$HGSCreds = New-Object System.Management.Automation.PSCredential ("Administrator", $HGSPassword)
$HGSDomainCreds = New-Object System.Management.Automation.PSCredential ("$HGSDomainName\Administrator", $HGSPassword)

#wait until machines are up and grab IPs
do{
    $HGSServerIPs=Invoke-Command -VMName *HGS1, *HGS2, *HGS3 -Credential $HGSCreds -ScriptBlock {(Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4).IPAddress} -ErrorAction SilentlyContinue
    Start-Sleep 5
}until ($HGSServerIPs.count -eq 3)

#Install required HGS feature on HGS VMs
Invoke-Command -VMName *HGS1,*HGS2,*HGS3 -Credential $HGSCreds -ScriptBlock {
    Install-WindowsFeature -Name HostGuardianServiceRole -IncludeManagementTools
}

#restart VMs
Restart-VM -VMName *HGS* -Type Reboot -Force -Wait -For HeartBeat

#Install HGS on first node
Invoke-Command -VMName *HGS1 -Credential $HGSCreds -scriptblock {
    $SafeModeAdministratorPassword = ConvertTo-SecureString -AsPlainText $using:SafeModeAdministratorPlainPassword -Force
    Install-HgsServer -HgsDomainName $using:HGSDomainName -SafeModeAdministratorPassword $SafeModeAdministratorPassword #-Restart
}

#restart HGS1
Restart-VM -VMName *HGS1 -Type Reboot -Force -Wait -For HeartBeat

#Set the DNS forwarder on the fabric DC so other nodes can find the new domain
Invoke-Command -VMName *DC -Credential $FabricCreds -ScriptBlock {
    Add-DnsServerConditionalForwarderZone -Name $using:HGSDomainName -ReplicationScope Forest -MasterServers $using:HgsServerIPs
}

#wait for DC to be initialized
#Note: Sometimes DC starts for quite some time (Please wait for the Group Policy Client or Applying Computer settings).
$Result=$null
do {
    $Result=Invoke-Command -VMName *HGS1 -Credential $HGSDomainCreds -ScriptBlock {
        Get-ADComputer -Filter * -Server HGS1 -ErrorAction SilentlyContinue
        Start-Sleep 5
    }
}until($Result)

Read-host 'Is HGS1 really ready? press enter to continue' | Out-Null

#configure DNS IP addresses
Invoke-Command -VMName *HGS1 -Credential $HGSDomainCreds -ScriptBlock {
    Set-DnsClientServerAddress -ServerAddresses $using:HGSServerIPs -InterfaceAlias Ethernet
}
Invoke-Command -VMName *HGS2,*HGS3 -Credential $HGSCreds -ScriptBlock {
    Set-DnsClientServerAddress -ServerAddresses $using:HGSServerIPs -InterfaceAlias Ethernet
}

#add HGS2 and HGS3
Invoke-Command -VMName *HGS2,*HGS3 -Credential $HGSCreds -ScriptBlock {
    $SafeModeAdministratorPassword = ConvertTo-SecureString -AsPlainText $using:SafeModeAdministratorPlainPassword -Force
    Install-HgsServer -HgsDomainName $using:HGSDomainName -HgsDomainCredential $using:HGSDomainCreds -SafeModeAdministratorPassword $SafeModeAdministratorPassword #-Restart
}

#restart HGS2 and HGS3
Restart-VM -VMName *HGS2,*HGS3 -Type Reboot -Force -Wait -For HeartBeat

#you can create CA in Bastion forest https://docs.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-obtain-certs#request-certificates-from-your-certificate-authority

#or just create self signed cert
Invoke-Command -VMName *HGS1 -Credential $HGSDomainCreds -ScriptBlock {
    $certificatePassword = ConvertTo-SecureString -AsPlainText -String "LS1setup!" -Force

    $signCert = New-SelfSignedCertificate -Subject "CN=HGS Signing Certificate"
    Export-PfxCertificate -FilePath $env:temp\signCert.pfx -Password $certificatePassword -Cert $signCert
    Remove-Item $signCert.PSPath

    $encCert = New-SelfSignedCertificate -Subject "CN=HGS Encryption Certificate"
    Export-PfxCertificate -FilePath $env:temp\encCert.pfx -Password $certificatePassword -Cert $encCert
    Remove-Item $encCert.PSPath

    Initialize-HgsServer -HgsServiceName $using:HGSServiceName -SigningCertificatePath "$env:temp\signCert.pfx" -SigningCertificatePassword $certificatePassword -EncryptionCertificatePath "$env:Temp\encCert.pfx" -EncryptionCertificatePassword $certificatePassword -TrustTpm -hgsversion V1
}

# Wait for HGS2, HGS3 to finish dcpromo
$Result=$null
do {
    $Result=Invoke-Command -VMName *HGS2 -Credential $HGSDomainCreds -ScriptBlock {
        Get-ADComputer -Filter * -Server HGS2
        Start-Sleep 5
    }
}until($Result)

$Result=$null
do {
    $Result=Invoke-Command -VMName *HGS3 -Credential $HGSDomainCreds -ScriptBlock {
        Get-ADComputer -Filter * -Server HGS3
        Start-Sleep 5
    }
}until($Result)


# Join HGS2 and HGS3 to the cluster
Invoke-Command -VMName *HGS2,*HGS3 -Credential $HGSDomainCreds -ScriptBlock {
    Initialize-HgsServer -HgsServerIPAddress $using:HGSServerIPs[0]
}

# Set HGS configuration to support VMs (disable IOMMU requirement)
Invoke-Command -VMName *HGS1 -Credential $HGSDomainCreds -ScriptBlock {
    Disable-HgsAttestationPolicy Hgs_IommuEnabled
}

# Install HostGuardian Hyper-V Support on compute nodes
Invoke-Command -VMName *Compute1,*Compute2 -Credential $FabricCreds -ScriptBlock {
    Install-WindowsFeature HostGuardian -IncludeManagementTools
}

# Restart compute nodes
Restart-VM -VMName *Compute1,*Compute2 -Type Reboot -Force -Wait -For HeartBeat

# Wait for installation to complete
#Start-Sleep 60

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

Invoke-Command -VMName *Compute1, *Compute2 -Credential $FabricCreds -ScriptBlock {
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
Restart-VM -Name *Compute1,*Compute2 -Type Reboot -Force -Wait -For HeartBeat

# Collect attestation artifacts from hosts

$HGS1Session = New-PSSession -VMName *HGS1 -Credential $HGSDomainCreds
$Compute1Session = New-PSSession -VMName *Compute1 -Credential $FabricCreds
$Compute2Session = New-PSSession -VMName *Compute2 -Credential $FabricCreds

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
Invoke-Command -VMName *HGS1 -Credential $HGSDomainCreds -ScriptBlock {
    # Every individual EK needs to be added
    Add-HgsAttestationTpmHost -Path C:\attestationdata\TPM_EK_COMPUTE1.xml -Force
    Add-HgsAttestationTpmHost -Path C:\attestationdata\TPM_EK_Compute2.xml -Force

    # But only one copy of the baseline and CI policy, since they should be identical on both hosts
    Add-HgsAttestationTpmPolicy -Path C:\attestationdata\TPM_Baseline_COMPUTE1.xml -Name "Hyper-V TPM Baseline"
    Add-HgsAttestationCIPolicy -Path C:\attestationdata\CI_POLICY_AUDIT.bin -Name "AllowMicrosoft-AUDIT-CI"
}

# Now, have the hosts try to attest
Invoke-Command -VMName *Compute1, *Compute2 -Credential $FabricCreds -ScriptBlock {
    Set-HgsClientConfiguration -AttestationServerUrl "http://$using:HGSServiceName.$using:HGSDomainName/Attestation" -KeyProtectionServerUrl "http://$using:HGSServiceName.$using:HGSDomainName/KeyProtection"
}

# Collect HGS Trace logs
Invoke-Command -VMName *Compute1, *Compute2 -Credential $FabricCreds -ScriptBlock {
    Get-HgsTrace -RunDiagnostics -Detailed
}

read-host 'Is HGS client validated and ok?' | out-null

# copy parent disk
Copy-Item .\ParentDisks\Win2019Core_G2.vhdx -Destination C:\Win2019Core_G2.vhdx -ToSession $Compute1Session

# install shielded Vm tools and restart
Invoke-Command -VMName *Compute1, *compute2, *Management -Credential $FabricCreds -ScriptBlock {
    Install-Module GuardedFabricTools -Repository PSGallery -MinimumVersion 1.0.0 -Force
    Install-WindowsFeature RSAT-Shielded-VM-Tools,RSAT-Hyper-V-Tools -IncludeAllSubFeature
    }
Restart-VM -Name *Compute1,*Compute2,*Management -Type Reboot -Force -Wait -For HeartBeat


# create protected template disk and save VSC
Invoke-Command -VMName *Compute1 -Credential $FabricCreds -ScriptBlock {
    New-SelfSignedCertificate -DnsName publisher.fabrikam.com
    $certificate = gci cert:\localmachine\my | Where-Object {$_.Subject -like "*publisher.fabrikam.com"} | select -First 1
    Protect-TemplateDisk -Certificate $certificate -Path C:\Win2019Core_G2.vhdx -TemplateName "Windows Server 2019" -Version 1.0.0.0
    Save-VolumeSignatureCatalog -TemplateDiskPath 'C:\Win2019Core_G2.vhdx' -VolumeSignatureCatalogPath 'C:\Win2019Core_G2.vsc'
    }

#copy VSC from compute1 to management
$Compute1Session = New-PSSession -VMName *Compute1 -Credential $FabricCreds
$ManagementSession = New-PSSession -VMName *Management -Credential $FabricCreds
Copy-Item -Path "C:\Win2019Core_G2.vsc" -Destination $env:Temp -FromSession $Compute1Session
Copy-Item -Path "$env:temp\Win2019Core_G2.vsc" -Destination C:\ -ToSession $ManagementSession



#create unattend file for shielding data file
Invoke-Command -VMName *Management -Credential $FabricCreds -ScriptBlock {
    $password = ConvertTo-SecureString -AsPlainText -Force -String 'P@ssw0rd'
    $adminCred = New-Object System.Management.Automation.PSCredential ("Administrator",$password) #local administrator
    $domainCred = New-Object System.Management.Automation.PSCredential ("rangers\Administrator",$password)#"Domain join credentials"

    New-ShieldingDataAnswerFile -Path 'C:\ShieldedVMAnswerFile.xml' -AdminCredentials $adminCred -DomainName 'cyber-rangers.lab' -DomainJoinCredentials $domainCred -Force #It is not recommended to enable the built-in 'Administrator' account in the VM. Select a different username or use -Force if you are sure you want to use this account.
}

<# only for dev cleanup
Invoke-Command -VMName *Management -Credential $FabricCreds -ScriptBlock {
Get-HgsGuardian | Remove-HgsGuardian
}
#>

# create shielding data file
Invoke-Command -VMName *Management -Credential $FabricCreds -ScriptBlock {
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
$Compute1Session = New-PSSession -VMName *Compute1 -Credential $FabricCreds
$ManagementSession = New-PSSession -VMName *Management -Credential $FabricCreds
Copy-Item -Path "C:\contoso.pdk" -Destination $env:Temp -FromSession $ManagementSession
Copy-Item -Path "$env:temp\contoso.pdk" -Destination C:\ -ToSession $Compute1Session
Copy-Item -Path "C:\ContosoES.pdk" -Destination $env:Temp -FromSession $ManagementSession
Copy-Item -Path "$env:temp\ContosoES.pdk" -Destination C:\ -ToSession $Compute1Session

#optional disable firewall
Invoke-Command -VMName *compute1,*compute2 -Credential $FabricCreds -ScriptBlock {
    netsh advfirewall set allprofiles state off
}

read-host 'expand the disk of compute1 VM now please' | out-null


#create shielded vm
Invoke-Command -VMName *Compute1 -Credential $FabricCreds -ScriptBlock {
    if (Get-VMswitch -Name LabSwitch) {} else { New-VMSwitch -Name 'LabSwitch' -AllowManagementOS $true -NetAdapterName Ethernet }
    #New-ShieldedVM -TemplateDiskPath 'C:\Win2019Core_G2.vhdx' -ShieldingDataFilePath 'C:\Contoso.pdk' -Wait -Name "ShieldedVM1" -SwitchName 'LabSwitch' -SpecializationValues @{ '@ComputerName@' = 'ShieldedVM1' } -MemoryStartupBytes 1GB -CpuCount 2
    New-ShieldedVM -TemplateDiskPath 'C:\Win2019Core_G2.vhdx' -ShieldingDataFilePath 'C:\ContosoES.pdk' -Wait -Name "EncrSuppVM1" -SwitchName 'LabSwitch' -SpecializationValues @{ '@ComputerName@' = 'EncrSuppVM1' } -MemoryStartupBytes 1GB -CpuCount 2 -VMPath C:\Hyper-V -Verbose
}