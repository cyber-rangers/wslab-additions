###########################
#Scenario - CA preparation#
###########################

# run on the host and from the lab deployment folder!

#variables definition
$CAName = 'Cyber-Rangers-CA'
$CAComputerNetBIOSName = 'DC'



. ".\LabConfig.ps1"
$CAVMName = "$($LabConfig.prefix)$CAComputerNetBIOSName"
$allpassword = $LabConfig.AdminPassword
$domainNetBIOS = $LabConfig.DomainNetbiosName
$domainFQDN = $LabConfig.DomainName
$domainDN = ''; $domainFQDN.split('.') | ForEach-Object {$domainDN += "DC=$_,"}; $domainDN = $domainDN.TrimEnd(',')
$OUPath = "OU=$($LabConfig.DefaultOUName),$domainDN"
$LocalAdminAccountName = $LabConfig.VMs.GetEnumerator().additionallocaladmin | Select-Object -First 1
$DOMAINADMIN_CREDS = New-Object System.Management.Automation.PSCredential ("$domainNetBIOS\Administrator", $(ConvertTo-SecureString $allpassword -AsPlainText -Force))



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