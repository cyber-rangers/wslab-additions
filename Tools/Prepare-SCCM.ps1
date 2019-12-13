#####################################
#Scenario - SCCM preparation#
#####################################

# run on the host and from the lab deployment folder!

#variables definition
$SCCMComputerNetBIOSName = 'SCCM1'
#$SCCMSiteType = 'Central Administration Site' # not supported in this script now (only for prereqs)
$SCCMSiteType = 'Primary Site'
#$SCCMSiteType = 'Secondary Site' # not supported in this script now (only for prereqs)
$SCCMSiteCode = 'LAB'
$SCCMSiteName = "$($LabConfig.DomainNetbiosName) SCCM Site $(Get-Random)"
$SCCMOSPartitionSize = 100GB


. ".\LabConfig.ps1"
$SCCMVMName = "$($LabConfig.prefix)$SCCMComputerNetBIOSName"
$DCVMName = "$($LabConfig.prefix)DC"
$allpassword = $LabConfig.AdminPassword
$domainNetBIOS = $LabConfig.DomainNetbiosName
$domainFQDN = $LabConfig.DomainName
$domainDN = ''; $domainFQDN.split('.') | ForEach-Object {$domainDN += "DC=$_,"}; $domainDN = $domainDN.TrimEnd(',')
$OUPath = "DC=$($LabConfig.DefaultOUName),$domainDN"
$LocalAdminAccountName = $LabConfig.VMs.GetEnumerator().additionallocaladmin | Select-Object -First 1
$DOMAINADMIN_CREDS = New-Object System.Management.Automation.PSCredential ("$domainNetBIOS\Administrator", $(ConvertTo-SecureString $allpassword -AsPlainText -Force))

# Expand SCCM VM disk
Get-VM $SCCMVMName | Get-VMHardDiskDrive -ControllerLocation 0 | Get-VHD | Resize-VHD -SizeBytes $SCCMOSPartitionSize

#Users and Groups
Invoke-Command -VMName $DCVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    do {start-sleep 5; New-ADUser `
        -Name "sccm.push" `
        -SamAccountName  "sccm.push" `
        -DisplayName "sccm.push" `
        -AccountPassword (ConvertTo-SecureString $using:allpassword -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -ea 0
        } until ($?)
    do {start-sleep 5; New-ADUser `
        -Name "sccm.naa" `
        -SamAccountName  "sccm.naa" `
        -DisplayName "sccm.naa" `
        -AccountPassword (ConvertTo-SecureString $using:allpassword -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -ea 0
        } until ($?)
    do {start-sleep 5; New-ADUser `
        -Name "sccm.rep" `
        -SamAccountName  "sccm.rep" `
        -DisplayName "sccm.rep" `
        -AccountPassword (ConvertTo-SecureString $using:allpassword -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -ea 0
        } until ($?)
    do {start-sleep 5; New-ADUser `
        -Name "sccm.domjoin" `
        -SamAccountName  "sccm.domjoin" `
        -DisplayName "sccm.domjoin" `
        -AccountPassword (ConvertTo-SecureString $using:allpassword -AsPlainText -Force) `
        -ChangePasswordAtLogon $false  `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -ea 0
        } until ($?)
    do {start-sleep 5; new-adgroup `
        -GroupCategory Security `
        -GroupScope DomainLocal `
        -Name 'SCCM-Administrators' `
        -DisplayName 'SCCM-Administrators' `
        -SamAccountName 'SCCM-Administrators' `
        -ea 0
        } until ($?)
    Add-ADGroupMember "SCCM-Administrators" "CorpAdmin"
    do {start-sleep 5; new-adgroup `
        -GroupCategory Security `
        -GroupScope DomainLocal `
        -Name 'SCCM-Site-Servers' `
        -DisplayName 'SCCM-Site-Servers' `
        -SamAccountName 'SCCM-Site-Servers' `
        -ea 0
        } until ($?)
    Add-ADGroupMember "SCCM-Site-Servers" "SCCM1$"
}


#Windows Server roles and features for SCCM
switch ($SCCMSiteType) {
    'Central Administration Site' {
        Invoke-Command -VMName $SCCMVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
            Install-WindowsFeature -Name "NET-Framework-Core","BITS","BITS-IIS-Ext","BITS-Compact-Server","RDC","WAS-Process-Model","WAS-Config-APIs","WAS-Net-Environment","Web-Server","Web-ISAPI-Ext","Web-ISAPI-Filter","Web-Net-Ext","Web-Net-Ext45","Web-ASP-Net","Web-ASP-Net45","Web-ASP","Web-Windows-Auth","Web-Basic-Auth","Web-URL-Auth","Web-IP-Security","Web-Scripting-Tools","Web-Mgmt-Service","Web-Stat-Compression","Web-Dyn-Compression","Web-Metabase","Web-WMI","Web-HTTP-Redirect","Web-Log-Libraries","Web-HTTP-Tracing","UpdateServices-RSAT","UpdateServices-API","UpdateServices-UI","UpdateServices-Services","UpdateServices-DB" -IncludeManagementTools
        }
    }
    'Primary Site' {
        Invoke-Command -VMName $SCCMVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
            Install-WindowsFeature -Name "RDC","NET-Framework-Core","BITS","BITS-IIS-Ext","BITS-Compact-Server","RDC","WAS-Process-Model","WAS-Config-APIs","WAS-Net-Environment","Web-Server","Web-ISAPI-Ext","Web-ISAPI-Filter","Web-Net-Ext","Web-Net-Ext45","Web-ASP-Net","Web-ASP-Net45","Web-ASP","Web-Windows-Auth","Web-Basic-Auth","Web-URL-Auth","Web-IP-Security","Web-Scripting-Tools","Web-Mgmt-Service","Web-Stat-Compression","Web-Dyn-Compression","Web-Metabase","Web-WMI","Web-HTTP-Redirect","Web-Log-Libraries","Web-HTTP-Tracing","UpdateServices-RSAT","UpdateServices-API","UpdateServices-UI","UpdateServices-Services","UpdateServices-DB" -IncludeManagementTools
        }
    }
    'Secondary Site' {
        Invoke-Command -VMName $SCCMVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
            Install-WindowsFeature -Name "RDC","NET-Framework-Core","BITS","BITS-IIS-Ext","BITS-Compact-Server","RDC","WAS-Process-Model","WAS-Config-APIs","WAS-Net-Environment","Web-Server","Web-ISAPI-Ext","Web-Windows-Auth","Web-Basic-Auth","Web-URL-Auth","Web-IP-Security","Web-Scripting-Tools","Web-Mgmt-Service","Web-Metabase","Web-WMI","UpdateServices-Services","UpdateServices-DB" -IncludeManagementTools
        }
    }
    defaut {Write-Error 'Unknown SCCM site type. Redefine pls.'; pause}
}

#ADK for SCCM
Invoke-Command -VMName $SCCMVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    Get-Disk | ? IsOffline | Set-Disk -IsOffline:$false | Set-Disk -IsReadOnly:$false | Out-Null
    Get-ScheduledTask "ServerManager" | Disable-ScheduledTask | Out-Null
    if ($(get-partition -DriveLetter C | Select-Object -ExpandProperty Size) -lt $($using:SCCMOSPartitionSize - 1GB)) {Resize-Partition -DriveLetter C -Size $(Get-PartitionSupportedSize -DriveLetter C | Select-Object -ExpandProperty SizeMax)}
    $setupfile = Get-Item -Path "D:\SCVMM\ADK\ADKsetup.exe" -ErrorAction SilentlyContinue
    if ($setupfile.versioninfo.ProductBuildPart -ge 17763){
        $winpesetupfile = Get-Item -Path "D:\SCVMM\ADKwinPE\adkwinpesetup.exe" -ErrorAction SilentlyContinue
    }
    if ($SetupFile.versioninfo.ProductBuildPart -ge 17763){
        Write-Host "ADK $($SetupFile.versioninfo.ProductBuildPart) Is being installed..." -ForegroundColor Cyan
        Start-Process -Wait -FilePath $setupfile.fullname -ArgumentList "/features OptionID.DeploymentTools OptionId.UserStateMigrationTool /quiet"
        Write-Host "ADKwinPE $($winpeSetupFile.versioninfo.ProductBuildPart) Is being installed..." -ForegroundColor Cyan
        Start-Process -Wait -FilePath $winpesetupfile.fullname -ArgumentList "/features OptionID.WindowsPreinstallationEnvironment /quiet"
    }else{
        Write-Host "ADK $($SetupFile.versioninfo.ProductBuildPart) Is being installed..." -ForegroundColor Cyan
        Start-Process -Wait -FilePath $setupfile.fullname -ArgumentList "/features OptionID.DeploymentTools OptionId.UserStateMigrationTool OptionID.WindowsPreinstallationEnvironment /quiet"
    }
}

#configure WSUS
Invoke-Command -VMName $SCCMVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    New-Item -Path C: -Name WSUSContent -ItemType Directory
    $arguments = "postinstall SQL_INSTANCE_NAME=$($env:COMPUTERNAME) CONTENT_DIR=C:\WSUSContent"
    Start-Process "$($env:programfiles)\Update Services\Tools\wsusutil.exe" -ArgumentList $arguments.Split(" ") -WorkingDirectory "$($env:programfiles)\Update Services\Tools" -NoNewWindow -Wait
}

# Create SYSTEM MANAGEMENT container
Invoke-Command -VMName $DCVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
# Validate existence of System Management container
    $ADFilter = "(&(objectClass=container)(cn=*System Management*))"
    $ADDirectorySearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $ADFilter
    if ($ADDirectorySearcher.FindOne() -ne $null) {
        # Output that System Management container was found
        Write-Host "System Management container already exist, will not attempt to create it" -ForegroundColor Magenta
    }
    else {
        # Output that System Management container was not found
        Write-Host "System Management container was not detected, attempting to create it" -ForegroundColor Magenta

        # Create System Management container
        try {
            $ADDirectoryEntry = New-Object -TypeName System.DirectoryServices.DirectoryEntry
            $ADSystemManagementContainer = $ADDirectoryEntry.Create("container", "CN=System Management,CN=System")
            $ADSystemManagementContainer.SetInfo()
        }
        catch [System.Exception] {
            Write-Host "Unable to create the System Management container. Error message: $($_.Exception.Message)" -ForegroundColor Magenta
        }

        # Validate that container was created successfully
        if ($ADDirectorySearcher.FindOne() -ne $null) {
            Write-Host "Successfully created the System Management container" -ForegroundColor Magenta
        }
        else {
            Write-Host "Unable to locate the System Management container after an attempt for creating it was made" -ForegroundColor Magenta
        }
    }
}

# Configure permissions on SYSTEM MANAGEMENT container
Invoke-Command -VMName $DCVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    # Determine the domain distinguished name
    $ADDomain = New-Object -TypeName System.DirectoryServices.DirectoryEntry | Select-Object -ExpandProperty distinguishedName
    if ($ADDomain -ne $null) {
        # Output attempting to detect domain distinguished name
        Write-Host "Attempting to determine distinguished name for domain" -ForegroundColor Magenta

        # Construct directory searcher to locate selected Active Directory group from the datagrid
        $ADDirectorySearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher("(&(ObjectCategory=group)(samAccountName=SCCM-Site-Servers))")
        $ADGroupResult = $ADDirectorySearcher.FindOne()
        if ($ADGroupResult -ne $null) {
            # Determine the selected Active Directory group SID
            [System.Security.Principal.SecurityIdentifier]$ADGroupSID = (New-Object -TypeName System.Security.Principal.SecurityIdentifier($ADGroupResult.Properties["objectSID"][0],0)).Value

            # Construct ADSI object for System Management container
            $SystemManagementContainer = [ADSI]("LDAP://CN=System Management,CN=System,$($ADDomain)")

            # Output enumeration for AccessRules
            Write-Host "Enumerating AccessRules for System Management container" -ForegroundColor Magenta

            # Loop through all the access rules for the System Management container and add them to an array list
            $AccessRulesList = New-Object -TypeName System.Collections.ArrayList
            foreach ($AccessRule in $SystemManagementContainer.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                $AccessRulesList.Add($AccessRule.IdentityReference.Value) | Out-Null
            }

            # Check whether selected Active Directory group SID is in the array list, if not then add group to System Management container 
            if ($ADGroupSID.Value -notin $AccessRulesList) {
                # Output that the selected Active Directory group will be added to the System Management container
                Write-Host "Adding new AccessRule for group SCCM-SiteServers to the System Management container" -ForegroundColor Magenta

                # Add new AccessRule and commit changes
                try {
                    $ADAccessRule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule($ADGroupSID, "GenericAll", "Allow", "All", ([System.Guid]::Empty))
                    $SystemManagementContainer.ObjectSecurity.AddAccessRule($ADAccessRule)
                    $SystemManagementContainer.CommitChanges()

                    # Validate that the Active Directory group was added to the AccessRules
                    $AccessRulesList.Clear()
                    foreach ($AccessRule in $SystemManagementContainer.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                        $AccessRulesList.Add($AccessRule.IdentityReference.Value) | Out-Null
                    }
                    if ($ADGroupSID.Value -in $AccessRulesList) {
                        Write-Host "Successfully added SCCM-Site-Servers to the System Management container" -ForegroundColor Magenta
                    }
                    else {
                        Write-Host "Unable to find SCCM-Site-Servers in the AccessRules list for the System Management container" -ForegroundColor Magenta
                    }
                }
                catch [System.Exception] {
                    Write-Host "Unable to amend AccessRules. Error message: $($_.Exception.Message)" -ForegroundColor Magenta
                }
            }
            else {
                Write-Host "Active Directory group SCCM-Site-Servers is already present in the AccessRules list for System Management container" -ForegroundColor Magenta
            }
        }
        else {
            Write-Host "Unable to determine the Active Directory group object from selected group" -ForegroundColor Magenta
        }
    }
    else {
        Write-Host "Unable to determine domain distinguished name" -ForegroundColor Magenta
    }
}

# Extend AD Schema for SCCM
Invoke-Command -VMName $DCVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    $(Get-Content D:\SCCM\SMSSETUP\bin\X64\ConfigMgr_ad_schema.ldf) -replace ',DC=x',',DC=cyber-rangers,DC=lab' | Out-File C:\ConfigMgr_ad_schema.ldf
    New-Item -Path C:\Logs -ItemType Directory | Out-Null
    $arguments = '-i -f C:\ConfigMgr_ad_schema.ldf -v -j C:\Logs'
    Write-Host "Arguments: $arguments" -ForegroundColor Magenta
    Start-Process "C:\Windows\System32\ldifde.exe" -ArgumentList $arguments.Split(" ") -WorkingDirectory 'C:\' -NoNewWindow -Wait
    Get-Content C:\Logs\ldif.log
}

# Install SCCM
$SCCM1SetupConfig = @"
[Identification]
Action=InstallPrimarySite


[Options]
ProductID=BXH69-M62YX-QQD6R-3GPWX-8WMFY
SiteCode=$SCCMSiteCode
SiteName=$SCCMSiteName
SMSInstallDir=C:\Microsoft Configuration Manager
SDKServer="$SCCMComputerNetBIOSName.$($domainFQDN)"
RoleCommunicationProtocol=HTTPorHTTPS
ClientsUsePKICertificate=0
PrerequisiteComp=1
PrerequisitePath=D:\SCCMPrereqs
MobileDeviceLanguage=0
ManagementPoint="$SCCMComputerNetBIOSName.$($domainFQDN)"
ManagementPointProtocol=HTTP
DistributionPoint="$SCCMComputerNetBIOSName.$($domainFQDN)"
DistributionPointProtocol=HTTP
DistributionPointInstallIIS=0
AdminConsole=1
JoinCEIP=0

[SQLConfigOptions]
SQLServerName="$SCCMComputerNetBIOSName.$($domainFQDN)"
DatabaseName=CM_$SCCMSiteCode
SQLSSBPort=4022
SQLDataFilePath=C:\SQLData
SQLLogFilePath=C:\SQLData

[CloudConnectorOptions]
CloudConnector=1
CloudConnectorServer="$SCCMComputerNetBIOSName.$($domainFQDN)"
UseProxy=0
ProxyName=
ProxyPort=

[SABranchOptions]
SAActive=1
CurrentBranch=1

[HierarchyExpansionOption]

"@
Invoke-Command -VMName $SCCMVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    param($SCCM1SetupConfig)
    Write-Host "Creating directory C:\config" -ForegroundColor Magenta
    New-Item -Path C:\SCCMInstallConfig -ItemType Directory | Out-Null
    Write-Host "Writing SCCM1Server.ini" -ForegroundColor Magenta
    $SCCM1SetupConfig | Out-File C:\SCCMInstallConfig\SCCMServer.ini
    New-Item -Path C:\SQLData -ItemType Directory | Out-Null
    Write-Host "Installing SC Configuration Manager" -ForegroundColor Magenta
    $arguments = '/script C:\SCCMInstallConfig\SCCMServer.ini'
    Write-Host "Arguments: $arguments" -ForegroundColor Magenta
    Start-Process "D:\SCCM\SMSSETUP\BIN\X64\setup.exe" -ArgumentList $arguments.Split(" ") -WorkingDirectory 'D:\SCCM\SMSSETUP\BIN\X64' -NoNewWindow -Wait
    While (Get-Process 'Setup' -ErrorAction SilentlyContinue | where-object {$_.description -eq 'Configuration Manager Setup Bootstrapper'} )
    {
        Write-Host "." -NoNewline -ForegroundColor Magenta
        Start-Sleep -Seconds 5
    }
    Write-Host "SCCM Installation is done."
} -ArgumentList $SCCM1SetupConfig

start-sleep -minutes 5

Invoke-Command -VMName $SCCMVMName -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
    Write-Host 'Importing SCCM PowerShell module...'
    Import-Module 'C:\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'
    Write-Host 'waiting 60 seconds...'
    invoke-sleep -seconds 60
    Write-Host "Changing PowerShell Location to $using:SCCMSiteCode"
    Set-Location "$using:SCCMSiteCode`:"
    Write-Host "Configuring Group $($using:domainName)\SCCM-Administrators as Full Administrator"
    New-CMAdministrativeUser -Name "$($using:domainName)\SCCM-Administrators" -RoleName 'Full Administrator'
}