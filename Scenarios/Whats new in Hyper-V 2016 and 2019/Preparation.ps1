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


#Run on host
Start-VM -Name "$($LabConfig.Prefix)*"
Wait-VM -Name "$($LabConfig.Prefix)*" -For Heartbeat

#Run on DC: Prepare S2D cluster
#https://raw.githubusercontent.com/microsoft/WSLab/master/Scenarios/S2D%20Hyperconverged/Scenario.ps1

#Run on DC: Prepare Hyper-V Cluster with shared storage !! Changer variables in script!
#https://raw.githubusercontent.com/microsoft/WSLab/master/Scenarios/Hyper-V%20with%20Shared%20Storage/Scenario.ps1

#Run on host: Prepare CA on DC
#https://raw.githubusercontent.com/cyber-rangers/wslab-additions/master/Tools/Prepare-Empty-CA.ps1

#Manually: Create new Certificate Template on DC for WAC (will run on Management)
#Manually: Request certificate on Management
#Run on host: Download WAC on Management to C:\
Invoke-Command -VMName "$($LabConfig.Prefix)Management" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "C:\WindowsAdminCenter.msi"
    }
#Manually: Install WAC on Management and use CA certificate
#Run on host: Configure delegateion: https://github.com/microsoft/WSLab/tree/master/Scenarios/Windows%20Admin%20Center%20and%20Enterprise%20CA#configure-resource-based-constrained-delegation
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
    $gateway = "Management" # Machine where Windows Admin Center is installed
    $gatewayObject = Get-ADComputer -Identity $gateway
    $nodes = (Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"}).Name# | Out-GridView -OutputMode Multiple # Machines that you want to manage

    foreach ($Node in $Nodes){
        $nodeObject = Get-ADComputer -Identity $node
        Set-ADComputer -Identity $nodeObject -PrincipalsAllowedToDelegateToAccount $gatewayObject -verbose
    }
}
#Run on host: Install GoogleChrome on DC using choco
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
Invoke-Command -VMName "$($LabConfig.Prefix)DC" -Credential $DOMAINADMIN_CREDS -ScriptBlock {
        choco install googlechrome -y
    }
#Manually: Enjoy WAC from the chrome browser on DC [update extensions; add servers etc.]

