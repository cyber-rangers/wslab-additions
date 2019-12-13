$LabConfig=@{ DomainAdminName='CorpAdmin'; AdminPassword='P@ssw0rd'; DomainName='cyber-rangers.lab'; DomainNetbiosName='RANGERS'; DefaultOUName="Lab"; Prefix = 'WCAaD-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = 'DC2' ; Configuration = 'Simple'; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MGMTNICs=1; AddToolsVHD=$True ;Unattend="DjoinCred" }
$LabConfig.VMs += @{ VMName = 'CL10RS51' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MGMTNICs=1; AddToolsVHD=$True ; DisableWCF=$True ; vTPM=$True; NestedVirt=$true}
$LabConfig.VMs += @{ VMName = 'CL10RS52' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MGMTNICs=1; AddToolsVHD=$True ; DisableWCF=$True ; vTPM=$True; NestedVirt=$true}
$LabConfig.VMs += @{ VMName = 'CL10RS61' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS6_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MGMTNICs=1; AddToolsVHD=$True ; DisableWCF=$True ; vTPM=$True; NestedVirt=$true}
$LabConfig.VMs += @{ VMName = 'CL10RS62' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS6_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MGMTNICs=1; AddToolsVHD=$True ; DisableWCF=$True ; vTPM=$True; NestedVirt=$true}
$LabConfig.VMs += @{ VMName = 'CL71' ; Configuration = 'Simple' ; ParentVHD = 'Win7SP1_G1.vhdx'  ; MemoryStartupBytes= 1GB ; MGMTNICs=1; AddToolsVHD=$True ; Generation=1; Unattend="DjoinCred"}
$LabConfig.VMs += @{ VMName = 'CL81' ; Configuration = 'Simple'; ParentVHD = 'Win8.1_G2.vhdx' ; MemoryStartupBytes= 1GB ; MGMTNICs=1; AddToolsVHD=$True ;Unattend="DjoinCred" }
$LabConfig.VMs += @{ VMName = 'FILES' ; Configuration = 'Simple'; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes= 1GB ; MGMTNICs=1; AddToolsVHD=$True }
$LabConfig.VMs += @{ VMName = 'WEB' ; Configuration = 'Simple'; ParentVHD = 'Win2012R2_G2.vhdx'; MemoryStartupBytes= 1GB ; MGMTNICs=1; AddToolsVHD=$True; Unattend="DjoinCred" }
$LabConfig.VMs += @{ VMName = 'ARCHIVE' ; Configuration = 'Simple'; ParentVHD = 'Win2012_G2.vhdx'; MemoryStartupBytes= 1GB ; MGMTNICs=1; AddToolsVHD=$True; Unattend="DjoinCred" }
$LabConfig.VMs += @{ VMName = 'DETECTION' ; Configuration = 'Simple'; ParentVHD = 'Win2016_G2.vhdx'; MemoryStartupBytes= 4GB ; MGMTNICs=1; AddToolsVHD=$True}
$LabConfig.VMs += @{ VMName = 'MONITORING' ; Configuration = 'Simple'; ParentVHD = 'Win2016_G2.vhdx'; MemoryStartupBytes= 4GB ; MGMTNICs=1; AddToolsVHD=$True}


$LabConfig.VMs += @{ VMName = 'PARTNER-DC' ; Configuration = 'Simple'; ParentVHD = 'Win2008R2SP1_G1.vhdx' ; MemoryStartupBytes= 1GB ; MGMTNICs=1; AddToolsVHD=$True; Unattend="NoDjoin" ; Generation = 1}
$LabConfig.VMs += @{ VMName = 'PARTNER-WEB' ; Configuration = 'Simple'; ParentVHD = 'Win2008R2SP1_G1.vhdx' ; MemoryStartupBytes= 1GB ; MGMTNICs=1; AddToolsVHD=$True; Unattend="NoDjoin" ; Generation = 1}
$LabConfig.VMs += @{ VMName = 'PARTNER-CL72' ; Configuration = 'Simple' ; ParentVHD = 'Win7SP1_G1.vhdx'  ; MemoryStartupBytes= 1GB ; MGMTNICs=1; AddToolsVHD=$True ; Generation=1; Unattend="NoDjoin"; AdditionalLocalAdmin='LocalAdmin'}

$LabConfig.VMs += @{ VMName = 'ATTACK-KALI' ; Configuration = 'Simple'; ParentVHD = 'kali.vhdx' ; MemoryStartupBytes= 4GB ; MGMTNICs=1; Unattend="None" ; Generation = 1}

$LabConfig.VMs += @{ VMName = 'ATTACK-WIN10' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 4GB ; MGMTNICs=1; AddToolsVHD=$True ; DisableWCF=$True; Unattend="NoDjoin"; AdditionalLocalAdmin='LocalAdmin'}
