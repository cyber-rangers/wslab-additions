$LabConfig=@{ DomainAdminName='CorpAdmin'; AdminPassword='P@ssw0rd'; DomainName='cyber-rangers.lab'; DomainNetbiosName='RANGERS'; DefaultOUName="Lab"; Prefix = 'ATOMTest-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = 'DC2' ; Configuration = 'Simple'; ParentVHD = 'Win2019_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True }
$LabConfig.VMs += @{ VMName = 'S19CORE' ; Configuration = 'Simple'; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True ;Unattend="DjoinCred" }
$LabConfig.VMs += @{ VMName = 'S19DE' ; Configuration = 'Simple'; ParentVHD = 'Win2019_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True }
$LabConfig.VMs += @{ VMName = 'S12R2CORE' ; Configuration = 'Simple'; ParentVHD = 'Win2012R2Core_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True; Unattend="DjoinCred" }
$LabConfig.VMs += @{ VMName = 'S12R2DE' ; Configuration = 'Simple'; ParentVHD = 'Win2012R2_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True; Unattend="DjoinCred" }
$LabConfig.VMs += @{ VMName = 'S12CORE' ; Configuration = 'Simple'; ParentVHD = 'Win2012Core_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True; Unattend="DjoinCred" }
$LabConfig.VMs += @{ VMName = 'S12DE' ; Configuration = 'Simple'; ParentVHD = 'Win2012_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True; Unattend="DjoinCred" }
$LabConfig.VMs += @{ VMName = 'S16CORE' ; Configuration = 'Simple'; ParentVHD = 'Win2016Core_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True}
$LabConfig.VMs += @{ VMName = 'S16DE' ; Configuration = 'Simple'; ParentVHD = 'Win2016_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True}
$LabConfig.VMs += @{ VMName = 'S8R2CORE' ; Configuration = 'Simple'; ParentVHD = 'Win2008R2SP1Core_G1.vhdx' ; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True; Unattend="DjoinCred" ; Generation = 1}
$LabConfig.VMs += @{ VMName = 'S8R2DE' ; Configuration = 'Simple'; ParentVHD = 'Win2008R2SP1_G1.vhdx' ; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True; Unattend="DjoinCred" ; Generation = 1}