$LabConfig=@{ DomainAdminName='CorpAdmin'; AdminPassword='P@ssw0rd'; DomainName='cyber-rangers.lab'; DomainNetbiosName='RANGERS'; DefaultOUName="Lab"; Prefix = 'ATOMNextGen-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = 'DC2' ; Configuration = 'Simple'; ParentVHD = 'Win2019_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True }
$LabConfig.VMs += @{ VMName = 'DCX' ; Configuration = 'Simple'; ParentVHD = 'Win2019_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True; Unattend="NoDjoin" }
$LabConfig.VMs += @{ VMName = 'S19DE' ; Configuration = 'Simple'; ParentVHD = 'Win2019_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True }
$LabConfig.VMs += @{ VMName = 'S12R2DE' ; Configuration = 'Simple'; ParentVHD = 'Win2012R2_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True; Unattend="DjoinCred" }
$LabConfig.VMs += @{ VMName = 'S16CORE' ; Configuration = 'Simple'; ParentVHD = 'Win2016Core_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True}
$LabConfig.VMs += @{ VMName = 'S16DE' ; Configuration = 'Simple'; ParentVHD = 'Win2016_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True}