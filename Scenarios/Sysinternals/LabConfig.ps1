$LabConfig=@{ DomainAdminName='CorpAdmin'; AdminPassword='P@ssw0rd'; DomainName='cyber-rangers.lab'; DomainNetbiosName='RANGERS'; DefaultOUName="Lab"; Prefix = 'Sysinternals-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = 'DC2' ; Configuration = 'Simple'; ParentVHD = 'Win2019_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True }
$LabConfig.VMs += @{ VMName = 'DATA' ; Configuration = 'Simple'; ParentVHD = 'Win2019_G2.vhdx'; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True }
$LabConfig.VMs += @{ VMName = 'CL7' ; Configuration = 'Simple' ; ParentVHD = 'Win7SP1_G1.vhdx'  ; MemoryStartupBytes= 1GB ; MGMTNICs=1; AddToolsVHD=$True ; Generation=1; Unattend="DjoinCred"}
$LabConfig.VMs += @{ VMName = 'CL10' ; Configuration = 'Simple' ; ParentVHD = 'Win1019H1_G2.vhdx'  ; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True ; DisableWCF=$True ; vTPM=$True; NestedVirt=$true; Wallpaper='blue'}
$LabConfig.VMs += @{ VMName = 'CL10WG' ; Configuration = 'Simple' ; ParentVHD = 'Win1019H1_G2.vhdx'  ; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True ; DisableWCF=$True ; vTPM=$True; NestedVirt=$true; Unattend="NoDjoin"; AdditionalLocalAdmin='LocalAdmin'}
