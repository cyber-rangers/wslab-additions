$LabConfig=@{ DomainAdminName='CorpAdmin'; AdminPassword='P@ssw0rd'; DomainName='cyber-rangers.lab'; DomainNetbiosName='RANGERS'; DefaultOUName="Lab"; Prefix = 'W10Dep-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@(); EmptyVMs=@()}

$LabConfig.VMs += @{ VMName = 'CL1019031' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS6_G2.vhdx'  ; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True ; DisableWCF=$True ; vTPM=$True; NestedVirt=$true}
$LabConfig.VMs += @{ VMName = 'CL1018091' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True ; DisableWCF=$True ; vTPM=$True; NestedVirt=$true}
$LabConfig.VMs += @{ VMName = 'CL71' ; Configuration = 'Simple' ; ParentVHD = 'Win7SP1_G1.vhdx'  ; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True ; Generation=1; Unattend="DjoinCred"}
$LabConfig.VMs += @{ VMName = 'CL81' ; Configuration = 'Simple'; ParentVHD = 'Win8.1_G2.vhdx' ; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True ;Unattend="DjoinCred" }
$LabConfig.VMs += @{ VMName = 'MDT1' ; Configuration = 'Simple'; ParentVHD = 'Win2019_G2.vhdx'; MemoryStartupBytes= 4GB ; MGMTNICs=1; AddToolsVHD=$True }
$LabConfig.VMs += @{ VMName = 'SCCM1' ; Configuration = 'Simple'; ParentVHD = 'Win2019_G2.vhdx'; MemoryStartupBytes= 12GB ; StaticMemory=$true; VMProcessorCount = 4; MGMTNICs=1; AddToolsVHD=$True }

$LabConfig.EmptyVMs += @{ VMName = 'CLEFITPM' ; MemoryStartupBytes= 2GB ; StaticMemory=$true; MGMTNICs=1; vTPM=$True; NestedVirt=$true}
$LabConfig.EmptyVMs += @{ VMName = 'CLBIOS' ; MemoryStartupBytes= 2GB ; StaticMemory=$true ; MGMTNICs=1; Generation=1}