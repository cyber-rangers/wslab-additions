$LabConfig=@{ DomainAdminName='CorpAdmin'; AdminPassword='P@ssw0rd'; DomainName='cyber-rangers.lab'; DomainNetbiosName='RANGERS'; DefaultOUName="Lab"; Prefix = 'W10Sec-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = 'DC2' ; Configuration = 'Simple'; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MGMTNICs=1; AddToolsVHD=$True}
$LabConfig.VMs += @{ VMName = 'SERVER19' ; Configuration = 'Simple'; ParentVHD = 'Win2019_G2.vhdx' ; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True}
$LabConfig.VMs += @{ VMName = 'CORESERVER19' ; Configuration = 'Simple'; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True}
$LabConfig.VMs += @{ VMName = 'SERVER12'; Configuration = 'Simple'; ParentVHD = 'Win2012_G2.vhdx'; MemoryStartupBytes = 2GB; MGMTNICs = 1; AddToolsVHD = $True; Unattend = "DjoinCred" }
$LabConfig.VMs += @{ VMName = 'CL10WG' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 4GB ; MGMTNICs=1; AddToolsVHD=$True ; DisableWCF=$True ; vTPM=$True; NestedVirt=$true; Unattend="NoDjoin"; AdditionalLocalAdmin='LocalAdmin'}
$LabConfig.VMs += @{ VMName = 'CL10RED' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 4GB ; MGMTNICs=1; AddToolsVHD=$True ; DisableWCF=$True ; Wallpaper='red'}
$LabConfig.VMs += @{ VMName = 'CL10BLUE' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 4GB ; MGMTNICs=1; AddToolsVHD=$True ; DisableWCF=$True ; vTPM=$True; NestedVirt=$true; Wallpaper='blue'}
$LabConfig.VMs += @{ VMName = 'CL71' ; Configuration = 'Simple' ; ParentVHD = 'Win7SP1_G1.vhdx'  ; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True ; Generation=1; Unattend="DjoinCred"}
$LabConfig.VMs += @{ VMName = 'CL81' ; Configuration = 'Simple'; ParentVHD = 'Win8.1_G2.vhdx' ; MemoryStartupBytes= 2GB ; MGMTNICs=1; AddToolsVHD=$True ;Unattend="DjoinCred" }

$LabConfig.VMs += @{ VMName = 'ATTACK-KALI' ; Configuration = 'Simple'; ParentVHD = 'kali.vhdx' ; MemoryStartupBytes= 4GB ; StaticMemory = $true; MGMTNICs=1; Unattend="None" ; Generation = 1}
$LabConfig.VMs += @{ VMName = 'ATTACK-WIN10' ; Configuration = 'Simple' ; ParentVHD = 'Win1019H1_G2.vhdx'  ; MemoryStartupBytes= 8GB ; MGMTNICs=2; StaticMemory = $true; AddToolsVHD=$True ; NestedVirt=$true; DisableWCF=$True; Unattend="NoDjoin"; AdditionalLocalAdmin='LocalAdmin'}


