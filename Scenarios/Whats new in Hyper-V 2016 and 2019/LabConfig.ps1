$LabConfig=@{ DomainAdminName='CorpAdmin'; AdminPassword='P@ssw0rd'; DomainName='cyber-rangers.lab'; DomainNetbiosName='RANGERS'; DefaultOUName="Lab"; Prefix = 'HV2019News-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = 'Win10' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win2019_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
1..2 | % {"ClusterNode$_"}  | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'Win2019Core_G2.vhdx'; ; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 4  ; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; VMSet= 'SharedStorage1' } }
1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }}
1..3 | % { $VMNames="HGS" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple'   ; ParentVHD = 'Win2019_G2.vhdx'    ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; Unattend="NoDjoin" ; vTPM=$True ; MGMTNICs=1 } }
1..2 | % { $VMNames="Compute" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple'   ; ParentVHD = 'Win2019_G2.vhdx'    ; MemoryStartupBytes= 4GB ; StaticMemory=$true; NestedVirt=$True ; vTPM=$True } }
 