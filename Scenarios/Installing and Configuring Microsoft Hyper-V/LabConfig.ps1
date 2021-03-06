﻿$LabConfig=@{ DomainAdminName='CorpAdmin'; AdminPassword='P@ssw0rd'; DomainName='cyber-rangers.lab'; DomainNetbiosName='RANGERS'; DefaultOUName="Lab"; Prefix = 'GOC206-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = 'Win10' ; Configuration = 'Simple' ; ParentVHD = 'Win1019H1_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win2019_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
1..2 | % {"HVHost$_"}  | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2019Core_G2.vhdx'; StaticMemory = $true; MemoryStartupBytes= 2GB ; NestedVirt=$true } }
1..2 | % {"Cluster1Node$_"}  | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'Win2019Core_G2.vhdx'; ; SSDNumber = 2; SSDSize=128GB ; HDDNumber = 4  ; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; StaticMemory = $true; VMSet= 'SharedStorage1'; NestedVirt=$true } }
1..2 | % {"Cluster2Node$_"}  | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'Win2019Core_G2.vhdx'; ; SSDNumber = 2; SSDSize=128GB ; HDDNumber = 4  ; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; StaticMemory = $true; VMSet= 'SharedStorage2'; NestedVirt=$true } }
