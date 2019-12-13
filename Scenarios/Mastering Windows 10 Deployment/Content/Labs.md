# Lab builder
aka.ms/wslab
https://github.com/cyber-rangers/wslab-additions/tree/master/Scenarios/Mastering%20Windows%2010%20Deployment

# Labs
## Module 2:
1. Install Windows ADK 1903 and Windows ADK 1903 on CL19031
2. Build custom WinPE boot media.
   * Architecture: x64
   * Download some device drivers for WinPE and add them to WinPE image
   * Add optional components
      * Scripting
      * NetFX
      * PowerShell
      * DISM cmdlets
   * Configure scratch space to 256MB
   * Modify start command to include configuration of high performance profile and start of Windows PowerShell console.
   * Cleanup mountpoints
3. Create bootable ISO
4. Test boot of newly created boot image on CLEFITPM virtual machine

## Module 3:
1. Create unattend.xml file for your vanilla OS install image
2. Initiate OS installation using newly created unattend file and custom WinPE on CLEFITPM
3. Create provisioning package on CL1019031 (define random computername, reset computer, join domain, protect with password)
4. Test provisioning package on CL1019032
5. Reconfigure computername on CL1019032 back to CL1019032 (delete original CL1019032 computer object in AD first)

## Module 4:
1. Start scanstate with required parameters and configuration on CL71
   * Create share on DC to store the USMT migrated data
   * Backup user data (Documents, Desktop, all JPG pictures on disk)
2. Reinstall operating system on CL71 to Windows 10 using the process built in previous module
3. Start loadstate with required parameter and configuration on CL71
   * Restore user data (Documents, Desktop) from DC share

## Module 5:
1. Install ADK 1809 and ADK 1809 WinPE on MDT1
2. Install MDT on MDT1
3. Create and configure (WinPE, OCs) Deployment Share on MDT1
4. Configure MDT content on MDT1
   * Add application 7-zip
   * Add Dell WinPE x64 drivers (download them from the internet first) and configure selection profile
   * Add operating system (1903) [full set of source files]
   * Modify customsettings.ini and bootstrap.ini
5. Test deployment of Windows 10 on CLBIOS (capture reference image)

## Module 6:
1. Configure Boundaries
2. Configure Boundary Group
3. Reconfigure Site and Roles to HTTPS
4. Configure Network Access Account
5. Configure Client Push installation method
6. Configure Discovery Methods (Forest, System, User, Group)
7. Configure Distribution Point to support OS deployment
8. Verify configurations using appropriete log files

## Module 7:
1. Create 7-zip application
2. Create VLC Media Player application
3. Create Office 365 Pro Plus application
4. Create Driver Package with Dell WINPE drivers
5. Install MDT and integrate it with SCCM
6. Create new MDT boot image
7. Inject Dell WINPE drivers to both MDT boot images (x86/x64)
8. Create Windows 10 computers collection using dynamic membership
9. Install and Configure Software Update Point role to deploy Windows 10 1903 critical and security updates to all Windows 10 computers collection (use ADR)
10. Configure Windows 10 servicing to SAC with 60 days delay.
11. Configure Computer Agent restart using client settings and deploy them to All Systems.
12. Create collection "MDT UDI Apps" with restrictive memberships and deploy all existing applications to this collection.

## Module 8:
1. Create SCCM task sequence to install clean Windows 10 operating system for EFI devices.
2. Create custom UDI wizard with the following settings
   * ComputerName is built based on device serialnumber (first 15 chars)
   * Device encryption using BDE is enabled by default
   * All apps deployed to collection "MDT UDI Apps" are available in wizard for installation
3. Deploy new Windows 10 operating system using built UDI based task sequence
4. Create new Task sequence to support side-by-side migrations.
5. Configure pair of user devices (CL81 -> new computer)
6. Deploy new computer and migrate the user data.
7. Create new Task sequence to support inplace upgrade of Windows 7 to Windows 10 and configure the windows setup to run with high priority
8. Configure the environment to support the Windows 10 servicing with high priority process start.

## Module 9:
1. Create new task sequence to upgrade the Dell devices' firmware to the latest version and reconfigure the boot to EFI native, turn on Intel-VT and clear TPM. Configure this task sequence to start disk encryption as soon as possible and to store the recovery keys to Active Directory.
2. Edit the existing in-place upgrade task sequence to convert the computer boot to EFI native.