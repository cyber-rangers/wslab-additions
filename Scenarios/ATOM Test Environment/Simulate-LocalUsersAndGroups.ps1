param(
    [switch]$CreateLocalUsersAndAddThemToGroups,
    [switch]$RemoveLocalUsersFromGroupsOnly,
    [switch]$RemoveLocalUsers
)
if ($CreateLocalUsersAndAddThemToGroups) {
    $adminusername = "LocAdmin$(Get-Random -Maximum 9999)"
    $rdpusername = "LocRDUser$(Get-Random -Maximum 9999)"
    $userpassword = 'P@ssw0rd'

    $adminusername | out-file C:\atom-simulate-localadmin.txt
    $rdpusername | out-file C:\atom-simulate-localrduser.txt

    New-LocalUser -FullName $adminusername -AccountNeverExpires -Name $adminusername -Password (ConvertTo-SecureString -AsPlainText -Force -String $userpassword) -PasswordNeverExpires
    Add-LocalGroupMember -Group 'Administrators' -Member $adminusername

    New-LocalUser -FullName $rdpusername -AccountNeverExpires -Name $rdpusername -Password (ConvertTo-SecureString -AsPlainText -Force -String $userpassword) -PasswordNeverExpires
    Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $rdpusername
}

if ($RemoveLocalUsersFromGroupsOnly) {
    Remove-LocalGroupMember -Group 'Administrators' -Member (Get-Content C:\atom-simulate-localadmin.txt)
    Remove-LocalGroupMember -Group 'Remote Desktop Users' -Member (Get-Content C:\atom-simulate-localrduser.txt)
}

if ($RemoveLocalUsers) {
    Remove-LocalUser -Name (Get-Content C:\atom-simulate-localadmin.txt)
    Remove-LocalUser -Name (Get-Content C:\atom-simulate-localrduser.txt)
}
