\# PowerShell-Domain-Controller-Audit-Script

\# A PowerShell script which can be copied/pasted into a PowerShell console window and retrieve auditable domain controller server configuration settings. This script only runs a series a queries (it does not make any modifications) and then creates a folder on the currently logged in user's desktop nameded after the computer name which can then be zipped and uploaded as supporting documentation.

\# PLEASE NOTE:

\# This script needs to be run as a Domain Administrator on each Domain Controller being audited seperately.

\# Search for: c:\windows\system32\windowspowershell\v1.0\powershell.exe, right click the application result and select "run as administrator".

\# Next, simply copy the entire blob of text below and paste into the PowerShell window.

New-Item -ItemType directory -Path "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit" ;

Net LocalGroup Administrators | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\1.Local_Admins.txt" ;

Get-ADGroupMember -Identity "Administrators" -Recursive | %{Get-ADUser -Identity $\_.distinguishedName} | Select Name, Enabled | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\2.Admins.txt" -append ;

Net Group "Domain Admins" | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\2.Admins.txt" -append ;

Get-ADGroupMember -Identity "Domain Admins" -Recursive | %{Get-ADUser -Identity $\_.distinguishedName} | Select Name, Enabled | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\2.Admins.txt" -append ;

Net Group "Enterprise Admins" | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\2.Admins.txt" -append ;

Get-ADGroupMember -Identity "Enterprise Admins" -Recursive | %{Get-ADUser -Identity $\_.distinguishedName} | Select Name, Enabled | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\2.Admins.txt" -append ;

Get-ADGroupMember -Identity "Guests" -Recursive | %{Get-ADUser -Identity $\_.distinguishedName} | Select Name, Enabled | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\3.Guests.txt" ;

systeminfo | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\4.SysteminfoandUpdates.txt" ;

wmic qfe list | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\4.SysteminfoandUpdates.txt" -append ; 

gpresult -h "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\5.DCFollowedGPOs.html" ; 

vaultcmd /listschema | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\6.CredentialManager.txt" ; 

vaultcmd /list | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\6.CredentialManager.txt" -append ; 

net share | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\7.Shares.txt" ; 

dir C:\Users | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\8.UsersOnHost.txt" ; 

netsh advfirewall show allprofiles | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\9.WindowsFirewall.txt" ; 

powercfg /A | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\10.SleepMode.txt" ; 

ipconfig /all | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\11.BridgedAdapters.txt" ; 

get-gporeport -all -reporttype HTML -path "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\12.DomainGPOs.html" ; 

auditpol.exe /get /category:* | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\13.AuditPolicySettings.txt" ; 

net accounts | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\14.PasswordPolicySettings.txt" ; 

Get-ADDefaultDomainPasswordPolicy | Out-File "$($env:USERPROFILE)\Desktop\\$env:computername DC Audit\14.PasswordPolicySettings.txt" -append
