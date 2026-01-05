\# PowerShell-Domain-Controller-Audit-Script

\# A PowerShell script which can be copied/pasted into a PowerShell console window and retrieve auditable domain controller server configuration settings. This script only runs a series a queries (it does not make any modifications) and then creates a folder on the currently logged in user's desktop nameded after the computer name which can then be zipped and uploaded as supporting documentation.

\# PLEASE NOTE:

\# This script needs to be run as a Domain Administrator on each Domain Controller being audited seperately.

\# Search for: c:\windows\system32\windowspowershell\v1.0\powershell.exe, right click the application result and select "run as administrator".

\# Next, simply copy the entire blob of text below and paste into the PowerShell window.

```

$path = "C:\\temp\\$env:computername DC Audit"
New-Item -ItemType directory -Path $path

Net LocalGroup Administrators | Out-File "$path\1.Local_Admins.txt" ;

Get-ADGroupMember -Identity "Administrators" -Recursive | %{Get-ADUser -Identity $_.distinguishedName} | Select Name, Enabled | Out-File "$path\2.Admins.txt" -append ;

Net Group "Domain Admins" | Out-File "$path\2.Admins.txt" -append ;

Get-ADGroupMember -Identity "Domain Admins" -Recursive | %{Get-ADUser -Identity $_.distinguishedName} | Select Name, Enabled | Out-File "$path\2.Admins.txt" -append ;

Net Group "Enterprise Admins" | Out-File "$path\2.Admins.txt" -append ;

Get-ADGroupMember -Identity "Enterprise Admins" -Recursive | %{Get-ADUser -Identity $_.distinguishedName} | Select Name, Enabled | Out-File "$path\2.Admins.txt" -append ;

Get-ADGroupMember -Identity "Guests" -Recursive | %{Get-ADUser -Identity $_.distinguishedName} | Select Name, Enabled | Out-File "$path\3.Guests.txt" ;

systeminfo | Out-File "$path\4.SysteminfoandUpdates.txt" ;

Get-HotFix | Format-table -property Caption, HotFixID, InstalledOn | Out-File "$path\4.SysteminfoandUpdates.txt" -append ; 

gpresult -h "$path\5.DCFollowedGPOs.html" ; 

vaultcmd /listschema | Out-File "$path\6.CredentialManager.txt" ; 

vaultcmd /list | Out-File "$path\6.CredentialManager.txt" -append ; 

net share | Out-File "$path\7.Shares.txt" ; 

dir C:\Users | Out-File "$path\8.UsersOnHost.txt" ; 

netsh advfirewall show allprofiles | Out-File "$path\9.WindowsFirewall.txt" ; 

powercfg /A | Out-File "$path\10.SleepMode.txt" ; 

ipconfig /all | Out-File "$path\11.BridgedAdapters.txt" ; 

get-gporeport -all -reporttype HTML -path "$path\12.DomainGPOs.html" ; 

auditpol.exe /get /category:* | Out-File "$path\13.AuditPolicySettings.txt" ; 

net accounts | Out-File "$path\14.PasswordPolicySettings.txt" ; 

Get-ADDefaultDomainPasswordPolicy | Out-File "$path\14.PasswordPolicySettings.txt" -append

Get-WinEvent -FilterHashtable @{logname = ‘setup’} | Export-CSV "$path\15.Patches.csv"

$zipPath = "$path.zip"
Compress-Archive -Path $path -DestinationPath $zipPath

```
