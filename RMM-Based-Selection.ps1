
$path = "C:\temp\RehmannDCSelection"
New-Item -ItemType directory -Path $path


Net LocalGroup Administrators | Out-File "$path\1.Local_Admins.txt" ;

Get-ADGroupMember -Identity "Administrators" -Recursive | %{Get-ADUser -Identity $_.distinguishedName} | Select Name, Enabled | Out-File "$path\2.Admins.txt" -append ;

Net Group "Domain Admins" | Out-File "$path\2.Admins.txt" -append ;

Get-ADGroupMember -Identity "Domain Admins" -Recursive | %{Get-ADUser -Identity $_.distinguishedName} | Select Name, Enabled | Out-File "$path\2.Admins.txt" -append ;

Net Group "Enterprise Admins" | Out-File "$path\2.Admins.txt" -append ;

Get-ADGroupMember -Identity "Enterprise Admins" -Recursive | %{Get-ADUser -Identity $_.distinguishedName} | Select Name, Enabled | Out-File "$path\2.Admins.txt" -append ;

Get-ADGroupMember -Identity "Guests" -Recursive | %{Get-ADUser -Identity $_.distinguishedName} | Select Name, Enabled | Out-File "$path\3.Guests.txt" ;

systeminfo | Out-File "$path\4.SysteminfoandUpdates.txt" ;

wmic qfe list | Out-File "$path\4.SysteminfoandUpdates.txt" -append ; 

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