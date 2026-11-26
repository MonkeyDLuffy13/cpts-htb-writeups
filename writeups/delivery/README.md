# Delivery — when the helpdesk becomes your mailbox

[![Difficulty](https://img.shields.io/badge/difficulty-Medium-yellow)](https://app.hackthebox.com/machines/delivery)
[![OS](https://img.shields.io/badge/OS-Linux-blue)](https://app.hackthebox.com/machines/delivery)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=gbs43E71mFM)

> **Attack path:** osTicket ticket → `@delivery.htb` email address → Mattermost account
> activation → SSH creds leaked in a chat channel → MariaDB root bcrypt hash cracked with
> hashcat rules → `su root`.

Credentials and flags are intentionally redacted as `<password>` / `<flag>` / `<hash>` —
you should recover them yourself while working the box.

## 1 · Reconnaissance

Full TCP scan plus service/version detection on the three open ports:

```bash
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.222
nmap -p 22,80,8065 -sC -sV -oA scans/nmap-tcpscans 10.10.10.222
```

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http    nginx 1.14.2
|_http-title: Welcome
8065/tcp open  unknown
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.0 200 OK
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Mattermost
```

- Port 80 is a simple "Delivery" welcome/portal page.
- Port 8065 fingerprints as a **Mattermost** chat server (version 5.30.0).

The portal on port 80 links to two services that use DNS names, so add them to `/etc/hosts`:

```text
10.10.10.222 delivery.htb helpdesk.delivery.htb
```

- `http://delivery.htb/` — the portal.
- `http://helpdesk.delivery.htb/` — an **osTicket** v1.14.1 support center.
- `http://delivery.htb:8065/` — Mattermost (open registration, but new accounts must
  verify an email address before logging in).

The whole box hinges on one design decision: every address `*@delivery.htb` is handled by
the mail stack feeding osTicket, so mail sent to such an address ends up attached to a
support ticket that *you* can read from the helpdesk web UI.

## 2 · Foothold

### Create a Mattermost account

On `http://delivery.htb:8065/signup_user_complete` pick a username (e.g. `0xdf`). Because
the instance only controls the `delivery.htb` domain, Mattermost tells you the activation
email was sent to `<username>@delivery.htb` — an address that does not exist anywhere
except on this box.

### Open an osTicket ticket with that address

At `http://helpdesk.delivery.htb/` choose **Open a New Ticket** and submit any contact
information using `<username>@delivery.htb` as the email. osTicket creates the ticket and
displays a ticket ID (format like `6HJ7YSAI`). Note it.

### Read the activation email through the ticket

The Mattermost activation mail is delivered locally and attached to your ticket thread.
On the helpdesk click **Check Ticket Status** (or browse to
`http://helpdesk.delivery.htb/tickets.php`) and log in with the email + ticket ID. The
ticket thread now contains the Mattermost message with an account-verification link.
Click it, then log in to Mattermost.

### Harvest credentials from chat

Join the team shown on signup (the internal team) and scroll the channels. An internal
conversation contains SSH credentials for a local account:

```text
username: maildeliverer
password: <password>
```

The same channels also discuss password practices — remember that for privesc.

## 3 · User flag

```bash
ssh maildeliverer@delivery.htb
# password: <password>

maildeliverer@Delivery:~$ id
uid=1000(maildeliverer) gid=1000(maildeliverer) groups=1000(maildeliverer)

maildeliverer@Delivery:~$ cat /home/maildeliverer/user.txt
<flag>
```

## 4 · Privilege escalation

### First checks

```bash
sudo -l
```

`maildeliverer` has **no** sudo rules — the privesc is a credential problem, not a
misconfigured-binary problem. Pivot to enumerating the Mattermost installation:

```bash
ls -l /opt/mattermost/config/config.json
grep -i '"DataSource"' /opt/mattermost/config/config.json
```

The config file is world-readable and contains the MariaDB connection string, including
the application's database credentials (`mmuser` / `<password>`).

### Dump the Mattermost database

```bash
mysql -u mmuser -p
```

```sql
show databases;
use mattermost;
show tables;
select Username, Password from Users;
```

The `Users` table holds bcrypt (`$2a$10$...`) hashes for every account, including the
local `root` user:

```text
root | <hash>
```

Save it in `hash` with the username prefix (`root:<hash>`).

### Crack with a hint from the chat

The Mattermost channels mention that the root password is based on the base phrase
`PleaseSubscribe!` with minor mutations. Put the base word in its own wordlist and let a
hashcat rule generate the mutations:

```bash
echo 'PleaseSubscribe!' > password
hashcat -m 3200 hash password --user -r /usr/share/hashcat/rules/best64.rule
```

`best64.rule` appends the classic suffixes and cracks the bcrypt hash quickly:

```text
<hash>:<password>
```

## 5 · Root flag

The cracked database password is reused as the local root password:

```bash
maildeliverer@Delivery:/$ su -
Password: <password>

root@Delivery:~# cat /root/root.txt
<flag>
```

## 6 · Impact & remediation

| Risk | Impact | Remediation |
| --- | --- | --- |
| Any unauthenticated visitor can obtain an `@delivery.htb` mailbox via a support ticket | Account takeover of every service that verifies ownership through that domain | Disable open ticket creation or external email-based verification; require staff vetting |
| SSH credentials shared in a chat channel | Direct foothold as `maildeliverer` for anyone who can register on Mattermost | Never share credentials in chat; use a secrets manager and rotate the exposed account |
| World-readable `/opt/mattermost/config/config.json` with DB credentials | Low-privilege shell can dump all user password hashes | Restrict config permissions to the service account; use a dedicated low-privilege DB user |
| Root password derived from a guessable base word (`best64`-crackable) | Full system compromise from a single cracked hash | Enforce long, random, unique passwords; never base real passwords on public phrases |
| Self-service Mattermost registration exposed to the internet | Anonymous users reach internal conversations | Place internal chat behind SSO/VPN and invite-only team join |

## 7 · CPTS takeaways

- Chaining two unrelated web apps through a **shared trust anchor** (one email domain) is
  a classic CPTS-style move — always map how email flows between exposed services.
- After a low-priv shell, enumerate application install dirs (`/opt/*`, config files)
  before reaching for kernel exploits; the DB password usually lives next to the app.
- `hashcat -m 3200` (bcrypt) with `--user` plus a rules file (`-r best64.rule`) turns a
  human hint into a crack strategy — the exam expects rule-based cracking, not just
  straight rockyou runs.
- Password reuse (chat → SSH, DB → root) is the real vulnerability on this box; credential
  reuse attacks are a core CPTS objective.
- Report-wise, this is a "credential hygiene" narrative: open registration, secrets in
  chat, weak derivation — a full finding set without a single memory-corruption bug.
