# CPTS Prep — HTB Lab Writeups

[![Playlist](https://img.shields.io/badge/Playlist-Unofficial_CPTS_Prep-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/playlist?list=PLidcsTyj9JXItWpbRtTg6aDEj10_F17x5)
![Machines](https://img.shields.io/badge/machines-22-blue)
![Writeups](https://img.shields.io/badge/writeups-22%2F22-brightgreen)

Structured, reproducible walkthroughs for the 22 Hack The Box machines in the
[**Unofficial CPTS Prep**](https://www.youtube.com/playlist?list=PLidcsTyj9JXItWpbRtTg6aDEj10_F17x5)
playlist (walkthroughs by [IppSec](https://www.youtube.com/@ippsec)).

These write-ups follow the playlist's attack paths step by step — commands,
reasoning, and the report-style impact/remediation view — as preparation for the
**HTB Certified Penetration Testing Specialist (CPTS)** exam.

> 🔐 **Flags are redacted** (`<flag>`) — spin the machine up and earn them yourself;
> that's the whole point of the prep. Credential values quoted in commands come from
> the public walkthroughs of these retired machines.

## Index

### Track 1 — Active Directory core *(the heart of the CPTS exam)*

| # | Machine | OS | Difficulty | Focus | Write-up | Video |
|---|---------|----|------------|-------|----------|-------|
| 1 | Forest | Windows | Easy | AS-REP Roasting · WinRM · DCSync | [writeup](writeups/forest/) | [IppSec](https://www.youtube.com/watch?v=H9FcE_FMZio) |
| 2 | Active | Windows | Easy | GPP cpassword · Kerberoasting · DCSync | [writeup](writeups/active/) | [IppSec](https://www.youtube.com/watch?v=jUc1J31DNdw) |
| 3 | Blackfield | Windows | Hard | AS-REP · BloodHound · LSASS dump · SeBackupPrivilege | [writeup](writeups/blackfield/) | [IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w) |
| 4 | Manager | Windows | Medium | MSSQL recon · password spray · AD CS ESC7 | [writeup](writeups/manager/) | [IppSec](https://www.youtube.com/watch?v=lT2Tv0m4k7M) |
| 5 | Administrator | Windows | Medium | assume-breach ACL chain → DCSync | [writeup](writeups/administrator/) | [IppSec](https://www.youtube.com/watch?v=Miam4nw9pmE) |
| 6 | Outdated | Windows | Medium | Follina phishing · shadow credentials · WSUS abuse | [writeup](writeups/outdated/) | [IppSec](https://www.youtube.com/watch?v=TR132R1h3Ds) |
| 7 | Vintage | Windows | Hard | machine password · gMSA · targeted Kerberoast · RBCD | [writeup](writeups/vintage/) | [IppSec](https://www.youtube.com/watch?v=-JM--KfVhpA) |

### Track 2 — Windows foothold & privilege escalation

| # | Machine | OS | Difficulty | Focus | Write-up | Video |
|---|---------|----|------------|-------|----------|-------|
| 8 | Remote | Windows | Easy | NFS leak · Umbraco RCE · TeamViewer decrypt | [writeup](writeups/remote/) | [IppSec](https://www.youtube.com/watch?v=iyYqgseKUPM) |
| 9 | Access | Windows | Medium | FTP mdb leak · PST mail · runas /savecred | [writeup](writeups/access/) | [IppSec](https://www.youtube.com/watch?v=Rr6Oxrj2IjU) |
| 10 | Driver | Windows | Easy | printer panel · .scf NTLM leak · driver hijack | [writeup](writeups/driver/) | [IppSec](https://www.youtube.com/watch?v=N2ahkarb-zI) |
| 11 | Sekhmet | Windows | Insane | node-serialize RCE · sssd abuse · LDAP injection · DPAPI | [writeup](writeups/sekhmet/) | [IppSec](https://www.youtube.com/watch?v=vsgPsMZx59w) |
| 12 | Hospital | Windows | Medium | .phar upload · kernel privesc · Ghostscript phishing | [writeup](writeups/hospital/) | [IppSec](https://www.youtube.com/watch?v=E8h0qWsBz6c) |

### Track 3 — Linux & web exploitation

| # | Machine | OS | Difficulty | Focus | Write-up | Video |
|---|---------|----|------------|-------|----------|-------|
| 13 | Soccer | Linux | Easy | Tiny File Manager · WebSocket SQLi · doas dstat | [writeup](writeups/soccer/) | [IppSec](https://www.youtube.com/watch?v=V_CkT7xyiCc) |
| 14 | Delivery | Linux | Medium | helpdesk mail enum · Mattermost · config reuse | [writeup](writeups/delivery/) | [IppSec](https://www.youtube.com/watch?v=gbs43E71mFM) |
| 15 | MetaTwo | Linux | Easy | BookingPress SQLi · WordPress XXE · vault crack | [writeup](writeups/metatwo/) | [IppSec](https://www.youtube.com/watch?v=Alx5KQWq7ZM) |
| 16 | Shoppy | Linux | Easy | NoSQL injection · credential reuse · docker group | [writeup](writeups/shoppy/) | [IppSec](https://www.youtube.com/watch?v=AJc53DUdt1M) |
| 17 | Agile | Linux | Easy | path traversal · Werkzeug PIN · session theft | [writeup](writeups/agile/) | [IppSec](https://www.youtube.com/watch?v=ob-CwobmkKk) |
| 18 | Trick | Linux | Easy | SQLi + LFI · mail poisoning · fail2ban hijack | [writeup](writeups/trick/) | [IppSec](https://www.youtube.com/watch?v=ai98umjeO8M) |
| 19 | UHC — Union | Linux | Event | SQLi · X-Forwarded-For command injection | [writeup](writeups/uhc-union/) | [IppSec](https://www.youtube.com/watch?v=z5pdizHDvt8) |
| 20 | UHC — Pressed | Linux | Event | wp-config leak · XML-RPC abuse · PwnKit | [writeup](writeups/uhc-pressed/) | [IppSec](https://www.youtube.com/watch?v=p8mIdm93mfw) |
| 21 | UHC — LogForge | Linux | Event | Log4Shell ×2 · Tomcat path confusion | [writeup](writeups/uhc-logforge/) | [IppSec](https://www.youtube.com/watch?v=XG14EstTgQ4) |

### Track 4 — Insane: containers & pivoting

| # | Machine | OS | Difficulty | Focus | Write-up | Video |
|---|---------|----|------------|-------|----------|-------|
| 22 | Reddish | Linux | Insane | Node-RED RCE · Redis pivot · rsync injection · container escape | [writeup](writeups/reddish/) | [IppSec](https://www.youtube.com/watch?v=Yp4oxoQIBAM) |

## Exam skill map

| CPTS exam skill | Practice on |
|---|---|
| External reconnaissance & enumeration | every box — always go deeper than the nmap summary |
| Web application attacks | Soccer · MetaTwo · Shoppy · Agile · Pressed · Delivery |
| Password attacks & cracking | Forest · Active · Blackfield · Manager · Shoppy |
| AD exploitation & lateral movement | Track 1 — Forest → Vintage, in order |
| Windows privilege escalation | Driver · Access · Hospital · Sekhmet |
| Post-exploitation & pivoting | Reddish |

## Notes

- Write-ups follow the playlist's attack paths, cross-checked against public
  walkthroughs (0xdf and others), and are for **educational purposes only** on
  intentionally vulnerable lab environments.
- Difficulty ratings reflect the HTB rating at release.
- Everything is reproducible with **free tooling** (Impacket, evil-winrm,
  BloodHound, certipy, hashcat, ...) — no paid licenses required.

## License

[MIT](LICENSE)
