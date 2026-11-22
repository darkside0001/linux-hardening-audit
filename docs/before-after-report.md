# Hardening report: before and after

Target: `vps-lab`, a throwaway Ubuntu 24.04 container built to look like a freshly
provisioned VPS with common mistakes ([`lab/Dockerfile`](../lab/Dockerfile)).
Everything below is produced by [`lab/run-before-after.sh`](../lab/run-before-after.sh):
audit, harden with [`harden.sh`](../harden.sh), reboot, audit again. Raw outputs are in
[`lab/results/`](../lab/results/).

- Before: 2026-11-22T07:27:51Z  |  After: 2026-11-22T07:28:11Z

## Result

| | Score | Pass | Warn | Fail |
|---|---|---|---|---|
| Before | **44/100** | 8 | 9 | 11 |
| After | **98/100** | 27 | 1 | 0 |

19 findings fixed, 1 left. High-severity failures: 4 -> 0.

## What an attacker sees from the network

| Check | Before | After |
|---|---|---|
| TCP port 22 | open | open |
| TCP port 8080 | open | closed/filtered |
| ssh auth methods offered | publickey,password | publickey |
| key login as deploy | OK (admin is not locked out) | OK (admin is not locked out) |

Port 8080 is a forgotten development web server. It still runs after hardening, but the
default-deny firewall no longer lets anyone reach it. SSH stops offering password
authentication, and the admin can still log in with a key, so the hardening did not
lock anyone out.

## Check by check

| ID | Severity | Check | Before | After |
|---|---|---|---|---|
| SSH-01 | high | Root login over SSH disabled | **FAIL** PermitRootLogin yes | PASS PermitRootLogin no |
| SSH-02 | high | Password authentication disabled | **FAIL** PasswordAuthentication yes | PASS PasswordAuthentication no |
| SSH-03 | high | Empty passwords rejected | PASS PermitEmptyPasswords no | PASS PermitEmptyPasswords no |
| SSH-04 | medium | MaxAuthTries is 4 or lower | WARN MaxAuthTries 10 | PASS MaxAuthTries 4 |
| SSH-05 | low | X11 forwarding disabled | WARN X11Forwarding yes | PASS X11Forwarding no |
| SSH-06 | low | LoginGraceTime is 60s or less | WARN LoginGraceTime 120 | PASS LoginGraceTime 30 |
| ACC-01 | high | Only root has UID 0 | PASS no other UID 0 accounts | PASS no other UID 0 accounts |
| ACC-02 | high | No accounts with empty passwords | **FAIL** accounts: test | PASS checked /etc/shadow |
| ACC-03 | low | Password maximum age is set | WARN PASS_MAX_DAYS 99999 | PASS PASS_MAX_DAYS 365 |
| ACC-04 | medium | No passwordless sudo rules | WARN NOPASSWD for: deploy | PASS no NOPASSWD entries |
| FS-_etc_passwd | medium | Permissions on /etc/passwd | PASS mode 644, expected 644 or stricter | PASS mode 644, expected 644 or stricter |
| FS-_etc_group | medium | Permissions on /etc/group | PASS mode 644, expected 644 or stricter | PASS mode 644, expected 644 or stricter |
| FS-_etc_shadow | medium | Permissions on /etc/shadow | **FAIL** mode 644, expected 640 or stricter | PASS mode 640, expected 640 or stricter |
| FS-_etc_gshadow | medium | Permissions on /etc/gshadow | PASS mode 640, expected 640 or stricter | PASS mode 640, expected 640 or stricter |
| FS-_etc_ssh_sshd_config | medium | Permissions on /etc/ssh/sshd_config | PASS mode 644, expected 644 or stricter | PASS mode 600, expected 644 or stricter |
| FS-WW | medium | No world-writable files in /etc | **FAIL** /etc/app.conf | PASS find /etc -perm -0002 |
| FS-TMP | low | Sticky bit set on /tmp | WARN mode 777 | PASS mode 1777 |
| KRN-01 | medium | ASLR fully enabled | PASS kernel.randomize_va_space = 2 | PASS kernel.randomize_va_space = 2 |
| KRN-02 | medium | TCP SYN cookies enabled | **FAIL** net.ipv4.tcp_syncookies = 0, expected 1 | PASS net.ipv4.tcp_syncookies = 1 |
| KRN-03 | low | ICMP redirects ignored | **FAIL** net.ipv4.conf.all.accept_redirects = 1, expected 0 | PASS net.ipv4.conf.all.accept_redirects = 0 |
| KRN-04 | low | ICMP redirects not sent | **FAIL** net.ipv4.conf.all.send_redirects = 1, expected 0 | PASS net.ipv4.conf.all.send_redirects = 0 |
| KRN-05 | low | Source-routed packets rejected | **FAIL** net.ipv4.conf.all.accept_source_route = 1, expected 0 | PASS net.ipv4.conf.all.accept_source_route = 0 |
| KRN-06 | low | Martian packets logged | **FAIL** net.ipv4.conf.all.log_martians = 0, expected 1 | PASS net.ipv4.conf.all.log_martians = 1 |
| SVC-01 | high | Host firewall active | **FAIL** ufw/firewalld/nftables/iptables not filtering input | PASS nftables |
| SVC-02 | medium | fail2ban running | WARN no automatic ban of brute-force sources | PASS brute-force protection active |
| SVC-03 | medium | auditd not running | WARN security events are not audited | WARN security events are not audited |
| SVC-04 | low | Ports listening on external interfaces | INFO 22 8080  | INFO 22 8080  |
| UPD-01 | high | No pending security updates | PASS apt-get -s upgrade | PASS apt-get -s upgrade |
| UPD-02 | medium | Unattended security upgrades enabled | WARN 20auto-upgrades missing or disabled | PASS 20auto-upgrades |

## What harden.sh changed

```
CHANGED  sshd: root login off, password login no, MaxAuthTries 4, no X11 (00-hardening.conf)
CHANGED  lock account 'test' (empty password)
CHANGED  login.defs: PASS_MAX_DAYS 365 (new accounts)
CHANGED  sudo: require a password in /etc/sudoers.d/90-deploy (NOPASSWD removed)
CHANGED  chmod 640 /etc/shadow (was 644)
CHANGED  chmod 600 /etc/ssh/sshd_config (was 644)
CHANGED  remove world-write bit from /etc/app.conf
CHANGED  set sticky bit on /tmp (was 777)
CHANGED  kernel network parameters (/etc/sysctl.d/60-hardening.conf)
NOTE     sysctl not writable here (container?), applied at next boot
CHANGED  nftables: default-deny inbound, allow SSH (rate limited)
CHANGED  fail2ban: sshd jail, 5 failures in 10 min -> 1 h ban
CHANGED  unattended-upgrades: daily security updates
RUN      apt-get update && apt-get upgrade (security updates)
```

Every changed file was backed up first (`/var/backups/hardening-<timestamp>/`). The
SSH drop-in was validated with `sshd -t` and the sudoers change with `visudo -c`
before being kept. Password login was disabled only after the script confirmed that
a sudo user has an `authorized_keys` file.

## Still open, and why

- **SVC-03 auditd not running** (security events are not audited).
- harden.sh: Firewall allows only SSH inbound. Open the ports your services need in /etc/nftables.conf.
- harden.sh: auditd needs the host kernel's audit subsystem; not started inside a container.

## Lab notes

- A container has no systemd, so `lab-init` plays its role: it starts sshd on every boot,
  and the firewall and fail2ban once harden.sh has enabled them.
- "Reboot" = the container's disk is committed to an image and started again with the
  values from `/etc/sysctl.d/60-hardening.conf` (network parameters are per network
  namespace). `kernel.randomize_va_space` belongs to the host kernel and was already 2.
- auditd needs the host kernel's audit subsystem, so it cannot run inside a container;
  on a VM, harden.sh enables it with systemd.
