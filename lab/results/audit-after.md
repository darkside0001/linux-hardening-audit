# Linux hardening audit: vps-lab

- Date: 2026-11-22T07:32:13Z
- Audited root: `/`
- Score: **98/100** (27 pass, 1 warn, 0 fail, 0 skipped)

## Findings to fix

| ID | Severity | Status | Finding | Detail | Remediation |
|----|----------|--------|---------|--------|-------------|
| SVC-03 | medium | WARN | auditd not running | security events are not audited | apt install auditd && systemctl enable --now auditd |

## All checks

| ID | Category | Status | Check | Detail |
|----|----------|--------|-------|--------|
| SSH-01 | SSH | PASS | Root login over SSH disabled | PermitRootLogin no |
| SSH-02 | SSH | PASS | Password authentication disabled | PasswordAuthentication no |
| SSH-03 | SSH | PASS | Empty passwords rejected | PermitEmptyPasswords no |
| SSH-04 | SSH | PASS | MaxAuthTries is 4 or lower | MaxAuthTries 4 |
| SSH-05 | SSH | PASS | X11 forwarding disabled | X11Forwarding no |
| SSH-06 | SSH | PASS | LoginGraceTime is 60s or less | LoginGraceTime 30 |
| ACC-01 | Accounts | PASS | Only root has UID 0 | no other UID 0 accounts |
| ACC-02 | Accounts | PASS | No accounts with empty passwords | checked /etc/shadow |
| ACC-03 | Accounts | PASS | Password maximum age is set | PASS_MAX_DAYS 365 |
| ACC-04 | Accounts | PASS | No passwordless sudo rules | no NOPASSWD entries |
| FS-_etc_passwd | Filesystem | PASS | Permissions on /etc/passwd | mode 644, expected 644 or stricter |
| FS-_etc_group | Filesystem | PASS | Permissions on /etc/group | mode 644, expected 644 or stricter |
| FS-_etc_shadow | Filesystem | PASS | Permissions on /etc/shadow | mode 640, expected 640 or stricter |
| FS-_etc_gshadow | Filesystem | PASS | Permissions on /etc/gshadow | mode 640, expected 640 or stricter |
| FS-_etc_ssh_sshd_config | Filesystem | PASS | Permissions on /etc/ssh/sshd_config | mode 600, expected 644 or stricter |
| FS-WW | Filesystem | PASS | No world-writable files in /etc | find /etc -perm -0002 |
| FS-TMP | Filesystem | PASS | Sticky bit set on /tmp | mode 1777 |
| KRN-01 | Kernel | PASS | ASLR fully enabled | kernel.randomize_va_space = 2 |
| KRN-02 | Kernel | PASS | TCP SYN cookies enabled | net.ipv4.tcp_syncookies = 1 |
| KRN-03 | Kernel | PASS | ICMP redirects ignored | net.ipv4.conf.all.accept_redirects = 0 |
| KRN-04 | Kernel | PASS | ICMP redirects not sent | net.ipv4.conf.all.send_redirects = 0 |
| KRN-05 | Kernel | PASS | Source-routed packets rejected | net.ipv4.conf.all.accept_source_route = 0 |
| KRN-06 | Kernel | PASS | Martian packets logged | net.ipv4.conf.all.log_martians = 1 |
| SVC-01 | Services | PASS | Host firewall active | nftables |
| SVC-02 | Services | PASS | fail2ban running | brute-force protection active |
| SVC-03 | Services | WARN | auditd not running | security events are not audited |
| SVC-04 | Services | INFO | Ports listening on external interfaces | 22 8080  |
| UPD-01 | Updates | PASS | No pending security updates | apt-get -s upgrade |
| UPD-02 | Updates | PASS | Unattended security upgrades enabled | 20auto-upgrades |
