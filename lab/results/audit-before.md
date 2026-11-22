# Linux hardening audit: vps-lab

- Date: 2026-11-22T07:27:52Z
- Audited root: `/`
- Score: **44/100** (8 pass, 9 warn, 11 fail, 0 skipped)

## Findings to fix

| ID | Severity | Status | Finding | Detail | Remediation |
|----|----------|--------|---------|--------|-------------|
| SSH-01 | high | FAIL | Root login over SSH allowed | PermitRootLogin yes | Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd. |
| SSH-02 | high | FAIL | Password authentication enabled | PasswordAuthentication yes | Use SSH keys and set 'PasswordAuthentication no'. This removes the brute-force attack surface. |
| ACC-02 | high | FAIL | Accounts with empty passwords | accounts: test | Lock them with 'passwd -l <user>' or set a password. |
| SVC-01 | high | FAIL | No active host firewall | ufw/firewalld/nftables/iptables not filtering input | Enable a default-deny firewall, e.g. 'ufw default deny incoming && ufw allow OpenSSH && ufw enable'. |
| SSH-04 | medium | WARN | MaxAuthTries is higher than 4 | MaxAuthTries 10 | Set 'MaxAuthTries 4' (or lower). |
| ACC-04 | medium | WARN | Passwordless sudo rules found | NOPASSWD for: deploy | Limit NOPASSWD to specific commands for service accounts only. |
| FS-_etc_shadow | medium | FAIL | Permissions on /etc/shadow are too open | mode 644, expected 640 or stricter | chmod 640 /etc/shadow |
| FS-WW | medium | FAIL | World-writable files in /etc | /etc/app.conf | chmod o-w on these files. |
| KRN-02 | medium | FAIL | TCP SYN cookies enabled | net.ipv4.tcp_syncookies = 0, expected 1 | Add 'net.ipv4.tcp_syncookies = 1' to /etc/sysctl.d/60-hardening.conf, then run 'sysctl --system'. |
| SVC-02 | medium | WARN | fail2ban not running | no automatic ban of brute-force sources | apt install fail2ban, enable the sshd jail. |
| SVC-03 | medium | WARN | auditd not running | security events are not audited | apt install auditd && systemctl enable --now auditd |
| UPD-02 | medium | WARN | Unattended upgrades not enabled | 20auto-upgrades missing or disabled | apt install unattended-upgrades && dpkg-reconfigure unattended-upgrades |
| SSH-05 | low | WARN | X11 forwarding enabled | X11Forwarding yes | Set 'X11Forwarding no' on servers. |
| SSH-06 | low | WARN | LoginGraceTime is longer than 60s | LoginGraceTime 120 | Set 'LoginGraceTime 60'. |
| ACC-03 | low | WARN | Passwords never expire | PASS_MAX_DAYS 99999 | Set PASS_MAX_DAYS 365 (or your policy) in /etc/login.defs. |
| FS-TMP | low | WARN | Sticky bit missing on /tmp | mode 777 | chmod 1777 /tmp |
| KRN-03 | low | FAIL | ICMP redirects ignored | net.ipv4.conf.all.accept_redirects = 1, expected 0 | Add 'net.ipv4.conf.all.accept_redirects = 0' to /etc/sysctl.d/60-hardening.conf, then run 'sysctl --system'. |
| KRN-04 | low | FAIL | ICMP redirects not sent | net.ipv4.conf.all.send_redirects = 1, expected 0 | Add 'net.ipv4.conf.all.send_redirects = 0' to /etc/sysctl.d/60-hardening.conf, then run 'sysctl --system'. |
| KRN-05 | low | FAIL | Source-routed packets rejected | net.ipv4.conf.all.accept_source_route = 1, expected 0 | Add 'net.ipv4.conf.all.accept_source_route = 0' to /etc/sysctl.d/60-hardening.conf, then run 'sysctl --system'. |
| KRN-06 | low | FAIL | Martian packets logged | net.ipv4.conf.all.log_martians = 0, expected 1 | Add 'net.ipv4.conf.all.log_martians = 1' to /etc/sysctl.d/60-hardening.conf, then run 'sysctl --system'. |

## All checks

| ID | Category | Status | Check | Detail |
|----|----------|--------|-------|--------|
| SSH-01 | SSH | FAIL | Root login over SSH allowed | PermitRootLogin yes |
| SSH-02 | SSH | FAIL | Password authentication enabled | PasswordAuthentication yes |
| SSH-03 | SSH | PASS | Empty passwords rejected | PermitEmptyPasswords no |
| SSH-04 | SSH | WARN | MaxAuthTries is higher than 4 | MaxAuthTries 10 |
| SSH-05 | SSH | WARN | X11 forwarding enabled | X11Forwarding yes |
| SSH-06 | SSH | WARN | LoginGraceTime is longer than 60s | LoginGraceTime 120 |
| ACC-01 | Accounts | PASS | Only root has UID 0 | no other UID 0 accounts |
| ACC-02 | Accounts | FAIL | Accounts with empty passwords | accounts: test |
| ACC-03 | Accounts | WARN | Passwords never expire | PASS_MAX_DAYS 99999 |
| ACC-04 | Accounts | WARN | Passwordless sudo rules found | NOPASSWD for: deploy |
| FS-_etc_passwd | Filesystem | PASS | Permissions on /etc/passwd | mode 644, expected 644 or stricter |
| FS-_etc_group | Filesystem | PASS | Permissions on /etc/group | mode 644, expected 644 or stricter |
| FS-_etc_shadow | Filesystem | FAIL | Permissions on /etc/shadow are too open | mode 644, expected 640 or stricter |
| FS-_etc_gshadow | Filesystem | PASS | Permissions on /etc/gshadow | mode 640, expected 640 or stricter |
| FS-_etc_ssh_sshd_config | Filesystem | PASS | Permissions on /etc/ssh/sshd_config | mode 644, expected 644 or stricter |
| FS-WW | Filesystem | FAIL | World-writable files in /etc | /etc/app.conf |
| FS-TMP | Filesystem | WARN | Sticky bit missing on /tmp | mode 777 |
| KRN-01 | Kernel | PASS | ASLR fully enabled | kernel.randomize_va_space = 2 |
| KRN-02 | Kernel | FAIL | TCP SYN cookies enabled | net.ipv4.tcp_syncookies = 0, expected 1 |
| KRN-03 | Kernel | FAIL | ICMP redirects ignored | net.ipv4.conf.all.accept_redirects = 1, expected 0 |
| KRN-04 | Kernel | FAIL | ICMP redirects not sent | net.ipv4.conf.all.send_redirects = 1, expected 0 |
| KRN-05 | Kernel | FAIL | Source-routed packets rejected | net.ipv4.conf.all.accept_source_route = 1, expected 0 |
| KRN-06 | Kernel | FAIL | Martian packets logged | net.ipv4.conf.all.log_martians = 0, expected 1 |
| SVC-01 | Services | FAIL | No active host firewall | ufw/firewalld/nftables/iptables not filtering input |
| SVC-02 | Services | WARN | fail2ban not running | no automatic ban of brute-force sources |
| SVC-03 | Services | WARN | auditd not running | security events are not audited |
| SVC-04 | Services | INFO | Ports listening on external interfaces | 22 8080  |
| UPD-01 | Updates | PASS | No pending security updates | apt-get -s upgrade |
| UPD-02 | Updates | WARN | Unattended upgrades not enabled | 20auto-upgrades missing or disabled |
