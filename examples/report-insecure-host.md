# Linux hardening audit: bad-host

- Date: 2026-11-20T06:00:00Z
- Audited root: `tests/fixtures/bad`
- Score: **28/100** (3 pass, 6 warn, 12 fail, 1 skipped)

## Findings to fix

| ID | Severity | Status | Finding | Detail | Remediation |
|----|----------|--------|---------|--------|-------------|
| SSH-01 | high | FAIL | Root login over SSH allowed | PermitRootLogin yes | Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd. |
| SSH-02 | high | FAIL | Password authentication enabled | PasswordAuthentication yes | Use SSH keys and set 'PasswordAuthentication no'. This removes the brute-force attack surface. |
| ACC-01 | high | FAIL | Extra accounts with UID 0 | accounts: toor | Remove or re-number these accounts. Any UID 0 account is a full root account. |
| ACC-02 | high | FAIL | Accounts with empty passwords | accounts: toor | Lock them with 'passwd -l <user>' or set a password. |
| SSH-04 | medium | WARN | MaxAuthTries is higher than 4 | MaxAuthTries 10 | Set 'MaxAuthTries 4' (or lower). |
| ACC-04 | medium | WARN | Passwordless sudo rules found | NOPASSWD for: alice | Limit NOPASSWD to specific commands for service accounts only. |
| FS-_etc_shadow | medium | FAIL | Permissions on /etc/shadow are too open | mode 644, expected 640 or stricter | chmod 640 /etc/shadow |
| FS-WW | medium | FAIL | World-writable files in /etc | /etc/writable.conf | chmod o-w on these files. |
| KRN-01 | medium | FAIL | ASLR fully enabled | kernel.randomize_va_space = 0, expected 2 | Add 'kernel.randomize_va_space = 2' to /etc/sysctl.d/60-hardening.conf, then run 'sysctl --system'. |
| KRN-02 | medium | FAIL | TCP SYN cookies enabled | net.ipv4.tcp_syncookies = 0, expected 1 | Add 'net.ipv4.tcp_syncookies = 1' to /etc/sysctl.d/60-hardening.conf, then run 'sysctl --system'. |
| SSH-05 | low | WARN | X11 forwarding enabled | X11Forwarding yes | Set 'X11Forwarding no' on servers. |
| SSH-06 | low | WARN | LoginGraceTime is longer than 60s | LoginGraceTime 120 | Set 'LoginGraceTime 60'. |
| ACC-03 | low | WARN | Passwords never expire | PASS_MAX_DAYS 99999 | Set PASS_MAX_DAYS 365 (or your policy) in /etc/login.defs. |
| FS-TMP | low | WARN | Sticky bit missing on /tmp | mode 755 | chmod 1777 /tmp |
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
| ACC-01 | Accounts | FAIL | Extra accounts with UID 0 | accounts: toor |
| ACC-02 | Accounts | FAIL | Accounts with empty passwords | accounts: toor |
| ACC-03 | Accounts | WARN | Passwords never expire | PASS_MAX_DAYS 99999 |
| ACC-04 | Accounts | WARN | Passwordless sudo rules found | NOPASSWD for: alice |
| FS-_etc_passwd | Filesystem | PASS | Permissions on /etc/passwd | mode 644, expected 644 or stricter |
| FS-_etc_shadow | Filesystem | FAIL | Permissions on /etc/shadow are too open | mode 644, expected 640 or stricter |
| FS-_etc_ssh_sshd_config | Filesystem | PASS | Permissions on /etc/ssh/sshd_config | mode 644, expected 644 or stricter |
| FS-WW | Filesystem | FAIL | World-writable files in /etc | /etc/writable.conf |
| FS-TMP | Filesystem | WARN | Sticky bit missing on /tmp | mode 755 |
| KRN-01 | Kernel | FAIL | ASLR fully enabled | kernel.randomize_va_space = 0, expected 2 |
| KRN-02 | Kernel | FAIL | TCP SYN cookies enabled | net.ipv4.tcp_syncookies = 0, expected 1 |
| KRN-03 | Kernel | FAIL | ICMP redirects ignored | net.ipv4.conf.all.accept_redirects = 1, expected 0 |
| KRN-04 | Kernel | FAIL | ICMP redirects not sent | net.ipv4.conf.all.send_redirects = 1, expected 0 |
| KRN-05 | Kernel | FAIL | Source-routed packets rejected | net.ipv4.conf.all.accept_source_route = 1, expected 0 |
| KRN-06 | Kernel | FAIL | Martian packets logged | net.ipv4.conf.all.log_martians = 0, expected 1 |
| SVC-00 | Services | SKIP | Running services | offline mode (--root), not checked |
