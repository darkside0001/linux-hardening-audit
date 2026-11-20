# linux-hardening-audit

A read-only Bash script that checks a Linux server against a security baseline
inspired by the CIS Benchmarks, and tells you exactly what to fix.

I wrote it to speed up the server audits I do (SSH, accounts, file permissions,
kernel network settings, firewall, updates). It changes nothing on the system:
it only reads configuration files and status commands.

```
$ sudo ./audit.sh
== SSH ==
[FAIL] Root login over SSH allowed (PermitRootLogin yes)
       fix: Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd.
[FAIL] Password authentication enabled (PasswordAuthentication yes)
       fix: Use SSH keys and set 'PasswordAuthentication no'. This removes the brute-force attack surface.
...
Summary: 4 pass, 6 warn, 11 fail, 1 skipped. Score: 33/100
```

Full sample reports: [text](examples/report-insecure-host.txt), [Markdown](examples/report-insecure-host.md).

## Features

- 29 checks in 6 areas (see table below), each with a severity and a remediation hint
- Output as coloured text, JSON (for SIEM / automation) or a Markdown report for clients
- Score from 0 to 100: PASS = 1 point, WARN = 0.5, FAIL = 0
- Exit code 1 when any check fails, so it can gate a CI pipeline or an Ansible run
- Offline mode (`--root`) to audit a mounted disk image or container filesystem
- Reads the effective SSH config with `sshd -T` when run as root, and parses
  `sshd_config.d/*.conf` drop-ins correctly otherwise
- Pure Bash plus coreutils. No dependencies to install on the server

## What it checks

| Area | Checks |
|------|--------|
| SSH | root login, password auth, empty passwords, MaxAuthTries, X11 forwarding, LoginGraceTime |
| Accounts | extra UID 0 accounts, empty passwords, password max age, `NOPASSWD` sudo rules |
| Filesystem | permissions on `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `sshd_config`; world-writable files in `/etc`; sticky bit on `/tmp` |
| Kernel | ASLR, SYN cookies, ICMP redirects, source routing, martian logging |
| Services | host firewall (ufw / firewalld / nftables / iptables), fail2ban, auditd, ports listening on external interfaces |
| Updates | pending security updates, unattended-upgrades (Debian/Ubuntu) |

## Usage

```bash
git clone https://github.com/darkside0001/linux-hardening-audit.git
cd linux-hardening-audit
sudo ./audit.sh                               # coloured report in the terminal
sudo ./audit.sh -f markdown -o report.md      # report for a client
sudo ./audit.sh -f json | jq '.findings[] | select(.status=="FAIL")'
./audit.sh --root /mnt/image                  # offline audit of a mounted filesystem
```

Running without root works, but checks that need `/etc/shadow`, sudoers or
firewall rules are marked `SKIP`.

## Tests

The `tests/fixtures` folder holds two fake filesystems: a deliberately insecure
host and a hardened one. The test script runs the audit against both and checks
every finding.

```bash
tests/run_tests.sh
# 41 passed, 0 failed
```

## Limitations

- It is a baseline, not a full CIS benchmark: it covers the settings I see
  misconfigured most often on small VPS and on-prem servers.
- Update checks currently support apt-based systems only.
- Only run it on systems you own or are authorised to assess.

## Related

- [ssh-bruteforce-detector](https://github.com/darkside0001/ssh-bruteforce-detector): finds the attacks that weak SSH settings let through
- [nmap-report](https://github.com/darkside0001/nmap-report): checks the same host from the outside

## License

MIT
