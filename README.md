# linux-hardening-audit

A read-only Bash script that checks a Linux server against a security baseline
inspired by the CIS Benchmarks and tells you exactly what to fix, plus a
companion script that applies those fixes safely, with a reproducible
before/after demonstration.

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

## Before and after: 44/100 -> 98/100

[`harden.sh`](harden.sh) fixes what the audit finds, and
[`lab/run-before-after.sh`](lab/run-before-after.sh) proves it on a throwaway
Ubuntu 24.04 "VPS" container with typical mistakes (root and password SSH
login, NOPASSWD sudo, an account without a password, `/etc/shadow` readable by
everyone, no firewall, a forgotten dev server on port 8080, unsafe kernel
network settings). It audits, hardens, reboots and audits again, and CI runs
the whole thing on every push.

| | Score | Fail | High-severity fail | Port 8080 from outside | SSH offers |
|---|---|---|---|---|---|
| Before | 44/100 | 11 | 4 | open | publickey, password |
| After | **98/100** | **0** | **0** | filtered | publickey only |

Full report with every check: [`docs/before-after-report.md`](docs/before-after-report.md).
The admin's key login is tested after hardening, so the script provably does
not lock you out. The one remaining warning (auditd) cannot run inside a
container; on a VM the script enables it.

```bash
sudo ./harden.sh            # dry run: shows what it would change
sudo ./harden.sh --apply    # backs up every file, validates sshd/sudoers, applies
SSH_ALLOW_FROM=10.8.0.0/24 sudo ./harden.sh --apply   # SSH only from your VPN
```

Safety rules in `harden.sh`: every changed file is backed up to
`/var/backups/hardening-<timestamp>/`; `sshd -t` and `visudo -c` must pass or
the change is rolled back; SSH password login is only turned off when a sudo
user already has an `authorized_keys` file; extra UID 0 accounts are reported
for a human to decide, never deleted.

## Features

- 29 checks in 6 areas (see table below), each with a severity and a remediation hint
- Output as coloured text, JSON (for SIEM / automation) or a Markdown report for clients
- Score from 0 to 100: PASS = 1 point, WARN = 0.5, FAIL = 0
- Exit code 1 when any check fails, so it can gate a CI pipeline or an Ansible run
- Offline mode (`--root`) to audit a mounted disk image or container filesystem
- Reads the effective SSH config with `sshd -T` when run as root, and parses
  `sshd_config.d/*.conf` drop-ins correctly otherwise
- Detects running services through systemd, or by process on hosts and
  containers without it
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
- [infra-security-monitoring](https://github.com/darkside0001/infra-security-monitoring): the monitored, firewalled web stack that runs on a host hardened like this

## License

MIT
