"""Builds docs/before-after-report.md from the raw outputs in lab/results/."""

import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
before = json.loads((out / "audit-before.json").read_text())
after = json.loads((out / "audit-after.json").read_text())
ext_b = (out / "external-before.txt").read_text().splitlines()[1:]
ext_a = (out / "external-after.txt").read_text().splitlines()[1:]
applied = [l for l in (out / "harden-apply.txt").read_text().splitlines() if l.startswith(("CHANGED", "RUN", "NOTE"))]
manual = (out / "harden-apply.txt").read_text().split("Needs a human:")[-1].strip().splitlines() \
    if "Needs a human:" in (out / "harden-apply.txt").read_text() else []

ICON = {"PASS": "PASS", "FAIL": "**FAIL**", "WARN": "WARN", "INFO": "INFO", "SKIP": "SKIP"}
b_by = {f["id"]: f for f in before["findings"]}
a_by = {f["id"]: f for f in after["findings"]}
sb, sa = before["summary"], after["summary"]

L = []
w = L.append
w("# Hardening report: before and after")
w("")
w("Target: `vps-lab`, a throwaway Ubuntu 24.04 container built to look like a freshly")
w("provisioned VPS with common mistakes ([`lab/Dockerfile`](../lab/Dockerfile)).")
w("Everything below is produced by [`lab/run-before-after.sh`](../lab/run-before-after.sh):")
w("audit, harden with [`harden.sh`](../harden.sh), reboot, audit again. Raw outputs are in")
w("[`lab/results/`](../lab/results/).")
w("")
w(f"- Before: {before['date']}  |  After: {after['date']}")
w("")
w("## Result")
w("")
w("| | Score | Pass | Warn | Fail |")
w("|---|---|---|---|---|")
w(f"| Before | **{sb['score']}/100** | {sb['pass']} | {sb['warn']} | {sb['fail']} |")
w(f"| After | **{sa['score']}/100** | {sa['pass']} | {sa['warn']} | {sa['fail']} |")
w("")
fixed = [i for i in b_by if b_by[i]["status"] in ("FAIL", "WARN") and a_by.get(i, {}).get("status") == "PASS"]
left = [f for f in after["findings"] if f["status"] in ("FAIL", "WARN")]
high_b = sum(1 for f in before["findings"] if f["status"] == "FAIL" and f["severity"] == "high")
high_a = sum(1 for f in after["findings"] if f["status"] == "FAIL" and f["severity"] == "high")
w(f"{len(fixed)} findings fixed, {len(left)} left. High-severity failures: {high_b} -> {high_a}.")
w("")
w("## What an attacker sees from the network")
w("")
w("| Check | Before | After |")
w("|---|---|---|")
for b, a in zip(ext_b, ext_a):
    k = b.split(":")[0] if ":" in b else b.rsplit(" ", 1)[0]
    w(f"| {k.replace('tcp/', 'TCP port ')} | {b[len(k):].lstrip(': ').strip()} | {a[len(k):].lstrip(': ').strip()} |")
w("")
w("Port 8080 is a forgotten development web server. It still runs after hardening, but the")
w("default-deny firewall no longer lets anyone reach it. SSH stops offering password")
w("authentication, and the admin can still log in with a key, so the hardening did not")
w("lock anyone out.")
w("")
w("## Check by check")
w("")
w("| ID | Severity | Check | Before | After |")
w("|---|---|---|---|---|")
for f in before["findings"]:
    a = a_by.get(f["id"], {})
    w(f"| {f['id']} | {f['severity']} | {a.get('title', f['title'])} | {ICON[f['status']]} {f['detail']} | {ICON.get(a.get('status'), '-')} {a.get('detail', '')} |".replace("\n", " "))
w("")
w("## What harden.sh changed")
w("")
w("```")
L.extend(applied)
w("```")
w("")
w("Every changed file was backed up first (`/var/backups/hardening-<timestamp>/`). The")
w("SSH drop-in was validated with `sshd -t` and the sudoers change with `visudo -c`")
w("before being kept. Password login was disabled only after the script confirmed that")
w("a sudo user has an `authorized_keys` file.")
w("")
w("## Still open, and why")
w("")
if left:
    for f in left:
        w(f"- **{f['id']} {f['title']}** ({f['detail']}).")
else:
    w("- Nothing from the audit.")
for m in manual:
    m = m.strip().lstrip("- ")
    if m:
        w(f"- harden.sh: {m}")
w("")
w("## Lab notes")
w("")
w("- A container has no systemd, so `lab-init` plays its role: it starts sshd on every boot,")
w("  and the firewall and fail2ban once harden.sh has enabled them.")
w("- \"Reboot\" = the container's disk is committed to an image and started again with the")
w("  values from `/etc/sysctl.d/60-hardening.conf` (network parameters are per network")
w("  namespace). `kernel.randomize_va_space` belongs to the host kernel and was already 2.")
w("- auditd needs the host kernel's audit subsystem, so it cannot run inside a container;")
w("  on a VM, harden.sh enables it with systemd.")
print("\n".join(L))
