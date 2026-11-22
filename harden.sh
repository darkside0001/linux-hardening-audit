#!/usr/bin/env bash
# harden.sh: fixes the findings that audit.sh reports, safely and idempotently.
#
#   sudo ./harden.sh             # dry run: print what would change
#   sudo ./harden.sh --apply     # make the changes
#
# Safety rules:
# - Every file is backed up to /var/backups/hardening-<timestamp>/ before it changes.
# - New sshd settings are validated with `sshd -t` and rolled back if invalid.
# - Password login over SSH is only disabled when at least one sudo-capable
#   user has an authorized_keys file (otherwise you would lock yourself out).
#   Override with --force-ssh-keys-only.
# - sudoers changes are validated with `visudo -c` and rolled back if invalid.
# - Accounts with UID 0 other than root are reported, never changed: that needs
#   a human decision.
set -euo pipefail
umask 027   # nothing this script creates becomes world-readable or writable by accident

APPLY=0 FORCE_KEYS=0
SSH_ALLOW_FROM="${SSH_ALLOW_FROM:-}"   # e.g. "10.8.0.0/24" to allow SSH only from a VPN
for a in "$@"; do
  case "$a" in
    --apply) APPLY=1 ;;
    --force-ssh-keys-only) FORCE_KEYS=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

TS=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP=/var/backups/hardening-$TS
CHANGED=0 MANUAL=()

say()    { printf '%-8s %s\n' "$1" "$2"; }
backup() { [[ $APPLY -eq 1 && -e "$1" ]] || return 0; mkdir -p "$BACKUP$(dirname "$1")"; cp -a "$1" "$BACKUP$1"; }
change() { # description, command...
  local d=$1; shift
  if [[ $APPLY -eq 1 ]]; then "$@"; say CHANGED "$d"; else say WOULD "$d"; fi
  CHANGED=$((CHANGED + 1))
}
write_file() { # path mode content
  backup "$1"; mkdir -p "$(dirname "$1")"; printf '%s\n' "$3" > "$1"; chmod "$2" "$1"
}
have() { command -v "$1" >/dev/null 2>&1; }
systemd_running() { [[ -d /run/systemd/system ]]; }
enable_service() { # name
  if systemd_running; then systemctl enable --now "$1" >/dev/null
  else mkdir -p /etc/lab/enabled; touch "/etc/lab/enabled/$1"   # lab container: started by lab-init on "boot"
  fi
}

echo "harden.sh  mode=$([[ $APPLY -eq 1 ]] && echo APPLY || echo DRY-RUN)  host=$(hostname)"
[[ $APPLY -eq 1 ]] && echo "backups: $BACKUP"
echo

# --------------------------------------------------------------- SSH ----
if [[ -f /etc/ssh/sshd_config ]]; then
  keys_ok=0
  for u in root $(getent group sudo wheel 2>/dev/null | cut -d: -f4 | tr ',' ' '); do
    h=$(getent passwd "$u" | cut -d: -f6)
    [[ -n "$h" && -s "$h/.ssh/authorized_keys" ]] && keys_ok=1
  done
  for f in /etc/sudoers.d/*; do  # users with sudo rules count too
    [[ -f "$f" ]] || continue
    for u in $(awk '!/^#/ && NF {print $1}' "$f"); do
      h=$(getent passwd "$u" | cut -d: -f6 || true)
      [[ -n "$h" && -s "$h/.ssh/authorized_keys" ]] && keys_ok=1
    done
  done
  pwauth="no"
  if [[ $keys_ok -eq 0 && $FORCE_KEYS -eq 0 ]]; then
    pwauth="yes"
    MANUAL+=("SSH password login left ON: no sudo-capable user has authorized_keys. Add a key, then rerun.")
  fi
  # 00- sorts first, and in OpenSSH the first value wins, so this overrides
  # provider defaults in other drop-ins without editing them.
  conf="# Managed by harden.sh ($TS)
PermitRootLogin no
PasswordAuthentication $pwauth
KbdInteractiveAuthentication no
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2"
  if ! grep -qs "^PermitRootLogin no" /etc/ssh/sshd_config.d/00-hardening.conf; then
    change "sshd: root login off, password login $pwauth, MaxAuthTries 4, no X11 (00-hardening.conf)" \
      write_file /etc/ssh/sshd_config.d/00-hardening.conf 0644 "$conf"
    if [[ $APPLY -eq 1 ]]; then
      grep -qE '^\s*Include\s+/etc/ssh/sshd_config.d/\*\.conf' /etc/ssh/sshd_config || {
        backup /etc/ssh/sshd_config; sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config; }
      if ! sshd -t; then
        rm -f /etc/ssh/sshd_config.d/00-hardening.conf
        [[ -f "$BACKUP/etc/ssh/sshd_config" ]] && cp -a "$BACKUP/etc/ssh/sshd_config" /etc/ssh/sshd_config
        echo "sshd -t failed, SSH changes rolled back" >&2; exit 1
      fi
      if systemd_running; then systemctl reload ssh 2>/dev/null || systemctl reload sshd
      else pkill -HUP -x sshd || true; fi
    fi
  fi
fi

# ---------------------------------------------------------- Accounts ----
uid0=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd | tr '\n' ' ')
[[ -n "$uid0" ]] && MANUAL+=("Accounts with UID 0 besides root: ${uid0% }. Investigate (possible backdoor) and remove.")

for u in $(awk -F: '$2=="" {print $1}' /etc/shadow); do
  change "lock account '$u' (empty password)" passwd -l "$u"
done

if grep -qE '^PASS_MAX_DAYS\s+(99999|[0-9]{4,})' /etc/login.defs; then
  backup /etc/login.defs
  change "login.defs: PASS_MAX_DAYS 365 (new accounts)" \
    sed -i -E 's/^PASS_MAX_DAYS\s+.*/PASS_MAX_DAYS\t365/' /etc/login.defs
fi

fix_nopasswd() {
  local f=$1
  backup "$f"
  sed -i -E 's/^([^#].*)NOPASSWD:\s*/# harden.sh: NOPASSWD removed\n\1/' "$f"
  if ! visudo -c -q; then cp -a "$BACKUP$f" "$f"; echo "visudo -c failed, $f restored" >&2; return 1; fi
}
for f in /etc/sudoers /etc/sudoers.d/*; do
  [[ -f "$f" ]] && grep -qE '^[^#].*NOPASSWD' "$f" || continue
  change "sudo: require a password in $f (NOPASSWD removed)" fix_nopasswd "$f"
done

# -------------------------------------------------------- Filesystem ----
fix_mode() { # path max_mode
  [[ -e "$1" ]] || return 0
  local m; m=$(stat -c %a "$1")
  (( (8#$m & ~8#$2) == 0 )) && return 0
  change "chmod $2 $1 (was $m)" chmod "$2" "$1"
}
fix_mode /etc/passwd 644
fix_mode /etc/group 644
fix_mode /etc/shadow 640
fix_mode /etc/gshadow 640
fix_mode /etc/ssh/sshd_config 600

while IFS= read -r f; do
  change "remove world-write bit from $f" chmod o-w "$f"
done < <(find /etc -xdev -type f -perm -0002 2>/dev/null)

m=$(stat -c %a /tmp)
[[ ${#m} -eq 4 && ${m:0:1} =~ [1357] ]] || change "set sticky bit on /tmp (was $m)" chmod 1777 /tmp

# ------------------------------------------------------------ Kernel ----
sysctl_conf="# Managed by harden.sh ($TS)
kernel.randomize_va_space = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv6.conf.all.accept_redirects = 0"
if [[ ! -f /etc/sysctl.d/60-hardening.conf ]]; then
  change "kernel network parameters (/etc/sysctl.d/60-hardening.conf)" \
    write_file /etc/sysctl.d/60-hardening.conf 0644 "$sysctl_conf"
  # In a container /proc/sys is read-only; the values apply at the next boot.
  [[ $APPLY -eq 1 ]] && { sysctl -q -p /etc/sysctl.d/60-hardening.conf 2>/dev/null || say NOTE "sysctl not writable here (container?), applied at next boot"; }
fi

# ---------------------------------------------------------- Services ----
nft_conf='#!/usr/sbin/nft -f
# Managed by harden.sh. Default deny inbound; SSH and established traffic allowed.
table inet harden_filter
delete table inet harden_filter
table inet harden_filter {
  chain input {
    type filter hook input priority filter; policy drop;
    ct state established,related accept
    ct state invalid drop
    iif "lo" accept
    meta l4proto { icmp, ipv6-icmp } limit rate 10/second accept
    tcp dport 22 SSH_SOURCE ct state new limit rate 15/minute accept
    limit rate 5/minute log prefix "harden-drop: "
  }
}'
if [[ -n "$SSH_ALLOW_FROM" ]]; then nft_conf=${nft_conf/SSH_SOURCE/ip saddr $SSH_ALLOW_FROM}; else nft_conf=${nft_conf/SSH_SOURCE /}; fi
if ! grep -qs "harden_filter" /etc/nftables.conf; then
  if have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
    say SKIP "firewall: ufw already active"
  else
    apply_nft() { write_file /etc/nftables.conf 0755 "$nft_conf" && nft -c -f /etc/nftables.conf && nft -f /etc/nftables.conf; }
    change "nftables: default-deny inbound, allow SSH${SSH_ALLOW_FROM:+ from $SSH_ALLOW_FROM} (rate limited)" apply_nft
    [[ $APPLY -eq 1 ]] && enable_service nftables
    MANUAL+=("Firewall allows only SSH inbound. Open the ports your services need in /etc/nftables.conf.")
  fi
fi

if have fail2ban-server && [[ ! -f /etc/fail2ban/jail.d/sshd-harden.local ]]; then
  change "fail2ban: sshd jail, 5 failures in 10 min -> 1 h ban" \
    write_file /etc/fail2ban/jail.d/sshd-harden.local 0644 "[sshd]
enabled  = true
backend  = auto
maxretry = 5
findtime = 10m
bantime  = 1h"
  if [[ $APPLY -eq 1 ]]; then
    [[ -f /var/log/auth.log ]] || touch /var/log/auth.log
    enable_service fail2ban
    systemd_running || fail2ban-server -b >/dev/null 2>&1 || true
  fi
elif ! have fail2ban-server; then
  MANUAL+=("Install fail2ban (apt install fail2ban) and rerun.")
fi

if have auditd || [[ -x /sbin/auditd ]]; then
  if systemd_running; then
    systemctl is-active --quiet auditd || change "enable auditd" systemctl enable --now auditd
  else
    MANUAL+=("auditd needs the host kernel's audit subsystem; not started inside a container.")
  fi
fi

if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]] || have unattended-upgrade; then
  if ! grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then
    change "unattended-upgrades: daily security updates" \
      write_file /etc/apt/apt.conf.d/20auto-upgrades 0644 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";'
  fi
fi

if have apt-get; then
  if [[ $APPLY -eq 1 ]]; then
    say RUN "apt-get update && apt-get upgrade (security updates)"
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq >/dev/null
  else
    say WOULD "apt-get update && apt-get upgrade"
  fi
fi

# ----------------------------------------------------------- Summary ----
echo
echo "$CHANGED change(s) $([[ $APPLY -eq 1 ]] && echo applied || echo pending)."
if [[ ${#MANUAL[@]} -gt 0 ]]; then
  echo "Needs a human:"
  printf '  - %s\n' "${MANUAL[@]}"
fi
[[ $APPLY -eq 0 ]] && echo "Dry run only. Rerun with --apply to make these changes."
exit 0
