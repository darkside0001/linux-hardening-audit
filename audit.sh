#!/usr/bin/env bash
# linux-hardening-audit: read-only security baseline check for Linux servers.
# Checks are inspired by the CIS Benchmarks for Debian/Ubuntu/RHEL.
# The script never changes the system: it only reads config files and runs
# status commands, then prints findings with remediation advice.

set -uo pipefail

VERSION="1.0.0"
ROOT="/"            # filesystem root to audit (override with --root for offline images/tests)
FORMAT="text"       # text | json | markdown
OUTPUT=""           # write report to this file instead of stdout
NO_COLOR="${NO_COLOR:-}"
LIVE=1              # run checks that query the running system (systemctl, ss, apt)

declare -a R_ID R_SEV R_STATUS R_CAT R_TITLE R_DETAIL R_FIX

usage() {
  cat <<EOF
linux-hardening-audit v$VERSION

Usage: sudo ./audit.sh [options]

Options:
  -f, --format FORMAT   text (default), json or markdown
  -o, --output FILE     write the report to FILE
  -r, --root DIR        audit a mounted filesystem / image at DIR (offline mode,
                        skips checks that need the running system)
      --no-color        disable colours in text output
  -h, --help            show this help

Exit code: 0 if no FAIL findings, 1 if at least one FAIL, 2 on usage error.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--format) FORMAT="${2:-}"; shift 2 ;;
    -o|--output) OUTPUT="${2:-}"; shift 2 ;;
    -r|--root)   ROOT="${2:-}"; LIVE=0; shift 2 ;;
    --no-color)  NO_COLOR=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$FORMAT" in text|json|markdown) ;; *) echo "Invalid format: $FORMAT" >&2; exit 2 ;; esac
[[ -d "$ROOT" ]] || { echo "Root directory not found: $ROOT" >&2; exit 2; }
ROOT="${ROOT%/}"

p() { printf '%s%s' "$ROOT" "$1"; }   # path inside the audited root

# record ID SEVERITY STATUS CATEGORY TITLE DETAIL REMEDIATION
# STATUS: PASS | FAIL | WARN | INFO | SKIP ; SEVERITY: high | medium | low
record() {
  R_ID+=("$1"); R_SEV+=("$2"); R_STATUS+=("$3"); R_CAT+=("$4")
  R_TITLE+=("$5"); R_DETAIL+=("$6"); R_FIX+=("${7:-}")
}

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- SSH ---

# Effective value of an sshd option. Uses `sshd -T` on a live system when
# possible, otherwise parses sshd_config and sshd_config.d/*.conf (first
# occurrence wins, as in OpenSSH).
sshd_value() {
  local key="${1,,}" val=""
  if [[ $LIVE -eq 1 && $EUID -eq 0 ]] && have sshd; then
    val=$(sshd -T 2>/dev/null | awk -v k="$key" 'tolower($1)==k {print tolower($2); exit}')
    [[ -n "$val" ]] && { echo "$val"; return; }
  fi
  local files=()
  [[ -f "$(p /etc/ssh/sshd_config)" ]] && files+=("$(p /etc/ssh/sshd_config)")
  for f in "$(p /etc/ssh/sshd_config.d)"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
  [[ ${#files[@]} -eq 0 ]] && return
  # Include files are read where the Include line sits; Debian puts it at the
  # top, so drop-ins are scanned first.
  local ordered=()
  for f in "${files[@]:1}"; do ordered+=("$f"); done
  ordered+=("${files[0]}")
  awk -v k="$key" '
    /^[[:space:]]*#/ {next}
    /^[[:space:]]*[Mm]atch[[:space:]]/ {exit}
    tolower($1)==k {print tolower($2); exit}
  ' "${ordered[@]}" 2>/dev/null | head -n1
}

check_ssh() {
  if [[ ! -f "$(p /etc/ssh/sshd_config)" ]]; then
    record SSH-00 low SKIP SSH "OpenSSH server config" "sshd_config not found, SSH server probably not installed" ""
    return
  fi

  local v
  v=$(sshd_value PermitRootLogin); v=${v:-prohibit-password}
  case "$v" in
    no) record SSH-01 high PASS SSH "Root login over SSH disabled" "PermitRootLogin $v" ;;
    prohibit-password|without-password)
      record SSH-01 high WARN SSH "Root login over SSH allowed with keys" "PermitRootLogin $v" \
        "Set 'PermitRootLogin no' and log in as a normal user with sudo." ;;
    *) record SSH-01 high FAIL SSH "Root login over SSH allowed" "PermitRootLogin $v" \
        "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd." ;;
  esac

  v=$(sshd_value PasswordAuthentication); v=${v:-yes}
  if [[ "$v" == "no" ]]; then
    record SSH-02 high PASS SSH "Password authentication disabled" "PasswordAuthentication no"
  else
    record SSH-02 high FAIL SSH "Password authentication enabled" "PasswordAuthentication $v" \
      "Use SSH keys and set 'PasswordAuthentication no'. This removes the brute-force attack surface."
  fi

  v=$(sshd_value PermitEmptyPasswords); v=${v:-no}
  if [[ "$v" == "no" ]]; then
    record SSH-03 high PASS SSH "Empty passwords rejected" "PermitEmptyPasswords no"
  else
    record SSH-03 high FAIL SSH "Empty passwords accepted" "PermitEmptyPasswords $v" "Set 'PermitEmptyPasswords no'."
  fi

  v=$(sshd_value MaxAuthTries); v=${v:-6}
  if [[ "$v" =~ ^[0-9]+$ && "$v" -le 4 ]]; then
    record SSH-04 medium PASS SSH "MaxAuthTries is 4 or lower" "MaxAuthTries $v"
  else
    record SSH-04 medium WARN SSH "MaxAuthTries is higher than 4" "MaxAuthTries $v" "Set 'MaxAuthTries 4' (or lower)."
  fi

  v=$(sshd_value X11Forwarding); v=${v:-no}
  if [[ "$v" == "no" ]]; then
    record SSH-05 low PASS SSH "X11 forwarding disabled" "X11Forwarding no"
  else
    record SSH-05 low WARN SSH "X11 forwarding enabled" "X11Forwarding $v" "Set 'X11Forwarding no' on servers."
  fi

  v=$(sshd_value LoginGraceTime); v=${v:-120}
  local secs=$v
  [[ "$v" =~ ^([0-9]+)m$ ]] && secs=$(( BASH_REMATCH[1] * 60 ))
  [[ "$v" =~ ^([0-9]+)s?$ ]] && secs=${BASH_REMATCH[1]}
  if [[ "$secs" =~ ^[0-9]+$ && "$secs" -gt 0 && "$secs" -le 60 ]]; then
    record SSH-06 low PASS SSH "LoginGraceTime is 60s or less" "LoginGraceTime $v"
  else
    record SSH-06 low WARN SSH "LoginGraceTime is longer than 60s" "LoginGraceTime $v" "Set 'LoginGraceTime 60'."
  fi
}

# ----------------------------------------------------------- Accounts ---

check_accounts() {
  local passwd shadow
  passwd="$(p /etc/passwd)"; shadow="$(p /etc/shadow)"

  if [[ -r "$passwd" ]]; then
    local uid0
    uid0=$(awk -F: '$3==0 && $1!="root" {printf "%s ", $1}' "$passwd")
    if [[ -z "$uid0" ]]; then
      record ACC-01 high PASS Accounts "Only root has UID 0" "no other UID 0 accounts"
    else
      record ACC-01 high FAIL Accounts "Extra accounts with UID 0" "accounts: ${uid0% }" \
        "Remove or re-number these accounts. Any UID 0 account is a full root account."
    fi
  fi

  if [[ -r "$shadow" ]]; then
    local empty
    empty=$(awk -F: '$2=="" {printf "%s ", $1}' "$shadow")
    if [[ -z "$empty" ]]; then
      record ACC-02 high PASS Accounts "No accounts with empty passwords" "checked /etc/shadow"
    else
      record ACC-02 high FAIL Accounts "Accounts with empty passwords" "accounts: ${empty% }" \
        "Lock them with 'passwd -l <user>' or set a password."
    fi
  else
    record ACC-02 high SKIP Accounts "Empty password check" "/etc/shadow not readable (run as root)"
  fi

  local defs maxdays
  defs="$(p /etc/login.defs)"
  if [[ -r "$defs" ]]; then
    maxdays=$(awk '/^[[:space:]]*PASS_MAX_DAYS/ {print $2}' "$defs" | tail -n1)
    maxdays=${maxdays:-99999}
    if [[ "$maxdays" =~ ^[0-9]+$ && "$maxdays" -le 365 ]]; then
      record ACC-03 low PASS Accounts "Password maximum age is set" "PASS_MAX_DAYS $maxdays"
    else
      record ACC-03 low WARN Accounts "Passwords never expire" "PASS_MAX_DAYS $maxdays" \
        "Set PASS_MAX_DAYS 365 (or your policy) in /etc/login.defs."
    fi
  fi

  local sudoers=() nopass=""
  [[ -r "$(p /etc/sudoers)" ]] && sudoers+=("$(p /etc/sudoers)")
  for f in "$(p /etc/sudoers.d)"/*; do [[ -f "$f" && -r "$f" ]] && sudoers+=("$f"); done
  if [[ ${#sudoers[@]} -gt 0 ]]; then
    nopass=$(grep -hE '^[^#]*NOPASSWD' "${sudoers[@]}" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')
    if [[ -z "$nopass" ]]; then
      record ACC-04 medium PASS Accounts "No passwordless sudo rules" "no NOPASSWD entries"
    else
      record ACC-04 medium WARN Accounts "Passwordless sudo rules found" "NOPASSWD for: ${nopass% }" \
        "Limit NOPASSWD to specific commands for service accounts only."
    fi
  else
    record ACC-04 medium SKIP Accounts "sudoers check" "sudoers not readable (run as root)"
  fi
}

# --------------------------------------------------------- Filesystem ---

file_mode() { stat -c '%a' "$1" 2>/dev/null; }

# mode_at_most FILE MAX: true if FILE has no permission bits outside MAX
mode_at_most() {
  local m; m=$(file_mode "$1") || return 1
  [[ -n "$m" ]] || return 1
  (( (8#$m & ~8#$2 & 8#7777) == 0 ))
}

check_filesystem() {
  local f
  for f in /etc/passwd:644 /etc/group:644 /etc/shadow:640 /etc/gshadow:640 /etc/ssh/sshd_config:644; do
    local path="${f%%:*}" max="${f##*:}"
    [[ -e "$(p "$path")" ]] || continue
    local m; m=$(file_mode "$(p "$path")")
    if mode_at_most "$(p "$path")" "$max"; then
      record "FS-${path//\//_}" medium PASS Filesystem "Permissions on $path" "mode $m, expected $max or stricter"
    else
      record "FS-${path//\//_}" medium FAIL Filesystem "Permissions on $path are too open" "mode $m, expected $max or stricter" \
        "chmod $max $path"
    fi
  done

  if [[ -d "$(p /etc)" ]]; then
    local ww
    ww=$(find "$(p /etc)" -xdev -type f -perm -0002 2>/dev/null | sed "s|^$ROOT||" | head -n 10 | tr '\n' ' ')
    if [[ -z "$ww" ]]; then
      record FS-WW medium PASS Filesystem "No world-writable files in /etc" "find /etc -perm -0002"
    else
      record FS-WW medium FAIL Filesystem "World-writable files in /etc" "${ww% }" "chmod o-w on these files."
    fi
  fi

  local tmp; tmp="$(p /tmp)"
  if [[ -d "$tmp" ]]; then
    local m; m=$(file_mode "$tmp")
    if [[ "$m" == 1777 ]]; then
      record FS-TMP low PASS Filesystem "Sticky bit set on /tmp" "mode $m"
    else
      record FS-TMP low WARN Filesystem "Sticky bit missing on /tmp" "mode $m" "chmod 1777 /tmp"
    fi
  fi
}

# ------------------------------------------------------------ Kernel ---

# sysctl_check ID SEVERITY KEY EXPECTED TITLE
sysctl_check() {
  local id=$1 sev=$2 key=$3 want=$4 title=$5
  local f; f="$(p "/proc/sys/${key//.//}")"
  if [[ ! -r "$f" ]]; then
    record "$id" "$sev" SKIP Kernel "$title" "$key not available"
    return
  fi
  local got; got=$(tr -s '[:space:]' ' ' < "$f" | sed 's/ $//')
  if [[ "$got" == "$want" ]]; then
    record "$id" "$sev" PASS Kernel "$title" "$key = $got"
  else
    record "$id" "$sev" FAIL Kernel "$title" "$key = $got, expected $want" \
      "Add '$key = $want' to /etc/sysctl.d/60-hardening.conf, then run 'sysctl --system'."
  fi
}

check_kernel() {
  sysctl_check KRN-01 medium kernel.randomize_va_space 2 "ASLR fully enabled"
  sysctl_check KRN-02 medium net.ipv4.tcp_syncookies 1 "TCP SYN cookies enabled"
  sysctl_check KRN-03 low net.ipv4.conf.all.accept_redirects 0 "ICMP redirects ignored"
  sysctl_check KRN-04 low net.ipv4.conf.all.send_redirects 0 "ICMP redirects not sent"
  sysctl_check KRN-05 low net.ipv4.conf.all.accept_source_route 0 "Source-routed packets rejected"
  sysctl_check KRN-06 low net.ipv4.conf.all.log_martians 1 "Martian packets logged"
}

# ----------------------------------------------- Services (live only) ---

svc_active() { have systemctl && systemctl is-active --quiet "$1" 2>/dev/null; }

check_services() {
  if [[ $LIVE -eq 0 ]]; then
    record SVC-00 low SKIP Services "Running services" "offline mode (--root), not checked"
    return
  fi

  local fw=""
  if have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then fw="ufw"
  elif svc_active firewalld; then fw="firewalld"
  elif have nft && [[ $(nft list ruleset 2>/dev/null | grep -c 'hook input') -gt 0 ]]; then fw="nftables"
  elif have iptables && iptables -S INPUT 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)|^-A INPUT'; then fw="iptables"
  fi
  if [[ -n "$fw" ]]; then
    record SVC-01 high PASS Services "Host firewall active" "$fw"
  elif [[ $EUID -ne 0 ]]; then
    record SVC-01 high SKIP Services "Host firewall" "run as root to read firewall rules"
  else
    record SVC-01 high FAIL Services "No active host firewall" "ufw/firewalld/nftables/iptables not filtering input" \
      "Enable a default-deny firewall, e.g. 'ufw default deny incoming && ufw allow OpenSSH && ufw enable'."
  fi

  if svc_active fail2ban; then
    record SVC-02 medium PASS Services "fail2ban running" "brute-force protection active"
  else
    record SVC-02 medium WARN Services "fail2ban not running" "no automatic ban of brute-force sources" \
      "apt install fail2ban, enable the sshd jail."
  fi

  if svc_active auditd; then
    record SVC-03 medium PASS Services "auditd running" "kernel audit logging active"
  else
    record SVC-03 medium WARN Services "auditd not running" "security events are not audited" \
      "apt install auditd && systemctl enable --now auditd"
  fi

  if have ss; then
    local listen
    listen=$(ss -H -tuln 2>/dev/null | awk '{print $5}' | grep -vE '^(127\.|\[::1\]|::1)' | sed 's/.*://' | sort -un | tr '\n' ' ')
    record SVC-04 low INFO Services "Ports listening on external interfaces" "${listen:-none}" \
      "Close any port you do not need, or bind it to 127.0.0.1."
  fi

  if have apt-get; then
    local sec
    sec=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst .*[Ss]ecurity')
    if [[ "$sec" -eq 0 ]]; then
      record UPD-01 high PASS Updates "No pending security updates" "apt-get -s upgrade"
    else
      record UPD-01 high FAIL Updates "Pending security updates" "$sec package(s)" "apt-get update && apt-get upgrade"
    fi
    if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]] && grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then
      record UPD-02 medium PASS Updates "Unattended security upgrades enabled" "20auto-upgrades"
    else
      record UPD-02 medium WARN Updates "Unattended upgrades not enabled" "20auto-upgrades missing or disabled" "apt install unattended-upgrades && dpkg-reconfigure unattended-upgrades"
    fi
  fi
}

# ------------------------------------------------------------ Report ---

json_escape() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

count() { local n=0 s; for s in "${R_STATUS[@]}"; do [[ "$s" == "$1" ]] && n=$((n+1)); done; echo $n; }

score() {
  # PASS = 1 point, WARN = 0.5, FAIL = 0. INFO and SKIP do not count.
  local pass warn fail total
  pass=$(count PASS); warn=$(count WARN); fail=$(count FAIL)
  total=$((pass + warn + fail))
  [[ $total -eq 0 ]] && { echo 0; return; }
  echo $(( (pass * 100 + warn * 50) / total ))
}

report_text() {
  local c_pass="" c_fail="" c_warn="" c_dim="" c_off=""
  if [[ -z "$NO_COLOR" && -t 1 && -z "$OUTPUT" ]]; then
    c_pass=$'\e[32m'; c_fail=$'\e[31m'; c_warn=$'\e[33m'; c_dim=$'\e[2m'; c_off=$'\e[0m'
  fi
  echo "linux-hardening-audit v$VERSION  host=$HOST  root=$ROOT_LABEL  $DATE"
  local last="" i col
  for i in "${!R_ID[@]}"; do
    if [[ "${R_CAT[$i]}" != "$last" ]]; then echo; echo "== ${R_CAT[$i]} =="; last="${R_CAT[$i]}"; fi
    case "${R_STATUS[$i]}" in PASS) col=$c_pass ;; FAIL) col=$c_fail ;; WARN) col=$c_warn ;; *) col=$c_dim ;; esac
    printf '%s[%-4s]%s %s %s(%s)%s\n' "$col" "${R_STATUS[$i]}" "$c_off" "${R_TITLE[$i]}" "$c_dim" "${R_DETAIL[$i]}" "$c_off"
    if [[ "${R_STATUS[$i]}" == FAIL || "${R_STATUS[$i]}" == WARN ]] && [[ -n "${R_FIX[$i]}" ]]; then
      printf '       fix: %s\n' "${R_FIX[$i]}"
    fi
  done
  echo
  echo "Summary: $(count PASS) pass, $(count WARN) warn, $(count FAIL) fail, $(count SKIP) skipped. Score: $(score)/100"
}

report_json() {
  local i first=1
  printf '{\n  "tool": "linux-hardening-audit",\n  "version": "%s",\n' "$VERSION"
  printf '  "host": "%s",\n  "root": "%s",\n  "date": "%s",\n' "$(json_escape "$HOST")" "$(json_escape "$ROOT_LABEL")" "$DATE"
  printf '  "summary": {"pass": %d, "warn": %d, "fail": %d, "skip": %d, "info": %d, "score": %d},\n' \
    "$(count PASS)" "$(count WARN)" "$(count FAIL)" "$(count SKIP)" "$(count INFO)" "$(score)"
  printf '  "findings": [\n'
  for i in "${!R_ID[@]}"; do
    [[ $first -eq 0 ]] && printf ',\n'; first=0
    printf '    {"id": "%s", "category": "%s", "severity": "%s", "status": "%s", "title": "%s", "detail": "%s", "remediation": "%s"}' \
      "$(json_escape "${R_ID[$i]}")" "${R_CAT[$i]}" "${R_SEV[$i]}" "${R_STATUS[$i]}" \
      "$(json_escape "${R_TITLE[$i]}")" "$(json_escape "${R_DETAIL[$i]}")" "$(json_escape "${R_FIX[$i]}")"
  done
  printf '\n  ]\n}\n'
}

report_markdown() {
  local i
  echo "# Linux hardening audit: $HOST"
  echo
  echo "- Date: $DATE"
  echo "- Audited root: \`$ROOT_LABEL\`"
  echo "- Score: **$(score)/100** ($(count PASS) pass, $(count WARN) warn, $(count FAIL) fail, $(count SKIP) skipped)"
  echo
  echo "## Findings to fix"
  echo
  echo "| ID | Severity | Status | Finding | Detail | Remediation |"
  echo "|----|----------|--------|---------|--------|-------------|"
  local any=0
  for sev in high medium low; do
    for i in "${!R_ID[@]}"; do
      [[ "${R_SEV[$i]}" == "$sev" ]] || continue
      [[ "${R_STATUS[$i]}" == FAIL || "${R_STATUS[$i]}" == WARN ]] || continue
      any=1
      echo "| ${R_ID[$i]} | $sev | ${R_STATUS[$i]} | ${R_TITLE[$i]} | ${R_DETAIL[$i]//|/\\|} | ${R_FIX[$i]//|/\\|} |"
    done
  done
  [[ $any -eq 0 ]] && echo "| - | - | - | Nothing to fix | - | - |"
  echo
  echo "## All checks"
  echo
  echo "| ID | Category | Status | Check | Detail |"
  echo "|----|----------|--------|-------|--------|"
  for i in "${!R_ID[@]}"; do
    echo "| ${R_ID[$i]} | ${R_CAT[$i]} | ${R_STATUS[$i]} | ${R_TITLE[$i]} | ${R_DETAIL[$i]//|/\\|} |"
  done
}

# -------------------------------------------------------------- Main ---

HOST=$(cat "$(p /etc/hostname)" 2>/dev/null || hostname 2>/dev/null || echo unknown)
HOST=${HOST%%$'\n'*}
ROOT_LABEL=${ROOT:-/}
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

if [[ $LIVE -eq 1 && $EUID -ne 0 ]]; then
  echo "Note: not running as root, some checks will be skipped." >&2
fi

check_ssh
check_accounts
check_filesystem
check_kernel
check_services

case "$FORMAT" in
  text)     out=$(report_text) ;;
  json)     out=$(report_json) ;;
  markdown) out=$(report_markdown) ;;
esac

if [[ -n "$OUTPUT" ]]; then
  printf '%s\n' "$out" > "$OUTPUT"
  echo "Report written to $OUTPUT" >&2
else
  printf '%s\n' "$out"
fi

[[ $(count FAIL) -eq 0 ]]
