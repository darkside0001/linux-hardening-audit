#!/usr/bin/env bash
# Audit -> harden -> reboot -> audit, on a throwaway "VPS" container.
# Writes raw outputs to lab/results/ and the report to docs/before-after-report.md.
#
#   ./lab/run-before-after.sh
#
# The container stands in for a small Ubuntu 24.04 VPS. Differences from a VM,
# all handled explicitly: no systemd (lab-init starts enabled services on
# "boot"), kernel parameters are set per network namespace when the container
# is created, and kernel.randomize_va_space / auditd belong to the host kernel.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=lab/results
NET=lha-lab VPS_IP=172.31.98.10 CLIENT_IP=172.31.98.20
IMG=${LAB_IMAGE:-lha/insecure-vps:local}
rm -rf "$OUT"; mkdir -p "$OUT"

cleanup() { docker rm -f lha-vps lha-client >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker image inspect "$IMG" >/dev/null 2>&1 || docker build -t "$IMG" lab
docker network create --subnet 172.31.98.0/24 $NET >/dev/null

# Network sysctls as a provider image often ships them (or as an admin left them).
INSECURE_SYSCTLS=(
  --sysctl net.ipv4.tcp_syncookies=0
  --sysctl net.ipv4.conf.all.accept_redirects=1
  --sysctl net.ipv4.conf.all.send_redirects=1
  --sysctl net.ipv4.conf.all.accept_source_route=1
  --sysctl net.ipv4.conf.all.log_martians=0
)
start_vps() { # image, sysctl flags...
  local image=$1; shift
  docker run -d --name lha-vps --hostname vps-lab --network $NET --ip $VPS_IP \
    --cap-add NET_ADMIN "$@" "$image" >/dev/null
  sleep 3
}

external_view() { # label
  local label=$1 f="$OUT/external-$1.txt"
  {
    echo "# External view ($label) from $CLIENT_IP"
    for port in 22 8080; do
      if docker exec lha-client python3 -c "import socket; socket.create_connection(('$VPS_IP', $port), timeout=2)" 2>/dev/null
      then echo "tcp/$port open"; else echo "tcp/$port closed/filtered"; fi
    done
    methods=$(docker exec lha-client ssh -v -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
      -o PreferredAuthentications=none root@$VPS_IP true 2>&1 | grep -m1 "Authentications that can continue" | sed 's/.*continue: //' || true)
    echo "ssh auth methods offered: ${methods:-none (connection refused)}"
    if docker exec lha-client ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
         -i /root/lab_admin_key deploy@$VPS_IP true 2>/dev/null; then
      echo "key login as deploy: OK (admin is not locked out)"
    else
      echo "key login as deploy: FAILED"
    fi
  } | tee "$f"
}

audit() { # label
  docker cp audit.sh lha-vps:/root/audit.sh
  docker exec lha-vps /root/audit.sh -f json --no-color > "$OUT/audit-$1.json" || true
  docker exec lha-vps /root/audit.sh -f markdown > "$OUT/audit-$1.md" || true
  docker exec lha-vps /root/audit.sh --no-color > "$OUT/audit-$1.txt" || true
  tail -1 "$OUT/audit-$1.txt"
}

echo "== 1. Start the insecure VPS"
start_vps "$IMG" "${INSECURE_SYSCTLS[@]}"
docker run -d --name lha-client --network $NET --ip $CLIENT_IP "$IMG" sleep infinity >/dev/null

echo "== 2. Before"
audit before
external_view before

echo "== 3. Harden (dry run, then apply)"
docker cp harden.sh lha-vps:/root/harden.sh
docker exec lha-vps /root/harden.sh | tee "$OUT/harden-dry-run.txt"
docker exec lha-vps /root/harden.sh --apply | tee "$OUT/harden-apply.txt"

echo "== 4. Reboot (commit the disk, start again with the sysctl.d values)"
docker commit lha-vps lha/vps-hardened:local >/dev/null
mapfile -t HARDENED_SYSCTLS < <(docker exec lha-vps sh -c 'cat /etc/sysctl.d/60-hardening.conf' \
  | awk -F' = ' '/^net\.ipv4\./ {print "--sysctl"; print $1"="$2}')
docker rm -f lha-vps >/dev/null
start_vps lha/vps-hardened:local "${HARDENED_SYSCTLS[@]}"

echo "== 5. After"
audit after
external_view after

mkdir -p docs
python3 lab/compare.py "$OUT" > docs/before-after-report.md
echo "report: docs/before-after-report.md"

# Used as an integration test in CI: hardening must leave no FAIL findings and
# must not lock the admin out.
python3 - "$OUT" <<'PY'
import json, sys
after = json.load(open(f"{sys.argv[1]}/audit-after.json"))["summary"]
ext = open(f"{sys.argv[1]}/external-after.txt").read()
ok = after["fail"] == 0 and "key login as deploy: OK" in ext and "8080 closed" in ext
print(f"after: score {after['score']}, {after['fail']} fail -> {'OK' if ok else 'NOT OK'}")
sys.exit(0 if ok else 1)
PY
