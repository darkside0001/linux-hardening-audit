#!/usr/bin/env bash
# Runs audit.sh against the fixture filesystems and checks the findings.
# Git does not keep file modes other than +x, so modes are set here first.
set -u
cd "$(dirname "$0")/.." || exit 2
FX=tests/fixtures
mkdir -p "$FX/bad/tmp" "$FX/good/tmp"   # git does not track empty directories
chmod 644 "$FX/bad/etc/shadow";  chmod 666 "$FX/bad/etc/writable.conf"; chmod 755 "$FX/bad/tmp"
chmod 640 "$FX/good/etc/shadow"; chmod 1777 "$FX/good/tmp"
chmod 644 "$FX"/{bad,good}/etc/passwd

pass=0; fail=0
expect() { # expect FIXTURE ID STATUS
  local got
  got=$(./audit.sh --root "$FX/$1" --format json | grep -o "\"id\": \"$2\"[^}]*\"status\": \"[A-Z]*\"" | grep -o '[A-Z]*"$' | tr -d '"')
  if [[ "$got" == "$3" ]]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $1 $2 expected $3, got '${got:-none}'"; fi
}

for id in SSH-01 SSH-02 ACC-01 ACC-02 FS-_etc_shadow FS-WW KRN-01 KRN-02 KRN-03; do expect bad "$id" FAIL; done
for id in SSH-04 SSH-05 SSH-06 ACC-03 ACC-04 FS-TMP; do expect bad "$id" WARN; done
expect bad SSH-03 PASS
for id in SSH-01 SSH-02 SSH-03 SSH-04 SSH-05 SSH-06 ACC-01 ACC-02 ACC-03 ACC-04 \
          FS-_etc_passwd FS-_etc_shadow FS-WW FS-TMP KRN-01 KRN-02 KRN-03 KRN-04 KRN-05 KRN-06; do
  expect good "$id" PASS
done

# drop-in in sshd_config.d must win over the main file (Include at top)
expect good SSH-02 PASS

check() { # check DESCRIPTION COMMAND...
  local desc=$1; shift
  if "$@"; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $desc"; fi
}
exit_code() { ./audit.sh "$@" >/dev/null; echo $?; }

check "good fixture exits 0" test "$(exit_code --root "$FX/good")" -eq 0
check "bad fixture exits 1"  test "$(exit_code --root "$FX/bad")" -eq 1
check "JSON output is valid" bash -c "./audit.sh --root '$FX/bad' --format json | python3 -m json.tool >/dev/null"
check "Markdown findings table" bash -c "./audit.sh --root '$FX/bad' --format markdown | grep -q '^| ACC-01 | high | FAIL'"

echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
