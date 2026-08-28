#!/usr/bin/env bash
# Prove the vulnerability gate fails closed.
#
# The gate's whole value is the difference between "scanned, found nothing"
# and "could not scan". That difference is one grep on an error message, so it
# is the kind of thing that rots silently: a wording change upstream, or a
# well-meant `|| true`, and the step goes green on days the database is down.
# These four cases are cheap and they pin it.
#
# govulncheck is stubbed. This tests the wrapper's decisions, not the scanner.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
scan="${here}/scan-vulnerabilities.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat > "${work}/go" <<'EOF'
#!/bin/sh
case "$1" in
  install) exit 0 ;;
  env) echo "/nonexistent" ;;
esac
EOF
chmod +x "${work}/go"

stub() {
  cat > "${work}/govulncheck"
  chmod +x "${work}/govulncheck"
}

failures=0
check() {
  local name="$1" want_status="$2" want_calls="$3"
  local status=0
  : > "${work}/calls"
  PATH="${work}:${PATH}" \
  GOVULNCHECK_ATTEMPTS=3 \
  GOVULNCHECK_DELAY=0 \
  GOVULNCHECK_BINARY="${work}/govulncheck" \
  CALLS="${work}/calls" \
    "$scan" "$work" > "${work}/output" 2>&1 || status=$?
  local calls
  calls="$(wc -l < "${work}/calls" | tr -d ' ')"
  if test "$status" != "$want_status" || test "$calls" != "$want_calls"; then
    echo "FAIL ${name}: exit ${status} (want ${want_status}), ${calls} scans (want ${want_calls})"
    sed 's/^/     /' "${work}/output"
    failures=$((failures + 1))
    return
  fi
  echo "ok   ${name}"
}

stub <<'EOF'
#!/bin/sh
echo call >> "$CALLS"
echo "No vulnerabilities found."
EOF
check "a clean scan passes" 0 1

stub <<'EOF'
#!/bin/sh
echo call >> "$CALLS"
echo "Vulnerability #1: GO-2026-1234"
exit 3
EOF
check "a finding fails and is never retried" 3 1

stub <<'EOF'
#!/bin/sh
echo call >> "$CALLS"
echo "govulncheck: fetching vulnerabilities: HTTP GET https://vuln.go.dev/index/modules.json.gz returned unexpected status: 403 Forbidden" >&2
exit 1
EOF
check "an unreachable database fails closed after retrying" 1 3
if ! grep -q "nothing was scanned" "${work}/output"; then
  echo "FAIL an unreachable database must say no scan happened, not report a finding"
  failures=$((failures + 1))
fi

stub <<'EOF'
#!/bin/sh
echo call >> "$CALLS"
if test "$(wc -l < "$CALLS")" -lt 2; then
  echo "govulncheck: fetching vulnerabilities: HTTP GET https://vuln.go.dev/index/modules.json.gz returned unexpected status: 403 Forbidden" >&2
  exit 1
fi
echo "No vulnerabilities found."
EOF
check "a transient database failure is retried and recovers" 0 2

if test "$failures" -ne 0; then
  echo "${failures} failed"
  exit 1
fi
echo "vulnerability gate behaves as specified"
