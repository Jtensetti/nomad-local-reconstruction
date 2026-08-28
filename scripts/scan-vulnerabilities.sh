#!/usr/bin/env bash
# Scan the given module directories for reachable vulnerabilities.
#
# Two things this deliberately does not do.
#
# It does not install govulncheck at @latest. CI runs this tool over the same
# source it is gating, with the same privileges, so the tool is part of the
# trusted set; @latest is whichever build the module proxy serves that minute,
# with nothing in the repository recording what actually ran. Pinning the tool
# does not stale the findings: the vulnerability data is fetched live, only the
# code doing the fetching is fixed.
#
# It does not treat an unreachable vulnerability database as a pass. The
# database is a third-party service that rate-limits, and govulncheck exits
# non-zero both for "found vulnerabilities" and for "could not fetch the list
# to compare against". Collapsing those two would let the gate report success
# on a day the service was down, which is precisely the day it is worth having.
# So a fetch failure is retried, and if it still cannot read the database the
# run fails saying that no scan happened -- never quietly, and never as a
# finding it did not make.

set -euo pipefail

VERSION="${GOVULNCHECK_VERSION:-v1.7.0}"
ATTEMPTS="${GOVULNCHECK_ATTEMPTS:-4}"
# Overridden to zero by the test, which has no reason to wait for a stub.
DELAY="${GOVULNCHECK_DELAY:-5}"

install_tool() {
  local attempt=1 delay="$DELAY"
  while :; do
    if go install "golang.org/x/vuln/cmd/govulncheck@${VERSION}"; then
      return 0
    fi
    if test "$attempt" -ge "$ATTEMPTS"; then
      echo "could not install govulncheck ${VERSION} after ${ATTEMPTS} attempts" >&2
      return 1
    fi
    echo "install failed, retrying in ${delay}s (attempt ${attempt}/${ATTEMPTS})" >&2
    if test "$delay" -gt 0; then sleep "$delay"; fi
    attempt=$((attempt + 1))
    delay=$((delay * 2))
  done
}

scan() {
  local directory="$1"
  local attempt=1 delay="$DELAY"
  local output status
  while :; do
    set +e
    output="$(cd "$directory" && "$GOVULNCHECK" ./... 2>&1)"
    status=$?
    set -e
    printf '%s\n' "$output"
    if test "$status" -eq 0; then
      return 0
    fi
    # govulncheck names the database on the line it fails on. Anything else is
    # a finding, or a build that does not compile, and is not retried: running
    # a scan again because it found something is how a finding gets lost.
    if ! printf '%s' "$output" | grep -q 'fetching vulnerabilities'; then
      return "$status"
    fi
    if test "$attempt" -ge "$ATTEMPTS"; then
      echo "the vulnerability database was unreachable after ${ATTEMPTS} attempts" >&2
      echo "nothing was scanned; this run fails for that, not for a finding" >&2
      return 1
    fi
    echo "vulnerability database unreachable, retrying in ${delay}s (attempt ${attempt}/${ATTEMPTS})" >&2
    if test "$delay" -gt 0; then sleep "$delay"; fi
    attempt=$((attempt + 1))
    delay=$((delay * 2))
  done
}

install_tool
GOVULNCHECK="${GOVULNCHECK_BINARY:-$(go env GOPATH)/bin/govulncheck}"

if test "$#" -eq 0; then
  set -- .
fi
for directory in "$@"; do
  echo "== ${directory} =="
  scan "$directory"
done
