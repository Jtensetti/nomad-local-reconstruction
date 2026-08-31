#!/usr/bin/env bash
# Run staticcheck, and fail closed when it cannot analyse.
#
# staticcheck exits 0 when it is unable to analyse a module -- for example when
# the module's go directive is newer than the Go release staticcheck was built
# with. It prints one line and reports success:
#
#   -: module requires at least go1.25.0, but Staticcheck was built with go1.24.7 (compile)
#
# So "no findings" and "analysed nothing" look identical to a CI step that only
# reads the exit code. That is how this gate reported zero findings across nine
# repositories while reading none of them.
#
# Two defences, in order of strength:
#   1. A positive control. Before trusting a clean run, staticcheck is pointed
#      at a fixture built to trip a known check. If it does not report it, the
#      tool is not analysing and this script fails regardless of what the real
#      run said.
#   2. Any "(compile)" diagnostic in the real run is a failure, not a finding.
set -euo pipefail

# Pinned. v0.7.0 and later require a Go release newer than this project builds
# with, and an unpinned install would reintroduce exactly the version skew the
# positive control exists to catch.
version="${STATICCHECK_VERSION:-v0.6.1}"
# The module's own toolchain, so staticcheck is built with a release that can
# read this module rather than with whatever the runner happens to have.
toolchain="${STATICCHECK_TOOLCHAIN:-go1.25.0}"

if ! command -v staticcheck >/dev/null 2>&1; then
  echo "== installing staticcheck ${version} (toolchain ${toolchain}) =="
  GOTOOLCHAIN="${toolchain}" go install "honnef.co/go/tools/cmd/staticcheck@${version}"
  PATH="$(go env GOPATH)/bin:${PATH}"
  export PATH
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "== positive control: staticcheck must report a planted finding =="
module_go_version="$(awk '/^go /{print $2; exit}' go.mod)"
mkdir -p "${work}/control"
cat > "${work}/control/go.mod" <<EOF
module staticcheckcontrol

go ${module_go_version}
EOF
# SA4000 and SA4006 are both planted, and both are required. They are the two
# checks that found real weakened assertions in this project -- comparisons
# between identical expressions, and values computed and thrown away -- so the
# control fails if exactly the class that mattered stops being reported.
#
# Two rather than one because a control is only worth what it detects: the
# first fixture written here reported nothing, and a single-check control
# would have been indistinguishable from a working one.
cat > "${work}/control/control.go" <<'EOF'
package control

func ComparedWithItself(a int) bool { return a != a }

func ComputedAndDiscarded() int {
	value := computed()
	value = 2
	return value
}

func computed() int { return 1 }
EOF

control_output="$(cd "${work}/control" && staticcheck ./... 2>&1 || true)"
for planted in SA4000 SA4006; do
  if ! printf '%s\n' "${control_output}" | grep -q "${planted}"; then
    echo "run-staticcheck: the positive control did not report ${planted}." >&2
    echo "run-staticcheck: staticcheck is not analysing this module, so a clean" >&2
    echo "run-staticcheck: run of the real tree would mean nothing." >&2
    printf '%s\n' "${control_output}" | sed 's/^/    /' >&2
    exit 1
  fi
done
echo "   control reported SA4000 and SA4006, so the tool is analysing"

# Pinned component snapshots are separate modules behind replace directives, so
# the root `staticcheck ./...` never reaches them. An unanalysed snapshot is how
# this project shipped a silent wrong-decode in a vendored decoder once already.
modules=(.)
while IFS= read -r found; do
  modules+=("$(dirname "${found}")")
done < <(find components -mindepth 2 -maxdepth 2 -name go.mod 2>/dev/null | sort)

status=0
for module in "${modules[@]}"; do
  echo "== staticcheck ./... in ${module} =="
  output="$(cd "${module}" && staticcheck ./... 2>&1 || true)"

  if printf '%s\n' "${output}" | grep -q '(compile)'; then
    echo "run-staticcheck: staticcheck could not compile part of ${module}." >&2
    echo "run-staticcheck: this is a failure to analyse, not an absence of findings." >&2
    printf '%s\n' "${output}" | sed 's/^/    /' >&2
    status=1
    continue
  fi

  if [ -n "${output}" ]; then
    printf '%s\n' "${output}" | sed 's/^/    /'
    status=1
  fi
done

if [ "${status}" -ne 0 ]; then
  echo "run-staticcheck: findings or unanalysed modules above." >&2
  exit 1
fi

echo "run-staticcheck: OK -- ${#modules[@]} module(s) analysed, and clean."
