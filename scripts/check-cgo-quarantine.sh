#!/usr/bin/env bash
#
# check-cgo-quarantine.sh — assert cmd/pam-module is the only cgo package.
#
# The PAM module's C bridge needs <security/pam_ext.h> and <json-c/json.h>,
# neither of which exists on macOS. Keeping cgo confined to cmd/pam-module is
# what lets `go build ./...`, `go vet ./...` and `go test ./...` run on a
# developer's Mac (#141), and it is also what keeps the C in the package that is
# built as c-shared, which is the actual fix for the module shipping with no
# entry points (#140).
#
# Neither of those properties is self-enforcing: importing "C" from, say,
# pkg/pam compiles fine on Linux and only breaks for people without the headers,
# which is nobody in CI. So check it directly.
#
# The check reads the build graph rather than the host, so it gives the same
# answer everywhere and needs no PAM headers installed:
#
#   - GOOS=linux, CGO_ENABLED=1: cmd/pam-module, and nothing else, has cgo files.
#     Anything else means cgo leaked into a portable package.
#   - GOOS=darwin: no package has cgo files at all. Anything means a build
#     constraint is missing and the Mac build is about to break.
#
# Usage: scripts/check-cgo-quarantine.sh
set -euo pipefail

readonly ALLOWED="github.com/scttfrdmn/oidc-pam/cmd/pam-module"

# cgo_packages GOOS -> import paths of ./... packages with at least one cgo file
cgo_packages() {
	CGO_ENABLED=1 GOOS="$1" go list -f '{{if .CgoFiles}}{{.ImportPath}}{{end}}' ./... |
		grep -v '^$' || true
}

status=0

linux_cgo="$(cgo_packages linux)"
if [ "${linux_cgo}" != "${ALLOWED}" ]; then
	echo "check-cgo-quarantine: unexpected cgo packages for GOOS=linux." >&2
	echo "  expected exactly: ${ALLOWED}" >&2
	echo "  got:" >&2
	if [ -z "${linux_cgo}" ]; then
		echo "    (none — has the C bridge left cmd/pam-module? see #140)" >&2
	else
		echo "${linux_cgo}" | sed 's/^/    /' >&2
	fi
	status=1
fi

darwin_cgo="$(cgo_packages darwin)"
if [ -n "${darwin_cgo}" ]; then
	echo "check-cgo-quarantine: cgo is reachable on GOOS=darwin, which has no PAM headers." >&2
	echo "  these packages need a //go:build linux constraint (see #141):" >&2
	echo "${darwin_cgo}" | sed 's/^/    /' >&2
	status=1
fi

if [ "${status}" -eq 0 ]; then
	echo "check-cgo-quarantine: OK — cgo is confined to ${ALLOWED#github.com/scttfrdmn/oidc-pam/}."
fi

exit "${status}"
