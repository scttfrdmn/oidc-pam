#!/usr/bin/env bash
#
# check-pam-module-producers.sh — assert scripts/build-pam-module.sh is the only
# thing that compiles pam_oidc.so.
#
# A module with no PAM entry points in it builds and exits 0 (#140), so the
# artifact has to be inspected before it can be trusted. That inspection lives
# inside scripts/build-pam-module.sh, which cannot finish without it — but only
# for callers that go through it. When each producer compiled the module itself,
# the check was a separate line three of them did not have (#222).
#
# So the invariant worth pinning is not "every producer calls the verifier", which
# is one grep away from being true again by accident. It is "there is one
# producer". This fails the build when a second one appears, which is the point at
# which it is cheap to fix.
#
# Usage: scripts/check-pam-module-producers.sh
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

readonly BUILDER="scripts/build-pam-module.sh"
readonly VERIFIER="scripts/verify-pam-module.sh"

# Every file that can run a build: the Makefile, the shell scripts, the images and
# the workflows. Documentation and Go source are not scanned — prose quotes these
# commands, and no .go file can emit the module.
build_inputs() {
	printf '%s\n' Makefile
	find scripts test .github/workflows \
		-type f \( -name '*.sh' -o -name 'Dockerfile*' -o -name '*.yml' -o -name '*.yaml' \) \
		-print | sort
}

# Compiling the module means one of two things: building the Go package as a
# c-shared library, or handing cgo_bridge_linux.c to a C compiler. A line has to
# name one of those *and* invoke a compiler to count, because these files discuss
# both — #140 is explained by quoting the command that caused it, and this script
# has to contain the pattern it searches for. Comment lines are dropped for the
# same reason.
readonly SUBJECT='buildmode=c-shared|cgo_bridge_linux\.c'
readonly COMPILER='go build|\$\{?CC\}?|(^|[[:space:]"'"'"'])(cc|gcc|clang)[[:space:]]'

offenders() {
	local file
	while IFS= read -r file; do
		[ -f "${file}" ] || continue
		[ "${file}" = "${BUILDER}" ] && continue
		grep -nE "${SUBJECT}" "${file}" 2>/dev/null |
			grep -vE '^[0-9]+:[[:space:]]*(@?#|//)' |
			grep -E "${COMPILER}" |
			sed "s|^|${file}:|" || true
	done < <(build_inputs)
}

status=0

found="$(offenders)"
if [ -n "${found}" ]; then
	echo "check-pam-module-producers: something other than ${BUILDER} builds the PAM module:" >&2
	echo "${found}" | sed 's/^/    /' >&2
	echo >&2
	echo "  Call ${BUILDER} instead. It compiles the module with the hardening flags" >&2
	echo "  and then runs ${VERIFIER} over the result, which is the only way to know a" >&2
	echo "  c-shared or -shared build produced something PAM can use (#140, #222)." >&2
	status=1
fi

# The builder is only worth having as the single producer because it verifies. Its
# own comments say so at length, so this has to find the call and not the prose.
if ! grep -nE "${VERIFIER}" "${BUILDER}" | grep -qvE '^[0-9]+:[[:space:]]*#'; then
	echo "check-pam-module-producers: ${BUILDER} no longer runs ${VERIFIER}." >&2
	echo "  Every producer goes through it, so removing that call leaves nothing" >&2
	echo "  checking that the shipped module has any PAM entry points in it (#140)." >&2
	status=1
fi

if [ "${status}" -eq 0 ]; then
	echo "check-pam-module-producers: OK — ${BUILDER} is the only producer, and it verifies its output."
fi

exit "${status}"
