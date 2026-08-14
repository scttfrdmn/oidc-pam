#!/usr/bin/env bash
#
# build-pam-module.sh <output-path> [expected-arch]
#
# The one path that produces pam_oidc.so. Everything that ships, tests or
# packages the module calls this: the Makefile, the e2e image and release.yml.
# scripts/check-pam-module-producers.sh fails the build if anything else starts
# compiling the module itself.
#
# There is one build path because building the module and checking the result
# cannot be separate steps. A shared object with no PAM entry points in it builds
# and exits 0 (#140), so a compiler's exit status says nothing about whether the
# artifact is usable — only inspecting it does. With the build open-coded in each
# producer, that inspection is a line each producer has to remember, and three of
# them did not (#222). Here it is not a line anyone can forget: this script does
# not finish without running scripts/verify-pam-module.sh over what it just
# built, and there is no flag to ask it not to.
#
# The module is plain C. All six pam_sm_* entry points are in
# cmd/pam-module/cgo_bridge_linux.c and nothing in them calls into Go — the
# package's Go files are cgo test wrappers that drive the C from `go test`, and
# the package exports no Go function to C at all. So the shipped artifact is
# built with the C compiler rather than as a Go c-shared library, which keeps the
# Go runtime — its threads, its signal handlers and its DF_1_NODELETE — out of
# every sshd pre-auth child that loads the module (#198). Keep it that way: if
# something in this module ever needs to call Go, the runtime comes back with it.
#
# Usage:
#   scripts/build-pam-module.sh bin/pam_oidc.so
#   scripts/build-pam-module.sh bin/pam_oidc.so-linux-arm64 arm64
#
# The optional second argument is the architecture the caller intends to ship
# this file as. Give it whenever the output name claims an architecture: the
# compiler builds for whatever it targets, so a name that disagrees with the
# result is a module that installs cleanly and then fails at dlopen time, inside
# sshd's auth path.
#
# Environment:
#   CC  the compiler to use (default: cc). A cross-build needs a cross-toolchain
#       here and the matching PAM and json-c headers for the target.

set -euo pipefail

SO="${1:-}"
EXPECT_ARCH="${2:-}"

if [[ -z "${SO}" ]] || [[ $# -gt 2 ]]; then
    echo "usage: $0 <output-path> [expected-arch]" >&2
    exit 2
fi

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/cmd/pam-module"

# The C bridge needs Linux-PAM (<security/pam_ext.h>) and json-c, neither of
# which exists on macOS. Refusing here is what keeps a developer's Mac from
# producing something that looks like a module: `make build` skips this target off
# Linux, and `make verify-linux` and the e2e harness build it in a container.
if [[ "$(uname -s)" != "Linux" ]]; then
    cat >&2 <<EOF
build-pam-module: the PAM module can only be built on Linux (this is $(uname -s)).
  Its C bridge needs Linux-PAM (<security/pam_ext.h>) and json-c.
  Run 'make verify-linux', or build in a Linux container.
EOF
    exit 1
fi

CC="${CC:-cc}"
if ! command -v "${CC}" >/dev/null 2>&1; then
    echo "build-pam-module: no C compiler (CC=${CC}); install gcc or clang." >&2
    exit 1
fi

# Hardening. cmd/pam-module/bridge_linux.go carries the same flags in its #cgo
# directives so that `go test ./cmd/pam-module` compiles this C the way the
# shipped artifact is compiled; the two lists are meant to agree.
#
# The artifact is a shared object loaded into sshd as root, and it holds a 16 KB
# response buffer on the stack, so:
#   -fstack-protector-strong  guards that buffer and every other stack array.
#   -O2                       is what makes _FORTIFY_SOURCE do anything; the
#                             fortify level itself is a floor set in the C source,
#                             so a distribution that already asks for a higher one
#                             is not quietly downgraded here.
#   -Wl,-z,relro -Wl,-z,now   full RELRO. Without -z now the build gets partial
#                             RELRO only and the PLT stays writable.
#   -Wl,-z,noexecstack        a non-executable stack. The toolchains this is built
#                             with already default to it; stating it means the
#                             property does not depend on that default.
# -fPIC is required for -shared and is not an optional hardening flag here.
#
# Not -Werror: the code is warning-clean under -Wall -Wextra today, but a future
# compiler's new diagnostic would then be a build failure for anyone building
# from source, which is a different bargain from the flags above. CI compiles the
# module on every push, so a new warning is still seen.
CFLAGS_HARDENING=(
    -O2
    -Wall -Wextra
    -fstack-protector-strong
    -fPIC
)
LDFLAGS_HARDENING=(
    "-Wl,-z,relro"
    "-Wl,-z,now"
    "-Wl,-z,noexecstack"
)

mkdir -p -- "$(dirname -- "${SO}")"

echo "build-pam-module: compiling ${SO} with ${CC}"
"${CC}" -shared \
    "${CFLAGS_HARDENING[@]}" \
    -I "${SRC_DIR}" -I /usr/include/security \
    -o "${SO}" \
    "${SRC_DIR}/cgo_bridge_linux.c" \
    "${LDFLAGS_HARDENING[@]}" \
    -lpam -ljson-c

# Assert the file is for the architecture its name claims. The since-deleted
# scripts/build-simple.sh packaged one host-native module as both the amd64 and
# the arm64 artifact (#222, #241); naming the output for the architecture built is
# the fix, and this is what keeps the name honest.
if [[ -n "${EXPECT_ARCH}" ]]; then
    case "${EXPECT_ARCH}" in
        amd64) want_machine="Advanced Micro Devices X86-64" ;;
        arm64) want_machine="AArch64" ;;
        386)   want_machine="Intel 80386" ;;
        *)
            echo "build-pam-module: unknown expected architecture '${EXPECT_ARCH}'" >&2
            exit 2
            ;;
    esac
    if ! command -v readelf >/dev/null 2>&1; then
        # Skipping is not an option: an unchecked name is exactly the artifact
        # this argument exists to prevent.
        echo "build-pam-module: readelf not found; cannot confirm ${SO} is ${EXPECT_ARCH}." >&2
        echo "  install binutils, or drop the expected-arch argument." >&2
        exit 1
    fi
    got_machine="$(readelf -h "${SO}" | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')"
    if [[ "${got_machine}" != "${want_machine}" ]]; then
        echo "build-pam-module: ${SO} is for ${got_machine}, not ${EXPECT_ARCH} (${want_machine})." >&2
        echo "  ${CC} built for its own target. Cross-building needs a cross-toolchain in CC" >&2
        echo "  and the target's PAM and json-c headers; release.yml builds each" >&2
        echo "  architecture on a runner of that architecture instead." >&2
        exit 1
    fi
fi

# The point of the whole script.
"${REPO_ROOT}/scripts/verify-pam-module.sh" "${SO}"
