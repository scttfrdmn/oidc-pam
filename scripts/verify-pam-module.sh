#!/usr/bin/env bash
#
# verify-pam-module.sh <path-to-pam_oidc.so>
#
# Asserts that a built PAM module is actually loadable by PAM: that it exports
# all six pam_sm_* entry points and links the libraries the C bridge needs.
#
# This exists because a build that produces a module with *no* entry points at
# all exits 0 (#140). cgo compiles only the C sources in the directory of the
# package being built, so when cgo_bridge.c lived in pkg/pam — a package
# cmd/pam-module does not import — `go build -buildmode=c-shared ./cmd/pam-module`
# happily emitted a shared object containing none of them. Nothing failed:
# cgo_bridge.h supplied valid declarations, nothing referenced libpam, and
# Debian's default -Wl,--as-needed dropped -lpam as unused. Every release shipped
# a module that PAM could load and find nothing in, so every C-side fix was
# absent from the artifact regardless of what the source said.
#
# A compiler cannot catch that; only inspecting the result can. Anything that
# produces a shipped .so must run this — `make build-pam` and the release
# workflow both do.

set -euo pipefail

SO="${1:-}"
if [[ -z "${SO}" ]]; then
    echo "usage: $0 <path-to-pam_oidc.so>" >&2
    exit 2
fi
if [[ ! -f "${SO}" ]]; then
    echo "verify-pam-module: ${SO} does not exist" >&2
    exit 1
fi

# The six functions libpam looks up by name. A module missing the one for a phase
# it is configured in makes PAM log "no module data" and fail the stack.
ENTRY_POINTS=(
    pam_sm_authenticate
    pam_sm_setcred
    pam_sm_acct_mgmt
    pam_sm_open_session
    pam_sm_close_session
    pam_sm_chauthtok
)

fail=0

if ! command -v nm >/dev/null 2>&1; then
    echo "verify-pam-module: nm not found; cannot verify ${SO}" >&2
    echo "  install binutils, or build inside the container (make verify-linux)." >&2
    exit 1
fi

# -D/--dynamic reads the dynamic symbol table, which is the only one that
# survives -s -w stripping and the only one dlopen() can resolve against.
symbols="$(nm -D --defined-only "${SO}" 2>/dev/null || true)"

for sym in "${ENTRY_POINTS[@]}"; do
    if ! grep -q " T ${sym}\$" <<<"${symbols}"; then
        echo "verify-pam-module: MISSING ENTRY POINT: ${sym}" >&2
        fail=1
    fi
done

if [[ "${fail}" -ne 0 ]]; then
    cat >&2 <<'EOF'

The module built, but PAM cannot use it. The usual cause is that the C sources
implementing the entry points are not in the package being built: cgo compiles
only the .c files sitting in that package's own directory, and an #include of a
header from elsewhere gives declarations without definitions. Keep
cgo_bridge_linux.c in cmd/pam-module.
EOF
    exit 1
fi

# Header-only linkage is what made #140 silent, so check the libraries too: the
# entry points can be present while a stub is linked in place of real libpam.
if command -v readelf >/dev/null 2>&1; then
    needed="$(readelf -d "${SO}" 2>/dev/null || true)"
    for lib in libpam libjson-c; do
        if ! grep -q "NEEDED.*${lib}" <<<"${needed}"; then
            echo "verify-pam-module: ${SO} does not link ${lib} (missing from DT_NEEDED)" >&2
            fail=1
        fi
    done
    if [[ "${fail}" -ne 0 ]]; then
        echo "  The linker dropped it as unused, which means the C bridge was not compiled in." >&2
        exit 1
    fi
else
    echo "verify-pam-module: readelf not found; skipped the DT_NEEDED check" >&2
fi

echo "verify-pam-module: ${SO} exports all ${#ENTRY_POINTS[@]} pam_sm_* entry points and links libpam"
