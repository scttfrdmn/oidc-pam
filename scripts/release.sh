#!/usr/bin/env bash
#
# Cut a release: stamp the README version badge and the CHANGELOG, commit, create
# an annotated tag, and push. Tagging this way guarantees the README/CHANGELOG in
# the tagged commit always match the version (no manual sync drift).
#
# Usage:
#   scripts/release.sh <version>
# Example:
#   scripts/release.sh 0.4.2          # leading 'v' optional
#
# Preconditions: clean working tree on the default branch, a "## [Unreleased]"
# section in CHANGELOG.md with content, and push access.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <version>   (e.g. $0 0.4.2)" >&2
  exit 2
fi

# Normalize: accept "0.4.2" or "v0.4.2"; VER has no 'v', TAG has the 'v'.
VER="${1#v}"
TAG="v${VER}"

if ! [[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "error: '$VER' is not a valid semver version" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# --- preconditions -----------------------------------------------------------
if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree is not clean; commit or stash first" >&2
  exit 1
fi

if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  echo "error: tag ${TAG} already exists" >&2
  exit 1
fi

if ! grep -q '^## \[Unreleased\]' CHANGELOG.md; then
  echo "error: no '## [Unreleased]' section in CHANGELOG.md" >&2
  exit 1
fi

# The Unreleased section must contain at least one bullet (don't release nothing).
UNRELEASED_BODY="$(awk '/^## \[Unreleased\]/{f=1;next} /^## /{f=0} f' CHANGELOG.md | grep -c '^- ' || true)"
if [[ "$UNRELEASED_BODY" -eq 0 ]]; then
  echo "error: '## [Unreleased]' has no entries to release" >&2
  exit 1
fi

TODAY="$(date -u +%Y-%m-%d)"

# --- stamp README version badge ---------------------------------------------
# Matches: ...badge/Version-<anything>-blue...
if ! grep -q 'badge/Version-' README.md; then
  echo "error: could not find version badge in README.md" >&2
  exit 1
fi
perl -0pi -e "s{badge/Version-[^-]*(?:-[^-]*)*?-blue}{badge/Version-${VER}-blue}g" README.md
# Simpler, robust replacement of just the version token between 'Version-' and '-blue':
perl -0pi -e "s{(badge/Version-)([^)]*?)(-blue)}{\${1}${VER}\${3}}g" README.md

# --- stamp the download snippet's VERSION ------------------------------------
# The README's "From a release" block opens with `VERSION=vX.Y.Z`, and every curl,
# tar and verify command below it interpolates that. Nothing used to stamp it, so it
# sat at v0.4.0 through two releases: readers were told to download a version that
# was no longer current, and — once the cosign instructions landed beneath it — to
# verify a signature that version does not have (#180). The badge check in
# verify-version did not catch it because it only reads the badge; that job now
# checks this line too, so the two cannot disagree again.
if ! grep -qE '^VERSION=v[0-9]' README.md; then
  echo "error: could not find the 'VERSION=vX.Y.Z' download snippet in README.md" >&2
  exit 1
fi
perl -0pi -e "s{^VERSION=v[0-9][^\n]*}{VERSION=v${VER}}mg" README.md

# --- roll CHANGELOG: insert a new version section below [Unreleased] ---------
# Turn:
#   ## [Unreleased]
#   <entries>
# into:
#   ## [Unreleased]
#
#   ## [<ver>] - <date>
#   <entries>
awk -v ver="$VER" -v date="$TODAY" '
  /^## \[Unreleased\]/ && !done {
    print
    print ""
    print "## [" ver "] - " date
    done=1
    next
  }
  { print }
' CHANGELOG.md > CHANGELOG.md.tmp && mv CHANGELOG.md.tmp CHANGELOG.md

# --- commit, tag, push -------------------------------------------------------
git add README.md CHANGELOG.md
git commit -m "chore(release): ${TAG}"
git tag -a "${TAG}" -m "oidc-pam ${TAG}"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
echo
echo "Prepared ${TAG} on branch '${BRANCH}':"
git --no-pager show --stat --oneline HEAD | head -20
echo
read -r -p "Push commit and tag to origin? [y/N] " ans
if [[ "${ans:-}" =~ ^[Yy]$ ]]; then
  git push origin "${BRANCH}"
  git push origin "${TAG}"
  echo "Pushed ${TAG}. The release workflow will build artifacts and publish the GitHub release."
else
  echo "Not pushed. To undo locally: git tag -d ${TAG} && git reset --hard HEAD~1"
fi
