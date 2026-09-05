#!/usr/bin/env bash
#
# Cut a release, in two phases:
#
#   scripts/release.sh <version>        # 1. stamp the docs, commit on a release
#                                       #    branch, push it, open the PR
#   scripts/release.sh --tag <version>  # 2. once that PR has merged: tag main
#
# Example:
#   scripts/release.sh 0.4.2            # leading 'v' optional
#   scripts/release.sh --tag 0.4.2
#
# Why two phases, when this used to be one push.
#
# `main` requires its status checks of everyone, admins included (#214), so the
# release commit cannot be pushed straight to it any more — it goes through a PR
# like every other change. That is the point: the previous flow published a
# release from a commit no test had ever run against, and the v0.5.1 push said so
# out loud ("Bypassed rule violations for refs/heads/main: 4 of 4 required status
# checks are expected").
#
# The tag then has to wait for the merge, and not for bureaucratic reasons: this
# repository rebase-merges, which rewrites the commit. A tag created in phase 1
# would point at a commit that is not on main, so the release workflow would
# build, sign and publish something no branch contains — and `git describe` on
# main would never find it. Phase 2 tags merged main after checking that main
# really does carry the release commit for this version.
#
# Tagging from the stamped commit is still what keeps the README badge, the
# download snippet and the CHANGELOG heading in agreement with the tag; phase 2
# now verifies that rather than assuming it.
#
# Preconditions: clean working tree on the default branch, a "## [Unreleased]"
# section in CHANGELOG.md with content, push access, and `gh` authenticated.

set -euo pipefail

MODE="prepare"
if [[ "${1:-}" == "--tag" ]]; then
  MODE="tag"
  shift
fi

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <version>          (e.g. $0 0.4.2)" >&2
  echo "       $0 --tag <version>    (after the release PR has merged)" >&2
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

RELEASE_BRANCH="release/${TAG}"

# The branch the release is cut from, as origin reports it rather than as this
# script assumes it.
DEFAULT_BRANCH="$(git symbolic-ref -q --short refs/remotes/origin/HEAD 2>/dev/null | sed 's#^origin/##')"
DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"

# --- preconditions shared by both phases -------------------------------------
if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree is not clean; commit or stash first" >&2
  exit 1
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$BRANCH" != "$DEFAULT_BRANCH" ]]; then
  echo "error: on branch '${BRANCH}'; releases are cut from '${DEFAULT_BRANCH}'" >&2
  exit 1
fi

if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  echo "error: tag ${TAG} already exists locally" >&2
  exit 1
fi

git fetch --quiet origin "${DEFAULT_BRANCH}" --tags

if [[ -n "$(git ls-remote --tags origin "refs/tags/${TAG}")" ]]; then
  echo "error: tag ${TAG} already exists on origin" >&2
  exit 1
fi

if [[ "$(git rev-parse HEAD)" != "$(git rev-parse "origin/${DEFAULT_BRANCH}")" ]]; then
  echo "error: ${DEFAULT_BRANCH} is not level with origin/${DEFAULT_BRANCH}; pull or push first" >&2
  exit 1
fi

# --- phase 2: tag merged main -------------------------------------------------
# Everything here is a check that the commit about to be tagged is the release
# commit for this version. A tag on the wrong commit is not a cosmetic mistake:
# the release workflow builds, signs and attests whatever the tag points at, and
# the attestation then says that artifact came from this repository at that
# commit — truthfully, about the wrong code.
if [[ "$MODE" == "tag" ]]; then
  if ! grep -q "badge/Version-${VER}-blue" README.md; then
    echo "error: README's version badge does not read ${VER}; is the release PR merged?" >&2
    exit 1
  fi
  if ! grep -qx "VERSION=${TAG}" README.md; then
    echo "error: README's download snippet does not read VERSION=${TAG}" >&2
    exit 1
  fi
  if ! grep -q "^## \[${VER}\] - " CHANGELOG.md; then
    echo "error: CHANGELOG.md has no '## [${VER}] - <date>' section" >&2
    exit 1
  fi

  SUBJECT="$(git log -1 --format=%s)"
  if [[ "$SUBJECT" != "chore(release): ${TAG}" ]]; then
    echo "error: HEAD is '${SUBJECT}', not 'chore(release): ${TAG}'" >&2
    echo "       Phase 2 tags the release commit itself, so that the tag, the README" >&2
    echo "       and the CHANGELOG cannot disagree. Rebase-merge the release PR and" >&2
    echo "       pull, then run this again." >&2
    exit 1
  fi

  git tag -a "${TAG}" -m "oidc-pam ${TAG}"
  echo
  echo "Tagged ${TAG} at $(git rev-parse --short HEAD) on ${DEFAULT_BRANCH}:"
  git --no-pager show --stat --oneline HEAD | head -20
  echo
  read -r -p "Push tag ${TAG} to origin? [y/N] " ans
  if [[ "${ans:-}" =~ ^[Yy]$ ]]; then
    git push origin "${TAG}"
    echo "Pushed ${TAG}. The release workflow will run the CI set, then build, sign"
    echo "and publish the artifacts."
  else
    echo "Not pushed. To undo locally: git tag -d ${TAG}"
  fi
  exit 0
fi

# --- phase 1: stamp the docs and open the release PR -------------------------
if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh is not installed; it is needed to open the release PR" >&2
  exit 1
fi

if git rev-parse -q --verify "refs/heads/${RELEASE_BRANCH}" >/dev/null; then
  echo "error: branch ${RELEASE_BRANCH} already exists; delete it or finish that release" >&2
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

# --- stamp the two prose version strings -------------------------------------
# The roadmap heading ("Delivered (through vX.Y.Z)") and the status line
# ("Current Status: Pre-1.0 (vX.Y.Z)") are where a reader looks to judge how
# current the document is, and nothing stamped either: both still said v0.4.0
# two releases later, a few screens below a badge that said 0.5.0. A README that
# contradicts itself about its own version teaches readers to discount all of it,
# including the parts that matter — the OpenSSH 7.7 requirement and the warnings
# about which PAM stacks this must never go into (#147).
if ! grep -q '^### Delivered (through v' README.md; then
  echo "error: could not find README's '### Delivered (through vX.Y.Z)' heading" >&2
  exit 1
fi
if ! grep -q '^\*\*Current Status\*\*: Pre-1.0 (v' README.md; then
  echo "error: could not find README's '**Current Status**: Pre-1.0 (vX.Y.Z)' line" >&2
  exit 1
fi
perl -0pi -e "s{^### Delivered \(through v[^)]*\)}{### Delivered (through v${VER})}mg" README.md
perl -0pi -e "s{^\*\*Current Status\*\*: Pre-1\.0 \(v[^)]*\)}{**Current Status**: Pre-1.0 (v${VER})}mg" README.md

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

# --- commit on a release branch and open the PR ------------------------------
git checkout -q -b "${RELEASE_BRANCH}"
git add README.md CHANGELOG.md
git commit -q -m "chore(release): ${TAG}"

echo
echo "Prepared ${TAG} on branch '${RELEASE_BRANCH}':"
git --no-pager show --stat --oneline HEAD | head -20
echo
read -r -p "Push ${RELEASE_BRANCH} and open the release PR? [y/N] " ans
if ! [[ "${ans:-}" =~ ^[Yy]$ ]]; then
  echo "Not pushed. To undo locally:"
  echo "  git checkout ${DEFAULT_BRANCH} && git branch -D ${RELEASE_BRANCH}"
  exit 0
fi

git push -q -u origin "${RELEASE_BRANCH}"
gh pr create \
  --base "${DEFAULT_BRANCH}" \
  --head "${RELEASE_BRANCH}" \
  --title "chore(release): ${TAG}" \
  --body "$(cat <<EOF
Stamps the README version badge, the \`VERSION=${TAG}\` download snippet, the
roadmap heading and the status line, and rolls \`## [Unreleased]\` into
\`## [${VER}] - ${TODAY}\`.

Generated by \`scripts/release.sh ${VER}\`. No code changes.

Once this is **rebase-merged** and \`${DEFAULT_BRANCH}\` is pulled:

\`\`\`bash
scripts/release.sh --tag ${VER}
\`\`\`

That tags the merged release commit and pushes the tag, which is what triggers
the release workflow. The tag is deliberately not created before the merge: a
rebase-merge rewrites the commit, so a tag made now would point at a commit that
is not on \`${DEFAULT_BRANCH}\`.
EOF
)"

echo
echo "Next: wait for the checks, rebase-merge the PR, then:"
echo "  git checkout ${DEFAULT_BRANCH} && git pull && scripts/release.sh --tag ${VER}"
