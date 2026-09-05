#!/usr/bin/env bash
#
# The branch- and tag-protection settings for this repository, written down.
#
#   scripts/repo-settings.sh show    # what GitHub has right now
#   scripts/repo-settings.sh apply   # make GitHub match this file
#
# Why this exists. These settings live in GitHub's database, not in the tree, so
# nothing records what they are or why (#214). Anyone with admin can widen them
# with two clicks and leave no trace, a restored or forked repository comes up
# with none of them, and a reviewer reading this repository cannot tell whether
# the release path is gated at all. `apply` is idempotent, so this file is both
# the record and the way to restore it.
#
# Requires `gh` authenticated as a repository admin.
#
# If a setting here ever locks out something legitimate, it is a fast fix, not an
# emergency: an admin can still delete the ruleset or the branch protection
# through the API (permission to administer a rule is separate from exemption
# from it), so the worst case is a rejected push and a minute of work.

set -euo pipefail

REPO="scttfrdmn/oidc-pam"
BRANCH="main"
RULESET_NAME="Protect release tags"

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh is not installed" >&2
  exit 1
fi

# --- required status checks ---------------------------------------------------
# Every job a pull request has to clear before it can reach main. This list used
# to be Test/Lint/Validate/Build only: the end-to-end suite, both PAM-module
# builds and every security scanner ran on each pull request and none of them
# could block a merge, so a red e2e run was advisory (#214).
#
# These are the *job* checks. The four code-scanning result checks (`CodeQL`,
# `gosec`, `Trivy`, `Semgrep OSS`) are deliberately not here: a required check
# that is only created when its tool uploads results blocks a merge forever on
# the run where the upload does not happen, and the jobs that produce those
# uploads are required already. `OpenSSF Scorecard` is excluded because its
# companion `Scorecard` check reports `neutral` ("skipping") on pull requests,
# and `security/snyk` because it is a third-party status that is often absent
# altogether — either would stall merges for reasons unrelated to the change.
REQUIRED_CHECKS=(
  # ci.yml
  "Test"
  "Lint"
  "Validate"
  "Build"
  "End-to-end (SSH + PAM)"   # the suite that exercises a real sshd and PAM stack
  "PAM (cgo)"                # the module actually compiling against libpam
  "macOS (no PAM headers)"   # the build-tag split still holding on a host with no PAM
  # security.yml
  "CodeQL Analysis (go)"
  "Gosec Security Scanner"
  "Go Vulnerability Check"
  "Semgrep Security Scan"
  "Trivy Security Scan"
  "Dependency Review"
)

show() {
  echo "== branch protection: ${BRANCH} =="
  gh api "/repos/${REPO}/branches/${BRANCH}/protection" --jq '{
    enforce_admins: .enforce_admins.enabled,
    strict: .required_status_checks.strict,
    contexts: .required_status_checks.contexts,
    required_reviews: (.required_pull_request_reviews // null),
    allow_force_pushes: .allow_force_pushes.enabled,
    allow_deletions: .allow_deletions.enabled
  }'
  echo
  echo "== rulesets =="
  gh api "/repos/${REPO}/rulesets" --jq 'if length == 0 then "(none)" else .[] | {id, name, target, enforcement} end'
}

apply() {
  # --- main ------------------------------------------------------------------
  # enforce_admins: true is the substantive change here. Without it the settings
  # below describe what contributors must do and what the maintainer may skip,
  # and the maintainer was skipping it: v0.5.1 was pushed straight to main and
  # git said so — "Bypassed rule violations for refs/heads/main: 4 of 4 required
  # status checks are expected". A release built from a commit no test ran
  # against is exactly the commit that most needs the tests.
  #
  # This is why scripts/release.sh is two-phase: with admins enforced, the
  # release commit has to arrive through a pull request like any other.
  #
  # required_pull_request_reviews stays null on purpose. A pull request is
  # required by GitHub's own rules once direct pushes are blocked, but *approval*
  # is not required, because GitHub will not let an author approve their own pull
  # request and this project has one maintainer: requiring a review would mean
  # nothing could ever merge. If a second maintainer joins, set
  # required_approving_review_count to 1 here.
  #
  # strict: true keeps "branch must be up to date" — the reason a PR that passed
  # in isolation still gets re-run against current main before merging.
  local checks_json
  checks_json="$(printf '%s\n' "${REQUIRED_CHECKS[@]}" | jq -R . | jq -s .)"

  echo "== applying branch protection to ${BRANCH} =="
  jq -n --argjson contexts "$checks_json" '{
    required_status_checks: { strict: true, contexts: $contexts },
    enforce_admins: true,
    required_pull_request_reviews: null,
    restrictions: null,
    allow_force_pushes: false,
    allow_deletions: false
  }' | gh api -X PUT "/repos/${REPO}/branches/${BRANCH}/protection" --input - >/dev/null
  echo "ok"

  # --- v* tags ---------------------------------------------------------------
  # A push of a v* tag is a publish: .github/workflows/release.yml builds from
  # it, signs the artifacts with a Sigstore certificate naming this repository,
  # attaches SLSA provenance, and creates the GitHub release (#180). Nothing
  # restricted who could start that. Anyone with write access — a future
  # collaborator, or a token scoped to write and not admin — could push a v*
  # tag at any commit and get genuinely signed artifacts out of it, whose
  # signature would verify.
  #
  # `update` and `deletion` matter as much as `creation`: a moved tag would make
  # the signature and the provenance describe code that is no longer there, and
  # a deleted-and-recreated tag is a moved tag with extra steps.
  #
  # The bypass is the admin repository role, so releasing still works for a
  # maintainer. That is a real limitation and not a loophole to be embarrassed
  # about: it stops the write-access and stolen-write-token cases, not an admin.
  # Closing the admin case means moving tag creation into a workflow, which is a
  # different piece of work.
  echo "== applying tag ruleset: ${RULESET_NAME} =="
  local body existing
  body="$(jq -n --arg name "$RULESET_NAME" '{
    name: $name,
    target: "tag",
    enforcement: "active",
    bypass_actors: [
      { actor_id: 5, actor_type: "RepositoryRole", bypass_mode: "always" }
    ],
    conditions: { ref_name: { include: ["refs/tags/v*"], exclude: [] } },
    rules: [
      { type: "creation" },
      { type: "update" },
      { type: "deletion" }
    ]
  }')"

  existing="$(gh api "/repos/${REPO}/rulesets" --jq ".[] | select(.name == \"${RULESET_NAME}\") | .id" || true)"
  if [[ -n "$existing" ]]; then
    printf '%s' "$body" | gh api -X PUT "/repos/${REPO}/rulesets/${existing}" --input - >/dev/null
    echo "ok (updated ruleset ${existing})"
  else
    printf '%s' "$body" | gh api -X POST "/repos/${REPO}/rulesets" --input - >/dev/null
    echo "ok (created)"
  fi

  echo
  show
}

case "${1:-}" in
  show) show ;;
  apply) apply ;;
  *)
    echo "usage: $0 show|apply" >&2
    exit 2
    ;;
esac
