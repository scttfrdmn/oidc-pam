# Verifying a release

`oidc-pam` ships `pam_oidc.so`, which is loaded into every authenticating process
on the host — including `sshd` — and a broker that runs as root. "Where did this
binary come from" should be answerable without trusting the GitHub release page,
so from **v0.5.1** every release artifact is signed and carries build provenance
(see [#180](https://github.com/scttfrdmn/oidc-pam/issues/180)).

There is **no oidc-pam signing key**. Signing is
[cosign](https://docs.sigstore.dev/) *keyless*: the release workflow signs with a
short-lived certificate issued to its own GitHub Actions OIDC identity. Nothing
secret is stored in this repository or in its secrets, and the thing you verify is
not "somebody who had the key" but "this repository's release workflow, running on
this tag".

## What each release publishes

For each architecture (`amd64`, `arm64`):

| Asset | What it is |
| --- | --- |
| `oidc-pam-<version>-linux-<arch>.tar.gz` | the release archive |
| `oidc-pam-<version>-linux-<arch>.tar.gz.sha256` | its checksum, on its own (integrity of the download only) |
| `oidc-pam-<version>-linux-<arch>.tar.gz.sigstore.json` | cosign signature bundle for the archive |

and once per release:

| Asset | What it is |
| --- | --- |
| `SHA256SUMS` | checksums of **every** architecture's archive, in one file |
| `SHA256SUMS.sigstore.json` | cosign signature bundle for that manifest |

Each archive additionally has a **SLSA v1 build provenance attestation**, stored
in GitHub's attestation store rather than as a release asset, and fetched by
`gh attestation verify`.

Inside each archive there is one more `SHA256SUMS`, covering the four binaries the
archive installs. `install.sh` checks it before copying anything into
`/usr/local/bin` and `/lib/security`, and refuses to install if it does not match.
That manifest travels inside the archive it describes, so it is only meaningful
*after* you have verified the archive's signature — it protects against a
half-written extraction, not against a hostile tarball.

## Requirements

- **cosign v3.0 or newer** — <https://docs.sigstore.dev/cosign/system_config/installation/>.
  The signatures are Sigstore bundles; cosign v3's `verify-blob` reads them with
  `--bundle`. (Releases deliberately do **not** ship the older detached `.sig` +
  `.pem` pair: cosign v3 removed `verify-blob --signature`/`--certificate`, so
  such a pair would be a signature current cosign cannot check.)
- **`gh` (GitHub CLI)** for the provenance attestation.

## Verify

Substitute the version and architecture you are installing.

```bash
VERSION=v0.5.1
ARCH=amd64   # or arm64
REPO=scttfrdmn/oidc-pam
TARBALL=oidc-pam-${VERSION}-linux-${ARCH}.tar.gz

# The signer identity is this repository's release workflow AT THIS TAG. A
# signature made by any other workflow, repository, or ref will not satisfy it.
IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}"
ISSUER="https://token.actions.githubusercontent.com"

gh release download "${VERSION}" --repo "${REPO}" \
  --pattern "${TARBALL}" --pattern "${TARBALL}.sigstore.json" \
  --pattern SHA256SUMS --pattern SHA256SUMS.sigstore.json
```

### 1. The signature over the archive

```bash
cosign verify-blob \
  --bundle "${TARBALL}.sigstore.json" \
  --certificate-identity "${IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}" \
  "${TARBALL}"
```

Must print `Verified OK`.

### 2. The signed checksum manifest

One signature covers both architectures, so this is the check to use if you
mirror releases or install more than one arch:

```bash
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "${IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}" \
  SHA256SUMS

# --ignore-missing: SHA256SUMS names every arch; you probably downloaded one.
sha256sum --ignore-missing -c SHA256SUMS
```

### 3. The build provenance

This is what ties the archive to a commit, a workflow and a builder, rather than
merely to a signer:

```bash
gh attestation verify "${TARBALL}" --repo "${REPO}" \
  --signer-workflow "${REPO}/.github/workflows/release.yml" \
  --source-ref "refs/tags/${VERSION}"
```

`--repo` alone will pass for any attestation this repository produced;
`--signer-workflow` pins it to the release workflow and `--source-ref` to the tag.
Use all three. Add `--deny-self-hosted-runners` if you want to require a
GitHub-hosted builder.

### Then install

```bash
tar -xzf "${TARBALL}"
cd "oidc-pam-${VERSION}-linux-${ARCH}"
sudo ./install.sh            # verifies the in-archive SHA256SUMS before installing
```

**If any check above fails, do not install the artifact**, and please open a
security report (see [SECURITY.md](../SECURITY.md)) rather than a public issue.

## What each check actually proves

- **`cosign verify-blob` succeeds** — these exact bytes were signed by a workflow
  run of `.github/workflows/release.yml` in `scttfrdmn/oidc-pam` at this tag,
  with an identity attested by GitHub's OIDC issuer, and the signature is recorded
  in Sigstore's public transparency log. Change one byte of the archive and it
  fails.
- **`gh attestation verify` succeeds** — GitHub asserts which workflow, which
  commit and which builder produced the archive, as a SLSA v1 provenance
  statement.
- **`sha256sum -c` succeeds** — the archive matches the manifest that the
  signature in step 2 covers.

What none of them prove: that the source commit is *good*. Provenance answers
"was this built from this repository by its release workflow", not "is this code
safe". It makes a swapped or backdoored *artifact* detectable; it does not audit
the tree it was built from.

## Verifying without network access

Both checks can run offline once the material is on disk.

```bash
# Provenance: fetch the attestation bundle now (writes a .jsonl file into the
# current directory, named after the artifact's digest), verify later.
gh attestation download "${TARBALL}" --repo "${REPO}"
ls *.jsonl

gh attestation verify "${TARBALL}" --repo "${REPO}" \
  --signer-workflow "${REPO}/.github/workflows/release.yml" \
  --bundle <the .jsonl file downloaded above>
```

`--custom-trusted-root <trusted_root.jsonl>` pins the Sigstore trust root as well,
for a host that cannot reach GitHub or Sigstore at all. For cosign,
`verify-blob --trusted-root <file>` does the equivalent — it verifies the bundle
against a trusted root on disk instead of fetching one over TUF; see
`cosign trusted-root create --help`.

Air-gapped installs generally want to verify at the boundary and then move the
verified archive inward, rather than reproducing the Sigstore trust root on every
host.

## Scripting across versions

If you must accept any tag rather than one specific version, use a regexp — and
note that this deliberately weakens the check to "some release of this
repository":

```bash
cosign verify-blob \
  --bundle "${TARBALL}.sigstore.json" \
  --certificate-identity-regexp "^https://github\.com/scttfrdmn/oidc-pam/\.github/workflows/release\.yml@refs/tags/v" \
  --certificate-oidc-issuer "${ISSUER}" \
  "${TARBALL}"
```

Anchor the pattern (`^`) and escape the dots. An unanchored, unescaped pattern
matches identities you did not intend, which is the usual way an identity check is
turned into no check at all.

## Releases before v0.5.1

Releases up to and including v0.5.0 have only a `.sha256` file per archive, and no
signature or provenance. That file is published by the same workflow to the same
release page as the archive, so it detects a corrupted download and nothing else.
There is no way to retroactively sign them; verify by other means or upgrade.
