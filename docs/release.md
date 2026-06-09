# Release Process

AgentSnitch releases are built from annotated GPG-signed tags. The release
workflow imports the trusted release public key from the GitHub
`release-signing` environment, verifies the tag, then builds, signs, notarizes,
and publishes the package.

## Release Trust Root

The release trust root is the maintainer GPG signing key whose armored public
key is stored in the `RELEASE_GPG_PUBLIC_KEY` secret in the GitHub
`release-signing` environment.

Do not use SSH-signed release tags for AgentSnitch releases. SSH signatures are
useful for developer Git operations, but AgentSnitch releases should use a GPG
key because the same release-signing model can be reused for future update
metadata and installer authenticity checks. An updater can pin the release
public key or key fingerprint, verify signed update manifests, and reject
updates that are not signed by the trusted release key.

## One-Time GPG Setup

Create or import the real maintainer release key on the release machine. Prefer
a hardware-backed key or a passphrase-protected key with a dedicated signing
subkey.

After the private key is available locally, configure this repository and the
GitHub Actions environment secret:

```sh
scripts/configure-release-gpg.sh <release-key-fingerprint-or-key-id>
```

The script:

- Verifies that the private signing key exists locally.
- Exports the armored public key.
- Sets `RELEASE_GPG_PUBLIC_KEY` in the GitHub `release-signing` environment.
- Configures this repository to use OpenPGP tag signing with that key.

You can confirm the secret is present with:

```sh
gh secret list --env release-signing
```

## Cutting a Release

1. Start from a clean `main` checkout:

   ```sh
   git checkout main
   git pull --ff-only origin main
   git status --short
   ```

2. Create an annotated GPG-signed tag:

   ```sh
   git tag -s v0.1.0-pre-alpha.N -m "AgentSnitch v0.1.0-pre-alpha.N"
   git verify-tag v0.1.0-pre-alpha.N
   ```

3. Push the tag:

   ```sh
   git push origin v0.1.0-pre-alpha.N
   ```

The `release-macos` workflow then verifies that:

- The tag name starts with `v`.
- The ref is an existing annotated tag.
- The tag points at the checked-out commit.
- The commit is reachable from `origin/main`.
- The tag signature validates against `RELEASE_GPG_PUBLIC_KEY`.

If any of those checks fail, the release stops before certificates,
provisioning profiles, notarization keys, or package signing are loaded.

The release notes are now sourced from `CHANGELOG.md`. To keep release messaging
accurate, add a `## [<tag>]` section before tagging (for example
`## [v0.1.0-pre-alpha.6]`) with the items for that release. If a matching
section is missing, the workflow falls back to recent commit history.

The `release-signing` environment must remain free of required reviewers. Any
required-reviewer rule on this environment pauses tag-triggered release jobs in a
permanent `waiting` state. If you see that behavior, clear the reviewer rule in
GitHub repository settings before continuing with tag automation.

If this needs to be repaired from automation tooling, you can run:

```sh
gh auth login
./scripts/ensure-release-environment-unlocked.sh release-signing
```
