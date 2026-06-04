# Release Signing and Notarization

AgentSnitch release artifacts are built by GitHub Actions from a tag. The
release workflow packages the Tauri app, Go daemon/support tools, LaunchAgent,
and hook installer wiring into one signed and notarized macOS installer package.

Do not commit certificates, private keys, provisioning profiles, `.p12` files,
App Store Connect keys, notary credentials, generated packages, or notarization
archives. Store them only in GitHub repository secrets or a local keychain.

## Required GitHub Secrets

Provisioning profiles:

- `AGENTSNITCH_HOST_PROFILE_BASE64`
- `AGENTSNITCH_EXTENSION_PROFILE_BASE64`

Developer ID certificates:

- `MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64`
- `MACOS_DEVELOPER_ID_APPLICATION_P12_PASSWORD`
- `MACOS_DEVELOPER_ID_APPLICATION_IDENTITY`
- `MACOS_DEVELOPER_ID_INSTALLER_P12_BASE64`
- `MACOS_DEVELOPER_ID_INSTALLER_P12_PASSWORD`
- `MACOS_DEVELOPER_ID_INSTALLER_IDENTITY`

App Store Connect API key for notarization:

- `APPLE_API_KEY_ID`
- `APPLE_API_ISSUER_ID`
- `APPLE_API_KEY_P8_BASE64`

## Store Provisioning Profiles

The profile files are base64 encoded before storage so GitHub Actions can decode
them on the macOS runner:

```bash
base64 -i "$HOME/Downloads/AgentSnitch_Host_Developer_ID.provisionprofile" \
  | gh secret set AGENTSNITCH_HOST_PROFILE_BASE64

base64 -i "$HOME/Downloads/AgentSnitch_Network_Extension_Developer_ID.provisionprofile" \
  | gh secret set AGENTSNITCH_EXTENSION_PROFILE_BASE64
```

## Store Developer ID Certificates

Export these from Keychain Access as password-protected `.p12` files:

- Developer ID Application certificate and private key
- Developer ID Installer certificate and private key

Then store them:

```bash
base64 -i /path/to/developer-id-application.p12 \
  | gh secret set MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64
gh secret set MACOS_DEVELOPER_ID_APPLICATION_P12_PASSWORD
gh secret set MACOS_DEVELOPER_ID_APPLICATION_IDENTITY \
  --body "Developer ID Application: Scott Moore (FC439DPN89)"

base64 -i /path/to/developer-id-installer.p12 \
  | gh secret set MACOS_DEVELOPER_ID_INSTALLER_P12_BASE64
gh secret set MACOS_DEVELOPER_ID_INSTALLER_P12_PASSWORD
gh secret set MACOS_DEVELOPER_ID_INSTALLER_IDENTITY \
  --body "Developer ID Installer: Scott Moore (FC439DPN89)"
```

`gh secret set ...PASSWORD` prompts for the value without writing it to shell
history.

## Store App Store Connect API Key

Create an App Store Connect API key with access to notarization, then store the
key id, issuer id, and `.p8` key:

```bash
gh secret set APPLE_API_KEY_ID --body "YOUR_KEY_ID"
gh secret set APPLE_API_ISSUER_ID --body "YOUR_ISSUER_ID"

base64 -i /path/to/AuthKey_YOUR_KEY_ID.p8 \
  | gh secret set APPLE_API_KEY_P8_BASE64
```

## Create a Pre-Alpha Release

Create and push a tag:

```bash
git tag -a v0.1.0-pre-alpha.N -m "AgentSnitch v0.1.0 pre-alpha N"
git push origin v0.1.0-pre-alpha.N
```

The `release-macos` workflow builds and publishes a prerelease containing:

- `AgentSnitch-v0.1.0-pre-alpha.N-macos.pkg`
- `AgentSnitch-v0.1.0-pre-alpha.N-macos.pkg.sha256`

The installer installs `AgentSnitch.app` into `/Applications`, installs the
daemon/support tools under `/Library/Application Support/AgentSnitch`, registers
the LaunchAgent, installs Claude Code hooks for the console user, and opens the
app after installation.

The workflow can also be run manually for an existing tag from GitHub Actions.
