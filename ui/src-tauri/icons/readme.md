# AgentSnitch macOS icon assets

Generated from: `a_logo_for_agentsnitch_is_displayed_with_the_nam.png`

## Contents

- `AgentSnitch.appiconset/` — standard macOS app icon PNG sizes.
- `AgentSnitch.icns` — best-effort macOS `.icns` file: created.
- `window-icons/` — icon-only PNGs for window title bars, toolbars, menu/status usage.
- `full-logo-resized/` — full logo with wordmark for docs/marketing only.

## Recommended use

Use the icon-only assets for the macOS app/window icon. The full wordmark does not read well at small icon sizes.

These assets are static UI files only. They do not contain runtime evidence, local paths, provisioning material, signing secrets, or user data.

Do not add source images that embed user names, local paths, screenshots, tokens, license keys, certificate metadata, or provisioning details. Icon rebuilds should only commit deterministic app assets needed by Tauri/macOS.

## Rebuild .icns on macOS

```bash
iconutil -c icns AgentSnitch.appiconset -o AgentSnitch.icns
```
