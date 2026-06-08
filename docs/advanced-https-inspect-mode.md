# Advanced HTTPS Inspect Mode

AgentSnitch Advanced HTTPS Inspect Mode is optional, local HTTPS inspection for managed AI coding-agent sessions. It is designed to work like a scoped Burp Suite or Charles Proxy flow, but with AgentSnitch evidence attached to agent session and tool-span context.

## Why This Exists

Default AgentSnitch evidence links local tool activity with process/network observations. That is useful for answering "what did the agent touch, and what destination did its process tree contact?" It does not show HTTP request details inside TLS.

Advanced HTTPS Inspect Mode adds a managed localhost proxy that can record HTTP method, host, path, status, sizes, redacted headers, hashes, and optional payload previews for traffic routed through that proxy. When TLS interception is in scope, AgentSnitch terminates TLS locally with a local AgentSnitch CA, records configured evidence, and opens a separate encrypted connection to the destination.

## Developer-Only Posture

HTTPS Inspect Mode is off by default. It is exposed under Settings -> Developer and must be enabled deliberately.

AgentSnitch does not install a trusted root certificate during app install, package install, hook install, daemon startup, or basic OS Sensor activation. System trust is a separate Developer action.

The feature is intentionally a developer/debugging control, not a default visibility path. It is only worth enabling when you need request/response evidence for managed proxy traffic and accept the CA/proxy setup cost.

## What It Can See

For managed proxy traffic, AgentSnitch can record:

- CONNECT host, remote endpoint, timing, byte counts, and metadata-only proxy evidence.
- HTTP method, scheme, host, path, query presence, status, content type, request size, and response size.
- Header names and redacted selected header values.
- Body SHA-256 hashes.
- Redacted request/response previews when preview capture is enabled.
- Redacted full payload records only when full payload capture is explicitly enabled.

## What It Cannot See

AgentSnitch cannot inspect:

- Traffic that bypasses the managed proxy.
- Browser traffic by default.
- All system traffic.
- Clients that reject the AgentSnitch CA due to certificate pinning or custom trust stores.
- Non-HTTP protocols inside TLS, except as metadata-only evidence.
- Raw prompts or model responses unless that specific traffic is routed through the managed proxy, the client accepts the AgentSnitch CA/trust configuration, and payload preview or full payload capture is enabled. Even in full payload mode, AgentSnitch writes redacted local payload records and evidence exports include payload references rather than inlining the retained bodies.

Put differently: OS Sensor mode and the default NetworkStatistics observer can prove that a process contacted a destination, but they do not break TLS. HTTPS Inspect can break and inspect TLS only for managed proxy traffic that honors the proxy and trust configuration.

## Trust Model

The default trust strategy is process-scoped trust. AgentSnitch creates a local CA and a process-scoped CA bundle. Managed tool processes can be launched with environment variables such as `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`, `npm_config_cafile`, and `YARN_CA_FILE`.

System trust is optional. `agentsnitchctl inspect trust-system` installs the AgentSnitch CA into the macOS System keychain and shows the CA fingerprint before doing so. It runs through macOS administrator authorization, so Touch ID or the device's configured admin approval path is required when available. Removal uses the same explicit authorization path through `agentsnitchctl inspect untrust-system`.

Use process-scoped commands when possible:

```bash
agentsnitchctl inspect env
agentsnitchctl inspect run -- <command> [args...]
```

`agentsnitchctl inspect run -- claude` is the managed-session launch path: Claude and tools it starts inherit the process-scoped proxy and CA environment. Existing Claude sessions that were already running before this command will not be retroactively reconfigured, because Claude hooks observe tool activity but cannot mutate the parent process environment.

## Retention

Metadata and redacted previews are separate from full payload capture.

Defaults:

- Metadata: retained with normal session evidence.
- Redacted previews: enabled, capped at 2048 bytes.
- Full payloads: disabled.
- Full payload mode: writes redacted local payload records under the HTTPS Inspect payload store and includes request/response payload refs in the inspected exchange.
- Authorization, Proxy-Authorization, Cookie, Set-Cookie, API key, auth token, AWS session token, GitHub token, OpenAI key, and Anthropic key headers are never stored raw by default.

`agentsnitchctl inspect purge-data` removes captured payload data.

## Disable And Cleanup

Disabling Inspect Mode stops inspection for new sessions and can remove process-scoped trust files and payload data:

```bash
agentsnitchctl inspect disable
```

System trust is intentionally separate:

```bash
agentsnitchctl inspect untrust-system
```

Uninstall checks whether the AgentSnitch CA is still trusted by macOS. If it is, uninstall attempts the same explicit admin-approved removal path and prints Keychain Access fallback instructions if macOS authorization or removal fails.

## Doctor

Use:

```bash
./bin/doctor inspect
agentsnitchctl inspect status
```

Doctor warns when:

- Inspect Mode is enabled but the local CA is missing.
- Private key permissions are broader than `0600`.
- System trust remains installed while Inspect Mode is disabled.
- Full payload capture uses manual retention.
- Inspect Mode is enabled but the managed proxy is unavailable.

## Relationship To OS Sensor

OS Sensor mode is metadata-only system network attribution. It is not a proxy, not TLS interception, and not required for HTTPS Inspect Mode.

HTTPS Inspect Mode is a managed localhost proxy with optional local TLS termination. It stays out of the Network Extension path so the Network Extension remains metadata-only and fail-open.
