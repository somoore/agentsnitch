# AgentSnitch — Product Requirements Document (PRD)

**Version:** 0.2 (Local MVP)
**Date:** 2026-06
**Status:** Local MVP implemented; distribution polish remains
**Owner:** Scott Moore (somoore)

---

## 1. Problem Statement

AI coding agents (Claude Code, Cursor, OpenAI Codex / codex-cli, Gemini CLI, and emerging tools) have been given unprecedented local agency on developers' machines. They can:

- Read arbitrary files (including secrets, keys, source, history).
- Execute shell commands, interpreters, and installers.
- Call MCP servers (which themselves can return untrusted content or instructions).
- Initiate outbound network connections (the primary exfil, C2, and second-stage payload channel).

The industry response so far has largely been one of two things:

- **Enterprise security platforms** focused on policy-as-code, central telemetry aggregation, detection rules, and response workflows. These inherit the 2010s EDR mindset: signatures, behavioral baselines, and correlation rules. They are poorly suited to an adversary that is a large language model generating novel, context-aware, polymorphic sequences of actions expressed in natural language.
- **Heavy mediation layers** (hook-based "sandboxes in reverse," IFC/taint systems, etc.) that attempt to intercept every tool call and apply allow/ask/deny decisions. These suffer from (a) extreme complexity, (b) per-vendor hook surface churn, (c) high developer friction, and (d) the fundamental problem that a determined or confused-deputy agent can still cause damage through paths the hooks don't perfectly cover.

**The result is a massive visibility gap.** Developers and security teams have almost no practical way to answer the question: "While I was using my AI coding agent just now, what sensitive things did it touch and what did it actually send over the network?"

Traditional network monitoring (Little Snitch, Lulu, Wireshark, EDR) shows raw flows but lacks the semantic "why" from the agent's tool surface. Hook-based tools show the "why" (or intent) but usually stop at local enforcement and don't reliably ground it in actual bytes on the wire. Neither alone is sufficient.

AgentSnitch exists to close that correlation gap with a developer-centric, low-friction visibility product.

---

## 2. Vision & Positioning

**"Little Snitch for AI coding agents."**

A small, always-available but mostly-invisible local tool that lights up the moment you start an AI coding agent and shows you, in near real time and with rich context, the dangerous transitions happening on your machine.

It is deliberately **not** positioned as:
- A full enterprise agent security platform.
- A replacement for sandboxing, containers, or least-privilege engineering.
- A blocker or policy engine (at least in phase 1).

It **is** positioned as:
- The thing that makes the abstract risk undeniable for the person who actually feels the pain (the developer at the keyboard).
- A high-signal data source that can later feed better policy, better sandboxes, or better human judgment.
- A forcing function that accelerates the rest of the ecosystem (agent vendors improving their own isolation, OS vendors adding better primitives, etc.).

---

## 3. Goals & Success Metrics (Phase 1 / MVP)

### Primary Goal
Within 5–15 minutes of a developer using an AI coding agent with AgentSnitch installed, they should have seen at least one concrete, correlated example of sensitive material access followed (or accompanied) by external network activity that they did not explicitly intend.

### Success Metrics (qualitative + leading indicators)
- Developers report "I had no idea it was doing that" or equivalent after seeing a correlated event.
- Time from "agent starts a session" to "first interesting correlated event surfaced" is low (seconds to a couple minutes in active use).
- The UI is described as "non-annoying" or "appropriately quiet" when nothing interesting is happening.
- Hook registration and System Extension approval are one-time costs that people are willing to pay after seeing value.
- Early users voluntarily share screenshots or session transcripts (anonymized) because the output is compelling.

### Non-goals / Anti-goals for v1
- Zero developer friction / completely silent install (we accept a one-time approval step for the System Extension).
- Perfect coverage of every possible agent and every possible bypass.
- Any form of blocking, redaction, or interactive prompts during the agent session.
- Central collection or SaaS backend.
- Cross-platform support (Linux/Windows come after macOS is solid).
- Full tamper-evidence or forensic ledger (a lightweight session transcript is fine).

### Current Local MVP Status

The local MVP now proves the core product path on macOS:

- Claude Code hook events provide semantic truth.
- The macOS Network Extension provides real OS/process network truth.
- The daemon links those streams using time-window and process-tree evidence.
- The UI defaults to attention-needed evidence, keeps raw hook/network events separated to avoid flooding the user, and lets users expand linked cards for raw reasons, timing, byte counts, destination, and process-tree context.
- Linked cards separate correlation confidence from risk and decision state. The current decision state is `Observed`; future policy work can move the same field to `Allowed`, `Blocked`, or `Would Block`.
- Destination categories identify normal services such as known Claude service, Playwright bridge traffic, telemetry/logging, package registry, local dev server bridge, and unknown external traffic.
- Known low-risk linked service traffic is collapsed by category in the linked feed so it remains available without dominating the main evidence list.
- Session export produces schema-tagged JSONL with a session header and per-event evidence fields so users can share or debug a short session without replaying product data.
- Quiet, per-pattern quiet, and dismiss mechanics reduce noisy cards without erasing the session transcript; very high-signal linked evidence can still break through quiet mode.

Runtime product evidence must come from real sensors only. Test fixtures may construct events for tests, but the app must not ship demo detections, synthetic evidence cards, or raw UI/API paths that let prepared JSON masquerade as agent activity.

---

## 4. Target Users & Personas

**Primary (Phase 1):**
- Individual power users / early adopters of AI coding agents (heavy Claude Code or Cursor users who live in the terminal or IDE + agent loop).
- Security-conscious developers who have already had the "what if it reads my .env and phones home?" thought.
- People who tried heavier tools (sir, custom sandboxes, etc.) and found them too heavy or brittle.

**Secondary (later phases):**
- Security engineers / platform teams who want to understand real agent behavior before rolling out policy.
- Researchers studying supply-chain and confused-deputy risks in agentic coding.
- Eventually, teams that want to run agents in higher-risk contexts (customer codebases, regulated data, etc.) with better observability.

---

## 5. Scope

### In Scope for Initial Release (MVP)

**Functional**
- Detection that an AI coding agent session has started (via hooks + process signals).
- Lightweight hook sensor registration for at least one primary agent (Claude Code as reference implementation; Cursor/Gemini/Codex as stretch).
- Structured emission of normalized hook events (tool name, arguments/targets, classification tags such as "sensitive_read", "external_egress_attempt", "mcp_response", etc.).
- Claude Code sub-agent visibility for process-backed fanout, built-in `Agent` tool delegation, and Claude sidechain transcript work. When no separate Claude CLI process exists, AgentSnitch should show hook-inferred or sidechain-derived sub-agent identity from `tool_use_id`, `agentId`, hook PID when available, `subagent_type`, and the hook/sidechain description instead of hiding the delegation under the main agent. Sidechain `tool_use` rows should surface as subagent activity and clicking a subagent should filter to that agent's event stream.
- Unprivileged macOS userland network observation that logs outbound connections from known or likely AI coding-agent process trees with usable PID/process attribution.
- The default userland observer is polling-based and best-effort; product copy and diagnostics must make clear that short-lived flows can be missed unless the opt-in Network Extension is enabled.
- Optional macOS Network Extension for users who explicitly opt into stronger audit-token network attribution.
- Local daemon that receives both streams and performs best-effort correlation (time window + process tree + semantic hints).
- Tauri-based menu bar / tray application.
- Minimal "agent active" UI surface: status item that appears or badges when an agent is detected; click or automatic trigger shows a compact popup/panel (top-of-screen or popover style) with a live or recent list of events, highlighting correlated "interesting" ones and showing a compact main-agent to subagent breakdown when teams are active.
- Basic interestingness heuristics:
  - External (non-loopback) network activity.
  - Network activity temporally close to a sensitive file read or credential-like shell command.
  - High outbound volume after file read or MCP ingestion.
  - Connections to previously unseen hosts in the current session.
  - Repeat suppression for expected network-heavy browser automation after the first same-pattern/same-destination card, while allowing sensitive, high-volume, or first-destination cards through.
  - Persistent per-project quieting for exact linked patterns, tool/destination pairs, browser-automation family/category combinations, plus a global known-service preset for Claude/Playwright bridge, telemetry, package registry, and local development bridge/tunnel traffic.
  - Default collapsed groups for known low-risk linked service categories: known Claude service, telemetry/logging, Playwright bridge traffic, package registry, and local dev server bridge.
  - Attention-first default view for medium/high risk, unknown external, first-time unknown destination, raw/private IP, sensitive/credential egress, large unknown transfer, new MCP server, public tunnel/listener, blocked, and ask-needed evidence.
  - Clearer titles when localhost MCP/browser actions bridge to external destinations.
  - Product-friendly generic card title: `Tool call → outbound connection`.
  - More specific large-transfer titles for high-byte MCP/tool correlations, informational titles for known Claude service traffic, and a credential-context title for credential-like output followed by outbound traffic.
  - Minimal session summary totals for known Claude traffic, telemetry, local bridge traffic, package traffic, high-signal cards, and new destinations.
- Session-scoped history (events for the current "agent run" are visible; old sessions are summarized or discarded).
- One-time or simple install flow that registers the sensors.
- Ability to export a session transcript (JSONL or human-readable) for sharing or later analysis.
- Contributor and release workflows must keep real secrets, signing credentials, provisioning material, local transcripts, and generated build outputs out of git.

**Non-Functional**
- Everything stays local to the machine.
- Low CPU/memory impact when no agent is running.
- The tool itself should not generate significant noise or "interesting" events in normal operation.
- Graceful degradation if hooks are incomplete or the Network Extension is not approved.

### Out of Scope (MVP, explicitly deferred)

- Any enforcement, blocking, allow-listing, or interactive approval UX.
- Deep content inspection of TLS payloads (SNI + metadata only).
- Full process sandboxing or namespace containment (this is complementary to, not a replacement for, tools like gVisor, bwrap, or `sir run`-style containment).
- Support for every agent on day one.
- Windows or Linux Network Extension / eBPF equivalents.
- Rich historical database or long-term storage.
- Integration with SIEM, Slack, etc. (export is sufficient).
- "Managed" or enterprise policy distribution.
- Automatic remediation or secret redaction in the UI (visibility only).

---

## 6. Key User Flows

1. **First-time setup**
   - User runs install command.
   - Tool detects installed agents.
   - Registers hook emitters (modifies agent config files).
   - Prompts user to approve the System Extension in Privacy & Security.
   - Tray icon appears (or becomes active).

2. **Normal development with agent**
   - User starts Claude Code (or Cursor, etc.) in a project.
   - AgentSnitch detects activity (hook fires or process appears).
   - Tray icon lights up / shows "Claude Code active".
   - User works normally. Most activity is quiet.

3. **"Oh shit" moment**
   - Agent reads a sensitive file (via Read tool, `cat .env`, `grep` on credential path, etc.).
   - Shortly after, the agent (or a child process it spawned) makes an external network connection.
   - The popup surfaces (or user clicks the icon) and sees a clearly linked pair of events with timing, tags, and destination.
   - User can expand for raw details, copy the event, or export the whole short session transcript.

4. **End of session**
   - Agent exits or user stops using it.
   - UI collapses back to quiet tray icon (or hides).
   - Optional: "Review last session" summary with count of external calls after sensitive access.

5. **Evidence export (power user / security person)**
   - User exports the session transcript.
   - Can share with team, attach to incident, or feed into another tool.

---

## 7. Functional Requirements

**FR-1 Hook Sensors**
- Must support registration of command-style hooks in at least the primary agent's configuration format.
- Emitter must be thin, fast, and always return a "proceed" response immediately.
- Normalization of raw hook payloads into a stable internal event shape (reuse/adapt prior adapter work).
- Lightweight classification / tagging of events (sensitive paths, known exfil patterns in shell, MCP tool usage, etc.) without heavy policy evaluation.

**FR-2 Network Observation (macOS)**
- Must ship semantic hooks plus unprivileged userland process/network correlation as the default path.
- Must only observe external flows from known or likely AI coding-agent process trees in the default path.
- Must surface that the default polling observer can miss connect/send/exit flows that complete between snapshots; the correlation window does not compensate for unobserved flows.
- May provide an opt-in Network Extension for stronger process attribution.
- If enabled, the Network Extension must use `NEFilterDataProvider` only, be metadata-only, fail open, and never proxy, forward, block, or rewrite user traffic.
- Must handle (or at least not break) long-lived connections.

**FR-3 Correlation Engine**
- Must join semantic events and network flows using a combination of:
  - Timestamp proximity (configurable small window).
  - Process ID / process group / ancestry matching.
  - Semantic hints from the tool event (e.g., a "Bash" or "WebFetch" tool that names a host should boost matching flows).
- Must produce "linked" or "related" annotations for the UI.
- Must apply simple interestingness scoring so the UI can highlight the important stuff without flooding the user.

**FR-4 UI / Activation Model**
- Must be a Tauri (or equivalent native) menu-bar / tray application.
- Must remain minimal when no AI coding agent is active.
- Must surface a small, dismissible or collapsible panel (ideally appearing to "drop from the top" or as a standard popover) when relevant activity occurs or on user request.
- The panel must show an attention-first default view plus chronological or grouped feeds for linked/raw events. Lower-signal linked cards should be compact by default, repeated lower-signal patterns should group in the linked feed, and known low-risk service categories should collapse by default.
- Linked cards must show destination category, risk, decision, and correlation as separate concepts.
- Expanding a linked card with `Explain` must provide a replay-style explanation of tool call, target, process, network flow, correlation reasons, and decision without dumping raw process-tree details by default.
- Must support basic actions: copy event, view raw, expand known-service groups, export session, quiet known service categories globally, quiet a specific category, and quiet a linked pattern for the current project.

**FR-5 Local Data & Privacy**
- Runtime evidence is ephemeral or session-scoped by default. The exception is local quiet preferences, which may persist per project or globally for known-service categories.
- No automatic outbound network from the AgentSnitch components themselves.
- Clear documentation of exactly what data leaves the machine (only what the user explicitly exports).

**FR-6 Installation & Operability**
- Simple, documented install path (script or binary).
- Clear "doctor" / status surface that tells the user what is installed, what agents are being sensed, which network observer is active, and whether the optional Network Extension is active.
- Uninstallation must cleanly remove hook registrations and the System Extension.

---

## 8. Non-Functional Requirements

- **Performance:** Negligible impact on agent responsiveness or developer machine when idle. Correlation and UI updates must feel near-instant.
- **Reliability:** If the optional Network Extension or daemon crashes, the agent must continue to function normally (hooks should be best-effort sensors).
- **Security of the tool itself:** The emitter and daemon must not introduce new high-privilege attack surface. The Network Extension is opt-in, least-privilege, metadata-only, and guarded by static checks against remote egress/proxy APIs.
- **Maintainability:** The hook sensor layer must be cheap to extend to new agents or new hook events as vendors evolve.
- **Transparency:** Every interesting decision the correlator makes should be explainable from the events it saw (good "why was this highlighted?" path).
- **Secret hygiene:** Code, fixtures, docs, and release packaging must avoid realistic credential values. Examples should use inert placeholders and `example.invalid` destinations.

---

## 9. Phasing & Roadmap (High Level)

**Phase 0 / Spike (complete)**
- Hook emitter for Claude Code Pre/Post ToolUse + a few lifecycle events.
- Local unix socket emission into the daemon receiver.
- Basic process detection.
- Skeleton Tauri tray app that can wake on receiving an event.

**Phase 1 — MVP (local visibility core complete)**
- Full sensor registration + install story for Claude Code (others documented).
- Working macOS Network Extension with attribution.
- Correlation heuristics + interestingness.
- Functional minimal popup UI showing linked events.
- Session export.
- Documentation + real-data verification that produces visible linked evidence when Claude Code activity creates it.

**Phase 2 — Polish & Breadth**
- Better child-process tracking and attribution.
- Support for 2–3 more agents.
- Smoother UI (animations, better grouping, search within session).
- "Quiet list" per-session and persisted per-project.
- Improved interestingness (volume, destination reputation signals if local, repeat offenders in session).
- Packaging / distribution story (installer, uninstall flow, and smoother System Extension onboarding).

**Phase 3+ (Post-MVP, only after Phase 1 proves value)**
- Optional light enforcement controls (e.g., "block this host for agents going forward" via the same extension).
- Integration points for heavier containment layers.
- Linux eBPF path.
- Richer evidence packs and sharing formats.
- Optional (opt-in) anonymous telemetry of "interesting event" shapes to help the ecosystem understand real risk (with full local review first).

---

## 10. Open Questions & Risks

- How robust can process attribution be across shells, interpreters, MCP servers, and sub-agents? (This is the hardest technical risk.)
- Will the one-time System Extension approval friction be acceptable once users see value? (We believe a compelling first correlated event makes it worth it.)
- How do we detect "agent is active" reliably without false positives from other processes that happen to have similar names?
- Long-lived connections established before taint: if a clean tunnel is open and then a secret is read, we need a way to surface that the existing connection could now carry exfil (re-validation or teardown signals).
- Semantic transformation: an agent that reads a secret and then later describes it in prose over a "normal" API call may not produce an obvious mechanical link. We will surface the temporal + sensitive-read + external-egress pattern and let the human connect the dots.
- Vendor hook surface changes: by treating hooks as best-effort sensors rather than the enforcement root, we reduce (but do not eliminate) the maintenance burden.

---

## 11. Success Criteria for "Phase 1 Done"

- A developer can follow a short README, install on a clean macOS machine, start Claude Code, cause a sensitive read + external network action (deliberately or naturally), and see a clear correlated entry in the popup within seconds.
- The same developer describes the experience as "eye-opening" or "I finally understand the risk" rather than "this is annoying."
- The code and docs are clear enough that another contributor could extend the emitter to a second agent without heroic effort.
- `doctor` can prove hooks, daemon, UI, Network Extension observer, and linked evidence status without relying on fabricated runtime events.

---

*This PRD is a living document. It will be updated as we learn from real usage.*
