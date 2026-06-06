# AgentSnitch UI/UX Plan — "Make it instantly obvious"

**Date:** 2026-06-05
**Goal:** Make it instantly obvious what AI coding agents are doing at runtime and on the network, and showcase the subagent visibility AgentSnitch uniquely has.
**Audience:** developers, AI engineers, security teams.

---

## How this was evaluated

Every tab was driven in the **live running app** (macOS Tauri window) via screen capture and synthetic clicks. Critically, the two headline features were initially **showing zero data** ("Agents" = 3 undifferentiated "Main", "Linked" = 0). To evaluate the populated states honestly, a subagent was spawned that read a config file + ran `curl` to GitHub — which **successfully populated** the subagent hierarchy and 5 linked-evidence cards. So detection works; the design problem is what happens before/around that.

| View | Status | Notes |
|---|---|---|
| Attention | observed live (empty + active) | reason filter chips, summary pills |
| Linked | observed live (count 0 → 5) | card *detail* layout read in source |
| Agents | observed live, **populated** | subagent hierarchy + named child confirmed |
| Hooks | observed live, populated | agent panel + chronological feed |
| Network | observed live, populated | feed + Raw expander |
| All | observed live | |
| Agent drill-down | observed live | side-by-side hierarchy + detail w/ filter chips |
| Explain / provenance expander | **observed live** | confirmed in Linked tab + Agents subagent-detail; same `toggleDetails` renderer is used in Attention too. Full forensic replay (see below) |
| Raw / Raw Why expanders | observed live | `toggleRawDetails` / `toggleWhy` key-value + reason detail |

---

## The single biggest problem: the empty/idle state *is* the first impression

When an agent is active but nothing has correlated yet, the app shows **0 Linked, 0 subagents** with passive messaging: *"Hooks and network are live; no tool/network pair has linked yet"* and *"correlation waiting."* For a tool whose pitch is "instantly obvious," the default state reads as "nothing is happening" even while the agent is busy. The product only becomes impressive *after* a correlation fires — which may be minutes in, or never in a read-only session.

**This is the #1 thing to fix.** Everything below serves making the live, pre-correlation state legible and confidence-inspiring.

---

## Findings & recommendations, by priority

### P0 — Make the active session legible before correlation happens

1. ✅ **Shipped (`track-b-ui`).** **Lead with a live "what the agent is doing right now" strip.** Always-visible **activity ticker**: last N tool calls as human sentences with live counts, surfacing hooks as the heartbeat. *(`#activityTicker` strip above the tabs, rendered at the top of `renderEvents()` so it survives every tab + empty paths.)*

2. ✅ **Shipped.** **Reframe "waiting" as "watching."** Confident present-tense status instead of "waiting/correlation waiting."

3. ✅ **Shipped.** **A persistent one-line verdict banner** (green/amber/red), `compute_verdict`. Verified live (red banner on a real sensitive-read→egress).

### P0 — Subagent visibility (the differentiator) — make it the star

4. ✅ **Shipped (`agent-grouping`).** **Agent identity by project/cwd label, not PID** (`agentProjectName`/`agentShortName`).

5. ✅ **Shipped (T1–T3).** **Subagent tree visual hierarchy** — indentation, rail/elbow, loud active selection.

6. ✅ **Shipped (`track-b-ui`).** **Whole-card click affordance.** The entire `.agent-tree-group` card inspects the main (`role=button`, hover + keyboard activation), guarded so inner buttons don't double-fire. *(Codex-reviewed: added Enter/Space keyboard activation.)*

7. ✅ **Shipped (`track-b-ui`).** **Subagent drill-down leads with a story summary.** `renderAgentDetailView` opens with a synthesized one-liner ("Spawned 8s ago by agentsnitch(69566) · read 1 file · 1 outbound flow to api.github.com · no sensitive context") above the chips + feed.

### Subagent view — tuning notes (observed fully populated, live)

This is the strongest view in the app and a stated favorite. It was driven live with **multiple real subagents** spawned in the `sir`/`agentsnitch` projects, captured in three states:

- `docs/ui-screenshots/agents-subagent-tree.png` — Main (3) with three named subagent children ("Research competitor/landscape features", "Research feature gaps from codebase", "Research UX and operator features"), live event counts, second Main below.
- `docs/ui-screenshots/subagent-detail-hooks.png` — a subagent's detail panel with All/Attention/Linked/Hooks/Network chips over a `SubagentToolUse` feed (read-heavy phase: Hooks only).
- `docs/ui-screenshots/subagent-detail-linked-evidence.png` — the same subagent once it did network work: **Attention 59 · Linked 59 · Network 59**, full linked-evidence cards ("Sensitive read → outbound connection", DESTINATION/HOOK EVIDENCE/NETWORK EVIDENCE/WHY THIS MATTERS rows, Explain / Raw Why / Quiet pattern actions).

**Confirmed working end-to-end:** Main → named subagents nested underneath → click a subagent → its own All/Attention/Linked/Hooks/Network filters → expanded linked-evidence cards scoped to that subagent. Detection and attribution are solid; the work is tuning.

Specific tuning items for this view:

T1. **Tree affordance is too flat.** Subagent rows sit nearly co-equal with their Main. Add real parent→child structure: indentation + a connecting line/rail, a distinct subagent accent color, and the active-selection state much louder than the current subtle purple left-border.

T2. **Live counts reflow the panel.** Counts tick as subagents work (great signal) but the layout reflows/resizes with them. Debounce layout; animate count changes in place instead of reflowing the tree and detail panel.

T3. **Subagent names truncate awkwardly.** Long task descriptions ("Research competitor/landscape features…") are the titles. Use the cleaned short name as the title with the full prompt on hover/expand; keep names single-line with a consistent truncation.

T4. ✅ **Shipped.** **Evidence cards are dense and partly redundant.** DESTINATION / DISPLAY NAME / OBSERVED ENDPOINT are often the same value (`168.79.104.10:443`). Collapse near-duplicate rows; lead with the human one-liner ("Subagent read sensitive context, then connected to <dest>"), put the raw endpoint/SNI/category behind Raw. *(Compact body shows destination + provenance only; the human one-liner is now the card **headline** — see T6 — shown once, not duplicated in the body; raw endpoint/SNI/tags behind Provenance details.)*

T5. ✅ **Shipped (`evidence-card-ia`).** **Risk color vs category chip can contradict.** A card shows red **"Needs Review"** + **"Sensitive read → outbound connection"** while the destination category is **"known Claude service"**. A known-safe destination after a sensitive read should not read as full red alarm. Reconcile the risk scale with the destination category so color always tracks true urgency (ties to #16, color semantics). *(Fix: `evidence_risk` now reconciles known-safe destinations BEFORE the `after_sensitive_read` escalation, so ordinary traffic to Claude's API / registry / telemetry reads low. Sensitive reads to **unknown** destinations still escalate to high — the timing/exfil case `compute_verdict` surfaces as amber and `linked_event_breaks_quiet` relies on. Pinned by `evidence_risk_reconciles_sensitive_read_with_destination_category`.)*

T6. ✅ **Shipped (headline upgrade `evidence-polish`).** **"WHY THIS MATTERS" is the best part — promote it.** The plain-English reason string is exactly the explainability the product promises. Make it the headline of each linked card, not a row near the bottom; keep Raw Why for the machine reasons. *(`why_human` is now the dominant **headline** line of the card; the generic pattern title ("Sensitive read → outbound connection") is demoted to a small uppercase eyebrow above it. Raw Why toggle sits inline on the headline. The duplicate body why-row was removed — single source.)*

T7. ✅ **Shipped.** **Parent attribution clarity.** The subagent detail subtitle reads "parent Main PID 780" while the tree groups it under a Main shown with a different PID — reads as inconsistent. Show the parent as the same human label used in the tree, not a raw PID. *(`parentLabel` uses `agentShortName`.)*

**Explain / provenance expander (observed live — `docs/ui-screenshots/explain-provenance-expanded.png`).** Confirmed working: the **Explain** button on any evidence card toggles a full forensic-replay block (button label flips to "Hide provenance details"). It works identically in the **Agents** subagent-detail, **Linked**, and **Attention** views. The expanded block shows: HOOK EVENT / HOOK PID / WORKING DIRECTORY / HOOK TAGS / INPUT SUMMARY, TIMING ("network flow active 817ms before hook"), PROCESS LINK ("hook PID 4282 (parent 780) → network PID 780 (parent 471)"), DESTINATION / REMOTE ENDPOINT / NETWORK PID / PROCESS / OBSERVER / FLOW STATE / PROTOCOL / BYTES, RAW REASONS, the full PROCESS TREE ancestry, CORRELATION score + reason pills, RAW WHY, and RISK. This is the deepest dig-in surface and the clearest proof of the product's explainability promise.

Tuning for Explain:
- T8. ✅ **Shipped.** **It's a wall of monospace key/value rows.** Two-tier it: a human summary line up top (the WHY string from T6), then "Show provenance details" reveals the full block. Group human-meaningful fields above machine fields. *(Explain → full body with human why; a separate "Provenance details" toggle reveals raw rows + process tree + diagnostic tags.)*
- T9. ✅ **Shipped (`evidence-card-ia`).** **PROCESS TREE is the most unique artifact and the least readable** (one long wrapped line of `pid ← ppid` hops). Render it as an actual indented tree with roles (hook / network / ancestor) labeled, mirroring the agent hierarchy styling so the two views feel related. *(Renders `evidence.process_tree` nested by ppid, root→leaf, with humanized role chips and the agent-tree rail/elbow styling; flat string dropped. In the Provenance details tier per T8.)*

**Verification screenshots (T5/T9/#16/T4/T6/F1):**
- `docs/ui-screenshots/16-unified-risk-scale.png` — three cards demonstrating the unified scale: red chip+border (risk high), **amber chip+border (risk medium / severity low — the divergence case)**, green chip+border (known-safe low). Chip color tracks the border at every tier; each card leads with its human one-liner headline.
- `docs/ui-screenshots/t9-process-tree.png` — an expanded card with the indented process tree (`pid 471 launchd [ANCESTOR]` → `pid 780 claude [ANCESTOR]` → `pid 4282 Read [HOOK] [NETWORK]`) inside the two-tier Provenance details (T8).
- `docs/ui-screenshots/live-app-default.png` — the **live native Tauri app** (built/notarized/installed from merged main): amber verdict banner, watching-not-waiting copy, live network flows.
- `docs/ui-screenshots/live-app-after-trigger.jpg` — the live app after a real hooked agent read `.env` then made an outbound connection: **red verdict banner** ("Sensitive context, then outbound connection…"), 69 linked cards, the Main→subagent tree (events correctly attributed to the `claude` sub-agent PID 64289), and an evidence card leading with the human "Matched because…" headline (T4/T6) under a risk-colored chip (#16 — green here, since the destination is a known Claude service, while the workflow status still reads "Needs Review": color = risk, text = workflow). (The native window's Spaces-wall instability prevented a clean *expanded*-card capture; T9's live render is corroborated by the daemon emitting a real 9-node `process_tree` and the harness render above.)

### P1 — Fix confusing cross-cutting behaviors

8. ✅ **Shipped (`#11` filter-persistence fix).** **Agent filter persistence across tabs** — `setView` clears the filter on tab switch + a loud amber active-filter indicator.

9. ✅ **Shipped (`track-a-rust`).** **The window repositions/resizes itself.** Root-caused to `resize_main_window` pushing size with no position control. Pure tested `solve_window_geometry` pins width, clamps position into the *current* monitor (preserves a deliberate 2nd-display placement), and preserves minimum height by sliding the top edge up. *(Codex-reviewed: fixed a height-collapse case for a window placed low on a small display.)* macOS Spaces-follow (raw NSWindow `collectionBehavior`) noted out of scope.

10. ✅ **Shipped (`track-a-rust`).** **Counts that change under you** — width pinned so live count changes no longer jitter the panel width.

### P1 — Tab structure & information scent

11. ✅ **Shipped (full restructure).** **Six tabs → five-tab Overview/Agents/Evidence/Raw/Flow-Trace restructure.** The old Attention + Linked tabs merge into **Evidence** (the deduped union of correlated + attention-worthy events, sorted risk-tier-descending then recency — an event that is both correlated AND attention-worthy appears exactly once); the old Hooks + Network + All tabs merge into **Raw** (the unfiltered firehose with an {All / Hooks / Network} sub-toggle reusing the Flow-Trace mode-toggle pattern). Architecture is **compose-don't-rename**: `filterEventsByKind`'s five internal kinds are untouched; `'evidence'`/`'raw'` are new composite `activeView` values resolved in one central `resolveViewEvents` so the feed, autosize, counts, and the agent-detail drill-down can't drift. The attention-reason chips move under Evidence (clicking one keeps you on Evidence and narrows the **whole** union by reason, so the rendered count matches the chip badge). The agent-detail drill-down chips mirror the new nav: **All / Evidence / Raw**. Verified live against an adversarial fixture (dedup headline = exactly one card; hot→medium→low ordering read off the DOM; reason-chip count parity; Raw sub-toggle changes list + badge; all five tabs cycle without blanks).

12. ✅ **Shipped (T4/T6 + `track-b-ui`).** **"Linked/Evidence" as the hero** — each card leads with the human one-liner headline; empty states now teach (see #15).

### P2 — Polish & affordances

13. ✅ **Shipped (`track-b-ui`).** **Raw→Details + grouping** — flow expander relabeled "Details"; human fields (destination, process, category) grouped above a "Diagnostics" subheading.
14. ✅ **Shipped (`track-b-ui`).** **Consistent button language** — collapsed to **Inspect / Explain / Details / Quiet / Clear**. Disclosure toggles keep a single static label (hints in tooltips). Documented exceptions: the `Raw Why ↔ Human` representation toggle, filter-dismiss/Back/Pause controls.
15. ✅ **Shipped (`track-b-ui`).** **Teaching empty-tab copy** — generic empties replaced with copy that teaches what would appear and why, per tab/lane.
16. ✅ **Shipped (`evidence-polish`).** **Color semantics.** Establish one risk scale (green/amber/red) used identically everywhere — summary pills, category chips, the verdict banner, card borders — so color always means risk, never decoration. *(The review-status chip's color is now driven by the card's risk tier (red/amber/green) so it can never contradict the card border, which uses the same scale; the chip text still carries the workflow status independently. The "low" card border moved from the purple accent to green to complete the scale. Deliberate exception: the destination **category pill stays neutral** — it names an identity (the category), not a risk level, so tinting it by risk would mislead.)*

### Known follow-ups

- ~~**F1. Verdict banner text can misstate linkage.**~~ ✅ **Fixed (`evidence-polish`).** `compute_verdict`'s amber `high_signal` path hardcoded `"...not linked to sensitive reads."` even when the surfaced card carried `after_sensitive_read` (the pre-existing-connection case). Now the message branches on whether the card is linked: when it carries `after_sensitive_read`/`credential_context` it says "after a sensitive read … connection predates the read"; otherwise it keeps the accurate "not linked" phrasing. Pinned both ways so the phrase is removed only where it would be false.
- **F2. Destination-category downgrade taxonomy.** The T5 reconciliation only carves out the four *known-safe* categories (Claude service / Playwright bridge / telemetry / package registry) from full-red. Whether any *other* category (e.g. local dev tunnel, cloud provider) should also downgrade a sensitive-read escalation is an open taxonomy question, not yet decided.

---

## New feature: Pause / Live toggle (true daemon halt)

**Goal:** a Wireshark/Charles-style toggle. When **Pause** is active, AgentSnitch stops receiving live data so you can study the dataset in place without constant refreshing. **Live** re-enabled → live data resumes.

**Decided behavior (team decision, confirmed twice with the tradeoff shown): true daemon halt.** Pause stops the daemon from sensing — not just a UI view-freeze.

| Layer | While Paused |
|---|---|
| UI render | frozen (no live updates) |
| UI ingestion (`ui.sock`) | nothing arrives |
| Daemon sensing (nettop/lsof/NE/process snapshots/correlation) | **stopped** |
| Transcript recording | **nothing written** |
| Agent traffic | **never touched** (Pause is not a network block; sensors-not-gates still holds) |

**⚠ Accepted tradeoff — evidence gap (intentional, documented):** anything an agent does while paused is *not recorded*. In the product's own "surprise egress" scenario, pausing to inspect one flow means a second flow firing during the pause leaves no evidence. The user chose this explicitly with the gap shown. This is a deliberate decision, not an oversight.

**Required mitigations (so the gap is honest, never silent):**
1. **Loud paused state.** Unmistakable banner + tray icon change: "⏸ Paused — sensing halted. Agent activity during pause is NOT being recorded." Not a subtle toggle.
2. **Gap marker in the transcript.** On resume, write an explicit `pause_gap` record (`{from, to, duration}`) into the session transcript so exports show *"sensing was halted HH:MM:SS–HH:MM:SS"* rather than an invisible hole. The gap is recorded *as a gap*.
3. **Pause is distinct from Quiet and Clear** — spell out all three so they're never conflated:
   - **Pause/Live** = stop/start sensing (new).
   - **Quiet** = keep sensing, suppress known-low-risk noise (existing `quiet_session`).
   - **Clear** = wipe the current session view (existing `clear_session`).

**Implementation sketch:**
- New Tauri command `set_paused(bool)` + a `paused` flag in `AppState`; emits `pause-changed`.
- The daemon needs a control path to halt/resume observers. Cleanest: the UI signals the daemon over the existing socket (a control message), and the daemon's observer goroutines check a paused flag and stop polling / stop reading nettop/lsof, stop the process-graph ticker, and skip correlation + transcript append. On resume, restart observers and write the `pause_gap` marker.
- Fail-safe defaults: if the app crashes or the daemon restarts while paused, it must come back **Live** (never silently stay halted) — a stuck-paused security tool is worse than a noisy one.

**Performance note (separate feature, do not merge):** at 100 subagents, nettop + 2s process snapshots may thrash. That argues for a *throttle/sampling* control, which is a different feature from pause-to-inspect. Keep them separate.

---

## New feature: Live flow-trace view (Sankey) — ✅ SHIPPED (`track-c-sankey`, PR #19)

**Shipped as a 7th "Flow Trace" tab** (the 6 existing tabs untouched; #11 restructure stays deferred). d3-sankey vendored INLINE as `ui/dist/d3-sankey.js` (14.7 KB, layout math only, ISC license preserved — no CDN, no build step; the accepted architecture.md §3.4 deviation). `buildTraceGraph()` derives the Agent→Subagent→Tool/Hook→Destination graph live from `events`; known-safe categories collapse into grey aggregate sinks, and uncollapsed destinations are colored by the #16 risk tier so the **one anomaly pops hot** in a field of grey/neutral. Three view toggles: **Sankey / Node-link / List**, sharing one selection + the existing provenance (click a node/ribbon → the same evidence-card provenance, no new surface). Verified with the adversarial 100-known-safe + 1-anomaly scenario for BOTH correlated and **raw uncorrelated** network flows (Codex-reviewed: raw-flow tier now reuses `attentionReasons`, and the raw-network hop is labeled "Network", not the destination host). The detail below is the original spec.


**Goal:** a beautiful live view that maps, in one glance, **hook/tool call → trace → PID (main or named subagent) → destination**, so you can *zoom out* over many agents and have anomalies pop. The driving scenario: 100 subagents running; normal calls to GitHub (your repos) and Anthropic (expected); then **one agent makes an egress to an unexpected IP in CN/RU** — it should jump out immediately, and clicking any part of the trace shows the provenance for *that* part.

**The real requirement (not "Sankey" literally — user said "or maybe multiple views"):** zoom-out + anomaly-pops-hot + click-any-node/edge-for-provenance. Sankey is the primary renderer; a grouped node-link / force view may be offered as an alternate that surfaces a single outlier even better than a thin Sankey ribbon.

**Renderer decision (team decision): d3 + d3-sankey approved.** This is an explicit, accepted deviation from architecture.md §3.4 ("extremely restrained, no heavy frameworks") — the first real frontend dependency. Worth recording in the architecture doc as a conscious exception.

**Design:**
- **Columns (left→right):** Agent (Main, grouped by project) → Subagent (named) → Tool/Hook (Read/Bash/WebFetch/MCP…) → Destination (host/SNI, grouped by `destination_category`). Ribbon width = flow volume or event count.
- **Anomaly-pops via the existing category model — this IS the zoom-out mechanism.** Known-safe categories (known Claude service, package registry, telemetry, Playwright bridge, local dev) **collapse into desaturated grey aggregate sinks**. Unknown-external / new-destination / sensitive-linked / high-byte break out in **hot color** (the one red ribbon in a sea of grey = the user's exact scenario). The correlator already emits `destination_category` and risk, and the UI already collapses known categories — reuse both.
- **Click-through reuses existing provenance.** Clicking a node or ribbon opens the **same `toggleDetails` provenance block** already confirmed live (hook event, timing, process link, endpoint, bytes, raw reasons, process tree, why, risk) — scoped to that node/edge. Do **not** build a new detail surface.
- **Multiple views toggle:** Sankey (flow proportion) ↔ node-link/force (single-outlier emphasis) ↔ the existing list. Same underlying selection + provenance.

**Blocking constraint — must fix first:** `MAX_UI_EVENTS = 160` (lib.rs:31). A 100-subagent live trace needs far more than 160 retained events to be meaningful. The ring-buffer cap and the linked-evidence-favoring retention need rework (larger cap, or a separate aggregated trace model that summarizes flows rather than holding every raw event) **before** the live view is worth building. This gates the feature.

**Suggested order for this feature:** (1) raise/rework the event-retention model; (2) build an aggregated trace data model (nodes = agents/subagents/tools/destinations, edges = flows, with category+risk); (3) Sankey render with grey-collapse + hot-breakout; (4) wire node/edge click → existing provenance; (5) add the alternate node-link view.

---

## Suggested sequencing

1. **Verdict banner + reframed status copy** (P0 #2, #3) — cheap, huge first-impression win.
2. **Agent identity: cwd/label over PID** (P0 #4) + **filter-persistence fix** (P1 #8) — removes the two most confusing things.
3. **Subagent tree visual hierarchy + full-card click + story drill-down** (P0 #5–7) — the differentiator.
4. **Live activity ticker / Overview tab** (P0 #1, P1 #11) — the structural change.
5. **Evidence card storytelling** (P1 #12) + **Raw/label cleanup** (P2 #13–15).
6. **Window-position/jitter fixes** (P1 #9, #10).
7. **Pause / Live toggle** — self-contained, high user value; daemon halt + transcript gap-marker + loud paused state.
8. **Event-retention rework** (gates the live view) → **Live flow-trace (Sankey)** — the biggest build; do retention first, then the d3-sankey view reusing category-collapse + existing provenance.

---

## Resolved decision — Agent grouping (was "open question")

**Context:** the active session rendered **3 separate "Main"** agents (PIDs 69566 = this agentsnitch session, 85582 = the "sir" project, 65617 = exited), presented as a flat peer list distinguished only by PID — *arguably correct* (three independent `claude` invocations across two projects) but confusing rather than informative.

**Decision: Project-labeled, flat — with a project header only when there's more than one project.** Not "always group by project."

### Why this option

1. **The data already exists; this is a render-layer fix, not new plumbing.** `AgentInfo.Cwd` flows end-to-end (Go struct → JSON → UI) and daemon sessions are *already* keyed by cwd (`derivedSessionID = sha1(cwd + ppid)` in `cmd/emitter/main.go`). The daemon's model is already "one session = one project working directory." The header already derives *"active in sir"* from cwd. The only bug is that `agentShortName()` (index.html ~1849) hardcodes every main to the literal string `'Main'`, discarding the project it already has.
2. **Don't pay the nesting tax in the common case.** The common case is one project / one main / maybe a few subagents. "Always group by project" wraps a project section + collapse chrome around a single item every time — adding friction to the 90% case to fix the 10% case. Information scent should scale with actual complexity.
3. **Directly serves "instantly obvious."** "agentsnitch — main" vs "sir — main" is self-explanatory; "Main · PID 69566" is not. The folder name is the identity a developer thinks in.

### Spec

- **Identity:** primary label = **project basename** (last path segment of cwd) + role, e.g. `agentsnitch — main`. PID demoted to the secondary meta line (diagnostic, not identity). Full cwd on hover/title.
- **Grouping/header:** when `distinct project count > 1`, show a lightweight per-project section label and a header count: *"Claude Code agents · 2 projects · 3 main"*. When 1 project, **no** group header — just labeled cards.
- **Sorting:** mains by project name, then activity (event count desc).
- **Subagents:** unchanged structurally — nest under their project's main (the `└` child confirmed live); inherit the parent's project, no extra labeling.
- **Header coupling:** the top header's *"active in sir"* is wrong when multiple projects are active — pluralize to *"active in 2 projects"* (or the most-recently-active project) so header and list agree.
- **Button:** collapse `Events`/`View` → a single **Inspect** (ties to #11/#14).

### Edge cases

- **Exited main (e.g. PID 65617, cwd unknown):** render `(ended) main`, muted, sorted last. Keep it (history may matter) but de-emphasize.
- **cwd missing/unresolved:** fall back to truncated `~/…` path, else `unknown project` — never blank.
- **Two mains, same project** (e.g. two `claude` tabs in one repo): label both with the project, disambiguate by PID in the meta line — this is where PID earns its place.

### Target rendering

```
Claude Code agents · 2 projects · 3 main

  agentsnitch — main        PID 69566 · 154 ev  [Inspect]
    └ Trigger subagent…     PID 96492 · 6 ev
  sir — main                PID 85582 · 12 ev   [Inspect]
  (ended) main              PID 65617 · 0 ev
```

### Implementation footprint (small)

- `agentShortName(agent)` (index.html ~1849): for mains, return a project-derived label instead of literal `'Main'`. Add `agentProjectName(agent)` deriving the basename from `agent.cwd`.
- `renderAgentHierarchy` / `agentGroups` (~2640 / ~2707): add the optional project section header gated on `distinctProjects > 1`; flat otherwise.
- Header label derivation: pluralize when multiple active projects.
- **Daemon (do this first):** ensure `agent.cwd` is reliably set on *every* main lifecycle/annotation, including network-attributed ones — `annotateNetwork` currently calls `registerMainLocked(pid, "", now)` with an empty cwd, so a network-only-attributed main can render "unknown project". Small fix so the label never falls back.

**Suggested order:** daemon cwd-on-main fix → `agentShortName` + grouping render changes → verify live by re-driving the app.
