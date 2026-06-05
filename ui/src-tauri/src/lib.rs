// AgentSnitch Tauri UI (tray + primary evidence window + live event display)
// Implements the MVP described in architecture.md §3.4 and prd.md "oh shit" flows.
// - Proper tray with menu + icon state change (active vs quiet)
// - Normal movable macOS window with tray affordances
// - Receives validated daemon-forwarded events via ~/.agentsnitch/ui.sock
// - Shared state + Tauri commands + live emit to frontend
// - Self-contained frontend in ui/dist/index.html (vanilla + inline mac-like CSS)
// - Activation: PreToolUse / claude-like => active tray + auto open panel
// Minimal new crates: only added "image-png" to tauri features.

use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tauri::{
    image::Image,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu},
    tray::{MouseButton, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, LogicalSize, Manager, RunEvent, Size, State,
};

const MAX_UI_EVENTS: usize = 160;
// Upper bound on a single UI-socket connection read. The daemon caps every
// upstream payload (NE/XPC at 32 KiB); this keeps the UI's one ingestion point
// symmetric so a misbehaving local daemon cannot drive unbounded allocation.
const MAX_UI_STREAM_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_SESSION_IDLE_SECS: u64 = 90;
const AGENT_PROCESS_CHECK_INTERVAL: Duration = Duration::from_secs(10);
const HEURISTICS_JSON: &str = include_str!("../../../config/heuristics.json");

/// Matches internal/event/event.go SemanticEvent JSON shape exactly (for compatibility with parallel Go work).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticEvent {
    pub schema: String,
    pub ts: String,
    pub agent: AgentInfo,
    pub session: SessionInfo,
    pub event: String,
    pub tool: String,
    pub target: Option<String>,
    pub cwd: Option<String>,
    pub pid: i32,
    pub ppid: Option<i32>,
    pub tags: Option<Vec<String>>,
    #[serde(rename = "destination_intents")]
    pub destination_intents: Option<Vec<String>>,
    #[serde(rename = "tool_use_id")]
    pub tool_use_id: Option<String>,
    #[serde(rename = "input_summary")]
    pub input_summary: Option<serde_json::Value>,
    #[serde(rename = "output_summary")]
    pub output_summary: Option<serde_json::Value>,
    #[serde(rename = "raw_ref")]
    pub raw_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFlowEvent {
    pub schema: String,
    pub ts: String,
    pub agent: Option<AgentInfo>,
    #[serde(rename = "flow_id")]
    pub flow_id: Option<String>,
    pub observer: Option<String>,
    pub pid: Option<i32>,
    pub ppid: Option<i32>,
    #[serde(rename = "process_path")]
    pub process_path: Option<String>,
    #[serde(rename = "process_bundle_id")]
    pub process_bundle_id: Option<String>,
    #[serde(rename = "process_team_id")]
    pub process_team_id: Option<String>,
    #[serde(rename = "signing_info")]
    pub signing_info: Option<serde_json::Value>,
    pub local: Option<String>,
    pub remote: Option<String>,
    pub sni: Option<String>,
    pub protocol: Option<String>,
    pub direction: Option<String>,
    #[serde(rename = "bytes_out")]
    pub bytes_out: Option<i64>,
    #[serde(rename = "bytes_in")]
    pub bytes_in: Option<i64>,
    pub state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedEvent {
    pub schema: Option<String>,
    pub ts: String,
    pub agent: Option<AgentInfo>,
    pub score: f64,
    pub confidence: Option<String>,
    pub reasons: Option<Vec<String>>,
    pub summary: Option<String>,
    pub semantics: Option<Vec<SemanticEvent>>,
    pub flows: Option<Vec<NetworkFlowEvent>>,
    #[serde(rename = "process_tree")]
    pub process_tree: Option<Vec<ProcessNode>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: i32,
    pub ppid: Option<i32>,
    pub name: Option<String>,
    pub source: Option<String>,
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentInfo {
    pub id: String,
    #[serde(rename = "type")]
    pub agent_type: Option<String>,
    pub name: String,
    pub pid: Option<i32>,
    #[serde(rename = "parent_agent_id")]
    pub parent_agent_id: Option<String>,
    #[serde(rename = "spawn_method")]
    pub spawn_method: Option<String>,
    #[serde(rename = "first_seen")]
    pub first_seen: Option<String>,
    #[serde(rename = "last_seen")]
    pub last_seen: Option<String>,
    pub cwd: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLifecycleEvent {
    pub schema: String,
    pub ts: String,
    pub event: String,
    pub agent: AgentInfo,
}

#[derive(Debug, Deserialize)]
struct SchemaProbe {
    schema: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionInfo {
    pub id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct HeuristicsConfig {
    schema: String,
    destination_categories: Vec<DestinationCategoryConfig>,
    quiet_categories: Vec<String>,
    noisy_automation: Vec<NoisyAutomationConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct DestinationCategoryConfig {
    name: String,
    domains: Vec<String>,
    #[serde(default)]
    cidrs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct NoisyAutomationConfig {
    family: String,
    contains: Vec<String>,
    #[serde(default)]
    requires_localhost: bool,
}

fn heuristics_config() -> &'static HeuristicsConfig {
    static CONFIG: OnceLock<HeuristicsConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let cfg: HeuristicsConfig =
            serde_json::from_str(HEURISTICS_JSON).expect("valid embedded heuristics config");
        assert_eq!(cfg.schema, "agentsnitch.heuristics.v0");
        cfg
    })
}

/// UI-facing event record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiEvent {
    pub id: u64,
    pub ts: String,
    pub summary: String,
    pub tags: Vec<String>,
    pub detail: Option<String>,
    pub destination: Option<String>,
    #[serde(rename = "destination_context")]
    pub destination_context: Option<DestinationContext>,
    pub correlated: bool,
    pub evidence: Option<LinkedEvidence>,
    pub agent: Option<AgentInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationContext {
    #[serde(rename = "project_key")]
    pub project_key: String,
    pub state: String,
    pub label: String,
    #[serde(rename = "previous_count")]
    pub previous_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedEvidence {
    pub title: String,
    pub semantic: String,
    pub flow: String,
    pub why: Vec<String>,
    #[serde(rename = "why_human")]
    pub why_human: String,
    pub destination: String,
    #[serde(rename = "destination_category")]
    pub destination_category: String,
    #[serde(rename = "destination_provenance")]
    pub destination_provenance: Vec<EvidenceDetail>,
    pub severity: String,
    pub risk: String,
    #[serde(rename = "review_status")]
    pub review_status: String,
    #[serde(rename = "review_subtitle")]
    pub review_subtitle: String,
    pub decision: String,
    pub details: Vec<EvidenceDetail>,
    pub replay: Vec<EvidenceDetail>,
    #[serde(rename = "process_tree")]
    pub process_tree: Vec<ProcessNode>,
    pub confidence: String,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceDetail {
    pub label: String,
    pub value: String,
}

/// Lightweight session info for the active-session header.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionSnapshot {
    pub id: String,
    pub agent_name: String,
    pub cwd: String,
    pub started_ts: String,
}

/// Tauri managed state.
#[derive(Default)]
struct AppState {
    events: Mutex<Vec<UiEvent>>,
    agents: Mutex<HashMap<String, AgentInfo>>,
    active: Mutex<bool>,
    session: Mutex<SessionSnapshot>,
    runtime: Mutex<SessionRuntime>,
    next_id: Mutex<u64>,
    quiet: Mutex<bool>,
    // paused: when true the user engaged Pause (Wireshark-style). The daemon halts
    // sensing; the UI freezes live updates. Never persisted — defaults to false
    // (Live) so a restart always comes back Live (fail-safe, see docs/ui-ux-plan.md).
    paused: Mutex<bool>,
    quieted_patterns: Mutex<HashSet<String>>,
    quiet_preferences: Mutex<QuietPreferences>,
    destination_memory: Mutex<DestinationMemory>,
    app_settings: Mutex<AppSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppSettings {
    schema: String,
    network_sensor_disabled: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            schema: "agentsnitch.ui_settings.v0".into(),
            network_sensor_disabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct AppSettingsUpdate {
    settings: AppSettings,
    detail: String,
    warning: Option<String>,
}

#[derive(Debug, Clone)]
struct SessionRuntime {
    last_agent_activity: Option<SystemTime>,
    last_process_check: Option<SystemTime>,
    agent_process_running: bool,
}

impl Default for SessionRuntime {
    fn default() -> Self {
        Self {
            last_agent_activity: None,
            last_process_check: None,
            agent_process_running: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub active: bool,
    pub header: String,
    pub event_count: usize,
    pub quiet: bool,
    pub paused: bool,
    pub summary: SessionSummary,
    pub agents: Vec<AgentInfo>,
    pub recent: Vec<UiEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionSummary {
    #[serde(rename = "known_claude_traffic")]
    pub known_claude_traffic: usize,
    #[serde(rename = "telemetry_traffic")]
    pub telemetry_traffic: usize,
    #[serde(rename = "local_bridge_traffic")]
    pub local_bridge_traffic: usize,
    #[serde(rename = "package_registry_traffic")]
    pub package_registry_traffic: usize,
    #[serde(rename = "new_destinations")]
    pub new_destinations: usize,
    #[serde(rename = "high_signal")]
    pub high_signal: usize,
    pub linked: usize,
    pub network: usize,
    #[serde(rename = "quieted_patterns")]
    pub quieted_patterns: usize,
    #[serde(rename = "new_destination_samples")]
    pub new_destination_samples: Vec<String>,
    #[serde(rename = "sensitive_context")]
    pub sensitive_context: usize,
    #[serde(rename = "agent_processes")]
    pub agent_processes: usize,
    #[serde(rename = "observer_coverage")]
    pub observer_coverage: usize,
    #[serde(rename = "project_new_destinations")]
    pub project_new_destinations: usize,
    #[serde(rename = "project_seen_destinations")]
    pub project_seen_destinations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct QuietPreferences {
    schema: String,
    global: HashSet<String>,
    projects: HashMap<String, HashSet<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DestinationMemory {
    schema: String,
    projects: HashMap<String, HashMap<String, usize>>,
}

impl Default for DestinationMemory {
    fn default() -> Self {
        Self {
            schema: "agentsnitch.destination_memory.v0".into(),
            projects: HashMap::new(),
        }
    }
}

fn compute_header(snap: &SessionSnapshot, active: bool, agents: &[AgentInfo]) -> String {
    compute_header_at(
        snap,
        active,
        Utc::now(),
        has_detected_subagents(agents),
        distinct_agent_projects(agents),
    )
}

/// Number of distinct projects across main agents. Identity is the full
/// normalized cwd (trailing slashes trimmed), not the basename, so two mains in
/// different paths that share a folder name (e.g. /tmp/a/app and /tmp/b/app)
/// count as two projects. Used to pluralize the header when >1 project is active.
fn distinct_agent_projects(agents: &[AgentInfo]) -> usize {
    let mut seen = HashSet::new();
    for agent in agents {
        if agent.agent_type.as_deref() == Some("sub") {
            continue;
        }
        if let Some(cwd) = agent.cwd.as_deref() {
            let key = cwd.trim_end_matches('/');
            if !key.is_empty() {
                seen.insert(key.to_string());
            }
        }
    }
    seen.len()
}

fn compute_header_at(
    snap: &SessionSnapshot,
    active: bool,
    now: DateTime<Utc>,
    has_subagents: bool,
    project_count: usize,
) -> String {
    if !active {
        return "No agent active".to_string();
    }
    let mut name = if snap.agent_name.is_empty()
        || snap.agent_name == "claude"
        || snap.agent_name.starts_with("QA ")
        || snap.agent_name.starts_with("READ-ONLY ")
        || snap.agent_name.contains('/')
        || snap.agent_name.len() > 42
    {
        "Claude Code".to_string()
    } else {
        snap.agent_name.clone()
    };
    if has_subagents && !name.to_ascii_lowercase().contains("subagent") {
        name.push_str(" (subagents)");
    }
    // With more than one project active, "active in sir" would be misleading;
    // say "active in N projects" so the header agrees with the agent list.
    let path = if project_count > 1 {
        format!("{} projects", project_count)
    } else if snap.cwd.is_empty() {
        "~/project".to_string()
    } else {
        snap.cwd.rsplit('/').next().unwrap_or(&snap.cwd).to_string()
    };
    let dur = session_age_label(&snap.started_ts, now);
    format!("{} active in {} • {}", name, path, dur)
}

fn has_detected_subagents(agents: &[AgentInfo]) -> bool {
    agents.iter().any(is_concrete_subagent)
}

fn is_concrete_subagent(agent: &AgentInfo) -> bool {
    agent.agent_type.as_deref() == Some("sub") && agent.pid.unwrap_or_default() > 0
}

fn session_age_label(started_ts: &str, now: DateTime<Utc>) -> String {
    let started_ts = started_ts.trim();
    if started_ts.is_empty() {
        return "now".to_string();
    }
    let Ok(started) = DateTime::parse_from_rfc3339(started_ts).map(|ts| ts.with_timezone(&Utc))
    else {
        return "active".to_string();
    };
    let age = now.signed_duration_since(started);
    if age.num_seconds() <= 0 {
        return "now".to_string();
    }
    let total_seconds = age.num_seconds();
    if total_seconds < 60 {
        return format!("{}s", total_seconds);
    }
    let total_minutes = total_seconds / 60;
    if total_minutes < 60 {
        return format!("{}m", total_minutes);
    }
    let hours = total_minutes / 60;
    let minutes = total_minutes % 60;
    if hours < 24 {
        if minutes == 0 {
            return format!("{}h", hours);
        }
        return format!("{}h {}m", hours, minutes);
    }
    let days = hours / 24;
    let hours = hours % 24;
    if hours == 0 {
        format!("{}d", days)
    } else {
        format!("{}d {}h", days, hours)
    }
}

fn refresh_tray(app: &AppHandle, active: bool) {
    // Paused overrides the active/quiet display: while sensing is halted the tray
    // must make the gap unmistakable (it is a security-relevant state).
    let paused = app
        .try_state::<AppState>()
        .map(|s| *s.paused.lock().unwrap())
        .unwrap_or(false);
    if let Some(tray) = app.tray_by_id("main") {
        let (tooltip, title) = if paused {
            (
                "AgentSnitch — PAUSED: sensing halted, activity not being recorded",
                "⏸",
            )
        } else if active {
            ("AgentSnitch — AI agent active (click for details)", "●")
        } else {
            ("AgentSnitch — quiet", "")
        };
        let _ = tray.set_tooltip(Some(tooltip));
        let _ = tray.set_title(Some(title));
    }
}

fn update_session_from_event(snap: &mut SessionSnapshot, ev: &SemanticEvent) {
    if snap.agent_name.is_empty() {
        snap.agent_name = if ev.agent.name.is_empty() {
            ev.agent.id.clone()
        } else {
            ev.agent.name.clone()
        };
    }
    if snap.cwd.is_empty() {
        if let Some(c) = &ev.cwd {
            snap.cwd = c.clone();
        }
    }
    if snap.started_ts.is_empty() {
        snap.started_ts = ev.ts.clone();
    }
    if snap.id.is_empty() {
        snap.id = ev.session.id.clone();
    }
}

fn note_agent_activity(state: &AppState) {
    state.runtime.lock().unwrap().last_agent_activity = Some(SystemTime::now());
}

fn session_idle_timeout() -> Duration {
    std::env::var("AGENTSNITCH_SESSION_IDLE_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds >= 15)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_SESSION_IDLE_SECS))
}

fn reconcile_session_liveness(state: &AppState, app: &AppHandle) -> bool {
    if !*state.active.lock().unwrap() {
        return false;
    }

    let timeout = session_idle_timeout();
    let snap = state.session.lock().unwrap().clone();
    let last_activity = session_activity_anchor(&state.runtime.lock().unwrap(), &snap);
    let Some(last_activity) = last_activity else {
        reset_session_state(state);
        refresh_tray(app, false);
        return true;
    };
    if last_activity
        .elapsed()
        .map(|elapsed| elapsed < timeout)
        .unwrap_or(true)
    {
        return false;
    }

    let process_running = {
        let now = SystemTime::now();
        let agents = state.agents.lock().unwrap().clone();
        let mut runtime = state.runtime.lock().unwrap();
        let should_check = runtime
            .last_process_check
            .and_then(|checked| checked.elapsed().ok())
            .map(|elapsed| elapsed >= AGENT_PROCESS_CHECK_INTERVAL)
            .unwrap_or(true);
        if should_check {
            runtime.last_process_check = Some(now);
            match agent_process_running_for_session(&snap, &agents) {
                Ok(running) => {
                    runtime.agent_process_running = running;
                    running
                }
                Err(err) => {
                    append_ui_log(&format!(
                        "[agentsnitch-ui] agent process liveness check failed: {}",
                        err
                    ));
                    true
                }
            }
        } else {
            runtime.agent_process_running
        }
    };

    if process_running {
        return false;
    }

    reset_session_state(state);
    refresh_tray(app, false);
    true
}

fn session_activity_anchor(runtime: &SessionRuntime, snap: &SessionSnapshot) -> Option<SystemTime> {
    runtime.last_agent_activity.or_else(|| {
        DateTime::parse_from_rfc3339(snap.started_ts.trim())
            .ok()
            .map(|ts| SystemTime::from(ts.with_timezone(&Utc)))
    })
}

fn reset_session_state(state: &AppState) {
    state.events.lock().unwrap().clear();
    state.agents.lock().unwrap().clear();
    *state.active.lock().unwrap() = false;
    *state.quiet.lock().unwrap() = false;
    *state.next_id.lock().unwrap() = 0;
    *state.session.lock().unwrap() = SessionSnapshot::default();
    *state.runtime.lock().unwrap() = SessionRuntime::default();
    let prefs = state.quiet_preferences.lock().unwrap().clone();
    *state.quieted_patterns.lock().unwrap() =
        effective_quieted_patterns(&prefs, &SessionSnapshot::default());
}

fn agent_process_running_for_session(
    snap: &SessionSnapshot,
    agents: &HashMap<String, AgentInfo>,
) -> Result<bool, String> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,comm=,args="])
        .output()
        .map_err(|err| err.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(agent_process_lines_running_for_session(
        text.lines(),
        session_agent_family(snap, agents),
    ))
}

fn agent_process_lines_running_for_session<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    family: AgentFamily,
) -> bool {
    lines
        .into_iter()
        .any(|line| agent_process_line_matches_family(line, family))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentFamily {
    Claude,
    Codex,
    Gemini,
    OpenAI,
    Cursor,
    Any,
}

fn session_agent_family(
    snap: &SessionSnapshot,
    agents: &HashMap<String, AgentInfo>,
) -> AgentFamily {
    let mut text = format!("{} {} {}", snap.agent_name, snap.id, snap.cwd);
    for agent in agents.values() {
        text.push(' ');
        text.push_str(&agent.id);
        text.push(' ');
        text.push_str(&agent.name);
        if let Some(version) = &agent.version {
            text.push(' ');
            text.push_str(version);
        }
    }
    classify_agent_family_text(&text)
}

fn classify_agent_family_text(text: &str) -> AgentFamily {
    let lower = text.to_ascii_lowercase();
    if lower.contains("claude") {
        AgentFamily::Claude
    } else if lower.contains("codex") {
        AgentFamily::Codex
    } else if lower.contains("gemini") {
        AgentFamily::Gemini
    } else if lower.contains("openai") {
        AgentFamily::OpenAI
    } else if lower.contains("cursor") {
        AgentFamily::Cursor
    } else {
        AgentFamily::Any
    }
}

fn agent_process_line_matches_family(line: &str, family: AgentFamily) -> bool {
    let lower = line.to_ascii_lowercase();
    if lower.contains("agentsnitch")
        || lower.contains(".app/contents/macos/claude")
        || lower.contains(".app/contents/macos/codex")
        || lower.contains(".app/contents/frameworks/codex")
        || lower.contains("claude helper")
        || lower.contains("codex (service)")
        || lower.contains("codex (renderer)")
        || lower.contains("crashpad_handler")
        || lower.contains(" gitleaks ")
        || lower.contains(" rg ")
        || lower.contains(" grep ")
        || lower.contains(" pgrep ")
    {
        return false;
    }

    let mut parts = line.split_whitespace();
    let _pid = parts.next();
    let comm = parts.next().unwrap_or("");
    let comm_base = std::path::Path::new(comm)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(comm)
        .to_ascii_lowercase();

    match family {
        AgentFamily::Claude => {
            comm_base == "claude"
                || lower.contains("/claude-code/")
                || lower.contains(" claude-code ")
                || lower.contains(" @anthropic-ai/claude-code")
        }
        AgentFamily::Codex => {
            (comm_base == "codex" || lower.contains("/.codex/"))
                && !lower.contains(".app/contents/")
        }
        AgentFamily::Gemini => comm_base == "gemini",
        AgentFamily::OpenAI => comm_base == "openai",
        AgentFamily::Cursor => comm_base == "cursor-agent",
        AgentFamily::Any => {
            agent_process_line_matches_family(line, AgentFamily::Claude)
                || agent_process_line_matches_family(line, AgentFamily::Codex)
                || agent_process_line_matches_family(line, AgentFamily::Gemini)
                || agent_process_line_matches_family(line, AgentFamily::OpenAI)
                || agent_process_line_matches_family(line, AgentFamily::Cursor)
        }
    }
}

fn should_track_agent(agent: &AgentInfo) -> bool {
    if agent.id.is_empty() {
        return false;
    }
    if agent.agent_type.as_deref() == Some("sub") {
        return agent.pid.unwrap_or_default() > 0;
    }
    agent.pid.unwrap_or_default() > 0
        || agent
            .agent_type
            .as_deref()
            .is_some_and(|value| !value.is_empty())
}

fn update_agent_registry(agents: &mut HashMap<String, AgentInfo>, agent: &AgentInfo) {
    if !should_track_agent(agent) {
        return;
    }
    let entry = agents
        .entry(agent.id.clone())
        .or_insert_with(|| agent.clone());
    merge_agent_info(entry, agent);
    if let Some(parent) = inferred_parent_agent(agent) {
        let entry = agents
            .entry(parent.id.clone())
            .or_insert_with(|| parent.clone());
        merge_agent_info(entry, &parent);
    }
}

fn merge_agent_info(entry: &mut AgentInfo, agent: &AgentInfo) {
    if entry.name.is_empty() {
        entry.name = agent.name.clone();
    }
    if entry.agent_type.is_none() {
        entry.agent_type = agent.agent_type.clone();
    }
    if entry.pid.is_none() {
        entry.pid = agent.pid;
    }
    if entry.parent_agent_id.is_none() {
        entry.parent_agent_id = agent.parent_agent_id.clone();
    }
    if entry.spawn_method.is_none() || entry.spawn_method.as_deref() == Some("inferred") {
        entry.spawn_method = agent.spawn_method.clone();
    }
    if entry.first_seen.is_none() {
        entry.first_seen = agent.first_seen.clone();
    }
    if agent.last_seen.is_some() {
        entry.last_seen = agent.last_seen.clone();
    }
    if entry.cwd.as_deref().unwrap_or("").is_empty() {
        entry.cwd = agent.cwd.clone();
    }
}

fn inferred_parent_agent(agent: &AgentInfo) -> Option<AgentInfo> {
    if agent.agent_type.as_deref() != Some("sub") {
        return None;
    }
    let parent_id = agent.parent_agent_id.as_ref()?.trim();
    if parent_id.is_empty() || parent_id == agent.id {
        return None;
    }
    let pid = parent_id
        .strip_prefix("main_")
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|pid| *pid > 0);
    Some(AgentInfo {
        id: parent_id.to_string(),
        agent_type: Some("main".into()),
        name: "claude".into(),
        pid,
        spawn_method: Some("inferred".into()),
        first_seen: agent.first_seen.clone(),
        last_seen: agent.last_seen.clone(),
        cwd: agent.cwd.clone(),
        ..AgentInfo::default()
    })
}

fn sorted_agents(agents: &HashMap<String, AgentInfo>) -> Vec<AgentInfo> {
    let mut out = agents.values().cloned().collect::<Vec<_>>();
    out.sort_by(|a, b| {
        let rank = |agent: &AgentInfo| match agent.agent_type.as_deref() {
            Some("main") => 0,
            Some("sub") => 1,
            _ => 2,
        };
        rank(a)
            .cmp(&rank(b))
            .then_with(|| a.pid.unwrap_or_default().cmp(&b.pid.unwrap_or_default()))
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

fn sem_to_ui(id: u64, ev: SemanticEvent) -> UiEvent {
    let short_ts = if ev.ts.len() >= 19 {
        ev.ts[11..19].to_string()
    } else {
        ev.ts.clone()
    };
    let mut summary = format!("{} {}", ev.event, ev.tool);
    if let Some(tgt) = &ev.target {
        if !tgt.is_empty() {
            summary = format!("{} {}", summary, tgt);
        }
    } else if let Some(c) = &ev.cwd {
        if !c.is_empty() {
            summary = format!("{} @ {}", summary, c);
        }
    }
    let mut tags = ev.tags.clone().unwrap_or_default();
    if semantic_is_egress_like(&ev) && !tags.iter().any(|tag| tag == "egress_like") {
        tags.push("egress_like".into());
    }
    UiEvent {
        id,
        ts: short_ts,
        summary,
        tags,
        detail: None,
        destination: None,
        destination_context: None,
        correlated: false,
        evidence: None,
        agent: Some(ev.agent),
    }
}

fn semantic_is_egress_like(ev: &SemanticEvent) -> bool {
    let tags = ev.tags.clone().unwrap_or_default();
    if tags
        .iter()
        .any(|t| t == "external_egress_attempt" || t == "mcp_tool_use")
    {
        return true;
    }
    ev.tool.starts_with("mcp__") || ev.tool == "WebFetch" || ev.tool == "WebSearch"
}

fn network_to_ui(id: u64, ev: NetworkFlowEvent) -> UiEvent {
    let short_ts = if ev.ts.len() >= 19 {
        ev.ts[11..19].to_string()
    } else {
        ev.ts.clone()
    };
    let remote = ev
        .remote
        .clone()
        .unwrap_or_else(|| "(unknown remote)".to_string());
    let destination = destination_snippet(&ev);
    let pid = ev
        .pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "?".to_string());
    let mut detail_parts = Vec::new();
    if destination != remote {
        detail_parts.push(format!("remote: {}", remote));
    }
    if let Some(observer) = &ev.observer {
        if !observer.is_empty() {
            detail_parts.push(format!("source: {}", observer));
        }
    }
    if let Some(state) = &ev.state {
        if !state.is_empty() {
            detail_parts.push(format!("state: {}", state));
        }
    }
    if let Some(protocol) = &ev.protocol {
        if !protocol.is_empty() {
            detail_parts.push(format!("proto: {}", protocol));
        }
    }
    if let Some(process_path) = &ev.process_path {
        if !process_path.is_empty() {
            detail_parts.push(format!("process: {}", compact_process_name(process_path)));
        }
    }
    if let Some(category) = destination_category_for_flow(&ev) {
        detail_parts.push(format!("category: {}", category));
    } else {
        detail_parts.push("category: unknown external".into());
    }
    if let Some(sni) = &ev.sni {
        if !sni.is_empty() {
            detail_parts.push(format!("SNI: {}", sni));
        }
    }
    if let Some(bundle_id) = &ev.process_bundle_id {
        if !bundle_id.is_empty() {
            detail_parts.push(format!("bundle: {}", bundle_id));
        }
    }
    if let Some(team_id) = &ev.process_team_id {
        if !team_id.is_empty() {
            detail_parts.push(format!("team: {}", team_id));
        }
    }
    if let Some(bytes) = ev.bytes_out {
        if bytes > 0 {
            detail_parts.push(format!("out: {}B", bytes));
        }
    }
    let mut tags = vec!["network_egress".into()];
    if let Some(state) = ev.state.as_ref().filter(|value| !value.is_empty()) {
        tags.push(format!("network_{}", state));
    }
    if let Some(observer) = ev.observer.as_ref().filter(|value| !value.is_empty()) {
        tags.push(observer.clone());
    }
    UiEvent {
        id,
        ts: short_ts,
        summary: format!("Network -> {} (pid {})", destination, pid),
        tags,
        detail: if detail_parts.is_empty() {
            None
        } else {
            Some(detail_parts.join(" • "))
        },
        destination: Some(destination),
        destination_context: None,
        correlated: false,
        evidence: None,
        agent: ev.agent,
    }
}

fn correlated_to_ui(id: u64, ev: CorrelatedEvent) -> UiEvent {
    let short_ts = if ev.ts.len() >= 19 {
        ev.ts[11..19].to_string()
    } else {
        ev.ts.clone()
    };
    let mut tags = ev.reasons.clone().unwrap_or_default();
    tags.insert(0, "correlated".into());
    if let Some(confidence) = &ev.confidence {
        tags.insert(1, format!("confidence_{}", confidence));
    }
    let primary_semantic = ev
        .semantics
        .as_ref()
        .and_then(|items| items.first())
        .cloned();
    let primary_flow = ev.flows.as_ref().and_then(|items| items.first()).cloned();
    let agent = ev
        .agent
        .clone()
        .or_else(|| primary_semantic.as_ref().map(|sem| sem.agent.clone()))
        .or_else(|| primary_flow.as_ref().and_then(|flow| flow.agent.clone()));
    let confidence = ev.confidence.clone().unwrap_or_else(|| "low".into());
    let reasons = ev.reasons.clone().unwrap_or_default();
    let evidence = linked_evidence(
        ev.summary.clone(),
        primary_semantic.as_ref(),
        primary_flow.as_ref(),
        ev.process_tree.as_deref().unwrap_or(&[]),
        &reasons,
        &confidence,
        ev.score,
    );
    let flow_detail = primary_flow.as_ref().map(flow_evidence_line);
    UiEvent {
        id,
        ts: short_ts,
        summary: ev
            .summary
            .unwrap_or_else(|| "Correlated sensitive activity and network flow".into()),
        tags,
        detail: flow_detail,
        destination: Some(evidence.destination.clone()),
        destination_context: None,
        correlated: true,
        evidence: Some(evidence),
        agent,
    }
}

fn linked_evidence(
    summary: Option<String>,
    semantic: Option<&SemanticEvent>,
    flow: Option<&NetworkFlowEvent>,
    process_tree: &[ProcessNode],
    reasons: &[String],
    confidence: &str,
    score: f64,
) -> LinkedEvidence {
    let mut title = linked_evidence_title(summary.as_deref(), semantic);

    let destination = flow
        .map(|flow| destination_snippet_with_semantic(semantic, flow))
        .unwrap_or_else(|| "unknown destination".into());
    let destination_category = destination_category(semantic, flow, &title);
    if generic_linked_title(&title) && destination_category == "known Claude service" {
        title = "Claude service traffic while agent active".into();
    }
    let risk = evidence_risk(semantic, reasons, flow, &destination_category);
    let review_status =
        evidence_review_status(semantic, reasons, flow, &destination_category, &risk);
    let review_subtitle = evidence_review_subtitle(reasons, confidence);
    let decision = "observed".to_string();

    LinkedEvidence {
        title,
        semantic: semantic
            .map(semantic_evidence_line)
            .unwrap_or_else(|| "Agent activity was observed by a hook".into()),
        flow: flow
            .map(flow_evidence_line)
            .unwrap_or_else(|| "Outbound network activity was observed".into()),
        why_human: human_reason_sentence(reasons, semantic),
        destination,
        destination_provenance: destination_provenance(semantic, flow, &destination_category),
        destination_category,
        severity: evidence_severity(semantic, reasons).into(),
        risk,
        review_status,
        review_subtitle,
        decision: decision.clone(),
        details: evidence_details(semantic, flow, process_tree, reasons, confidence, score),
        replay: evidence_replay(semantic, flow, reasons, confidence, score, &decision),
        process_tree: process_tree.to_vec(),
        why: reasons.to_vec(),
        confidence: confidence.to_string(),
        score,
    }
}

fn linked_evidence_title(summary: Option<&str>, semantic: Option<&SemanticEvent>) -> String {
    let title = summary
        .and_then(|s| s.split(':').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Linked activity → outbound connection".into());

    if !generic_linked_title(&title) {
        return title;
    }

    semantic.and_then(semantic_linked_title).unwrap_or(title)
}

fn generic_linked_title(title: &str) -> bool {
    matches!(
        title,
        "Tool call → outbound connection" | "Linked activity → outbound connection"
    )
}

fn semantic_linked_title(ev: &SemanticEvent) -> Option<String> {
    if let Some((connector, action)) = mcp_tool_label(&ev.tool) {
        return Some(format!("{} {} → outbound connection", connector, action));
    }
    match ev.tool.as_str() {
        "WebFetch" => Some("Web fetch → outbound connection".into()),
        "WebSearch" => Some("Web search → outbound connection".into()),
        _ => None,
    }
}

fn mcp_tool_label(tool: &str) -> Option<(String, String)> {
    let body = tool.strip_prefix("mcp__")?;
    let (server, action) = body.rsplit_once("__")?;
    let connector = server
        .rsplit('_')
        .find(|part| !part.is_empty())
        .unwrap_or(server);
    Some((humanize_identifier(connector), humanize_identifier(action)))
}

fn humanize_identifier(value: &str) -> String {
    value
        .replace(['_', '-'], " ")
        .split_whitespace()
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(_) if part.chars().all(|ch| ch.is_ascii_uppercase()) => part.to_string(),
                Some(first) => {
                    let mut word = first.to_uppercase().collect::<String>();
                    word.push_str(chars.as_str());
                    word
                }
                None => String::new(),
            }
        })
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn human_reason_sentence(reasons: &[String], semantic: Option<&SemanticEvent>) -> String {
    let mut parts = Vec::new();
    for reason in reasons {
        let text = match reason.as_str() {
            "pid_match" => "same PID",
            "parent_match" => "parent/child process match",
            "ancestor_match" => "same process tree",
            "common_agent_ancestor" => "shared tracked agent ancestor",
            "same_agent_session" => "same agent session",
            "known_agent_binary_match" => "known agent binary",
            "mcp_server_flow" => "MCP server flow",
            "first_destination" => "first time seeing this destination in the session",
            "high_bytes" => "large byte volume",
            "within_10s" => "within 10 seconds",
            "existing_connection_active" => "connection was already active",
            "after_sensitive_read" => {
                if let Some(ev) = semantic {
                    if let Some(target) = sensitive_target_label(ev) {
                        let phrase = format!("after reading a sensitive file ({})", target);
                        if !parts.iter().any(|part| part == &phrase) {
                            parts.push(phrase);
                        }
                        continue;
                    }
                }
                "after reading sensitive local context"
            }
            other => other,
        };
        if !parts.iter().any(|part: &String| part == text) {
            parts.push(text.to_string());
        }
    }
    if parts.is_empty() {
        "Matched because: daemon correlation linked the hook and network event.".into()
    } else {
        format!("Matched because: {}.", parts.join(", "))
    }
}

fn sensitive_target_label(ev: &SemanticEvent) -> Option<String> {
    let tags = ev.tags.clone().unwrap_or_default();
    if !tags
        .iter()
        .any(|tag| tag == "sensitive_read" || tag.contains("credential"))
    {
        return None;
    }
    let target = semantic_evidence_target(ev);
    if target.is_empty() || target == ev.tool {
        return None;
    }
    Some(
        target
            .rsplit('/')
            .next()
            .filter(|part| !part.is_empty())
            .unwrap_or(&target)
            .to_string(),
    )
}

fn evidence_severity(semantic: Option<&SemanticEvent>, reasons: &[String]) -> &'static str {
    let tags = semantic.and_then(|ev| ev.tags.clone()).unwrap_or_default();
    if tags
        .iter()
        .any(|tag| tag == "sensitive_read" || tag.contains("credential"))
        || reasons
            .iter()
            .any(|reason| reason == "after_sensitive_read")
    {
        return "hot";
    }
    if reasons.iter().any(|reason| reason == "mcp_server_flow")
        || tags.iter().any(|tag| tag == "mcp_tool_use")
    {
        return "medium";
    }
    "low"
}

fn evidence_risk(
    semantic: Option<&SemanticEvent>,
    reasons: &[String],
    flow: Option<&NetworkFlowEvent>,
    destination_category: &str,
) -> String {
    let tags = semantic.and_then(|ev| ev.tags.clone()).unwrap_or_default();
    if tags
        .iter()
        .any(|tag| tag == "sensitive_read" || tag.contains("credential"))
        || reasons
            .iter()
            .any(|reason| reason == "after_sensitive_read")
    {
        return "high".into();
    }
    if flow.map(known_safe_destination).unwrap_or(false)
        || matches!(
            destination_category,
            "known Claude service"
                | "Playwright bridge traffic"
                | "telemetry/logging"
                | "package registry"
        )
    {
        return "low".into();
    }
    if reasons.iter().any(|reason| reason == "high_bytes") {
        if semantic
            .map(semantic_is_browser_automation)
            .unwrap_or(false)
            && matches!(destination_category, "local dev server bridge")
        {
            return "low".into();
        }
        return "medium".into();
    }
    if matches!(destination_category, "local dev server bridge") {
        return "low".into();
    }
    if matches!(destination_category, "local dev tunnel") {
        return "medium".into();
    }
    if let Some(flow) = flow {
        let bytes_out = flow.bytes_out.unwrap_or_default();
        if bytes_out > 256 * 1024 {
            return "medium".into();
        }
    }
    if reasons.iter().any(|reason| reason == "first_destination")
        && matches!(destination_category, "unknown external" | "cloud provider")
    {
        return "medium".into();
    }
    "low".into()
}

fn evidence_review_status(
    semantic: Option<&SemanticEvent>,
    reasons: &[String],
    flow: Option<&NetworkFlowEvent>,
    destination_category: &str,
    risk: &str,
) -> String {
    let has_sensitive = semantic.map(has_sensitive_semantic).unwrap_or(false)
        || reasons
            .iter()
            .any(|reason| reason == "after_sensitive_read");
    let weak_existing_only = reasons
        .iter()
        .any(|reason| reason == "existing_connection_active")
        && !reasons.iter().any(|reason| {
            matches!(
                reason.as_str(),
                "within_10s" | "pid_match" | "ancestor_match" | "common_agent_ancestor"
            )
        });
    if has_sensitive && weak_existing_only {
        return "Likely False Positive".into();
    }
    if risk == "high"
        || (has_sensitive && !weak_existing_only)
        || destination_category == "unknown external"
        || destination_category == "local dev tunnel"
    {
        return "Needs Review".into();
    }
    if risk == "medium" || destination_category == "cloud provider" {
        return "Review".into();
    }
    if flow.map(known_safe_destination).unwrap_or(false)
        || matches!(
            destination_category,
            "known Claude service"
                | "Playwright bridge traffic"
                | "telemetry/logging"
                | "package registry"
                | "local dev server bridge"
                | "local dev server"
        )
    {
        return "Routine".into();
    }
    "Review".into()
}

fn evidence_review_subtitle(reasons: &[String], confidence: &str) -> String {
    if reasons
        .iter()
        .any(|reason| reason == "existing_connection_active")
    {
        return format!(
            "{}-confidence link to an already-open connection",
            confidence
        );
    }
    if reasons.iter().any(|reason| reason == "within_10s") {
        return format!("{}-confidence link within 10 seconds", confidence);
    }
    format!("{}-confidence correlation", confidence)
}

fn has_sensitive_semantic(ev: &SemanticEvent) -> bool {
    ev.tags.clone().unwrap_or_default().iter().any(|tag| {
        tag == "sensitive_read" || tag == "credential_output" || tag == "structured_secret"
    })
}

fn destination_provenance(
    semantic: Option<&SemanticEvent>,
    flow: Option<&NetworkFlowEvent>,
    category: &str,
) -> Vec<EvidenceDetail> {
    let mut rows = Vec::new();
    if let Some(flow) = flow {
        let display = destination_snippet_with_semantic(semantic, flow);
        rows.push(detail("Display name", display));
    }
    if let Some(intent) = semantic_destination_intent(semantic) {
        rows.push(detail("Semantic intent", intent));
    }
    if let Some(flow) = flow {
        if let Some(sni) = flow.sni.as_ref().filter(|value| !value.is_empty()) {
            rows.push(detail("SNI / PTR host", sni.clone()));
        }
        if let Some(remote) = flow.remote.as_ref().filter(|value| !value.is_empty()) {
            rows.push(detail("Observed endpoint", remote.clone()));
        }
        if let Some(observer) = flow.observer.as_ref().filter(|value| !value.is_empty()) {
            rows.push(detail("Observer", observer.clone()));
        }
    }
    rows.push(detail("Category", category.to_string()));
    rows
}

fn known_safe_destination(flow: &NetworkFlowEvent) -> bool {
    let host = destination_host(flow);
    matches!(
        destination_category_for_host(&host).as_deref(),
        Some(
            "known Claude service"
                | "Playwright bridge traffic"
                | "telemetry/logging"
                | "package registry"
        )
    )
}

fn destination_snippet(flow: &NetworkFlowEvent) -> String {
    let remote = flow
        .remote
        .clone()
        .unwrap_or_else(|| "unknown destination".into());
    if let Some(sni) = flow.sni.as_ref().filter(|value| !value.is_empty()) {
        if remote == "unknown destination" || remote == "(unknown remote)" {
            return sni.clone();
        }
        let remote_host = destination_host_from_value(&remote);
        let sni_host = destination_host_from_value(sni);
        if !remote_host.is_empty() && remote_host == sni_host {
            return remote;
        }
        if !sni_host.is_empty() {
            return format!("{} ({})", sni_host, remote);
        }
        return format!("{} ({})", sni, remote);
    }
    remote_display_without_port_when_named(remote)
}

fn destination_snippet_with_semantic(
    semantic: Option<&SemanticEvent>,
    flow: &NetworkFlowEvent,
) -> String {
    let remote = flow
        .remote
        .clone()
        .unwrap_or_else(|| "unknown destination".into());
    if let Some(intent) = semantic_destination_intent(semantic) {
        let remote_host = destination_host_from_value(&remote);
        if remote_host != intent {
            return format!("{} ({})", intent, remote);
        }
    }
    destination_snippet(flow)
}

fn remote_display_without_port_when_named(remote: String) -> String {
    let host = remote
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(&remote)
        .trim_matches(['[', ']']);
    if host.chars().any(|ch| ch.is_ascii_alphabetic()) {
        host.to_string()
    } else {
        remote
    }
}

fn destination_category(
    semantic: Option<&SemanticEvent>,
    flow: Option<&NetworkFlowEvent>,
    title: &str,
) -> String {
    let Some(flow) = flow else {
        return "unknown external".into();
    };
    if let Some(intent) = semantic_destination_intent(semantic) {
        if semantic.map(semantic_targets_localhost).unwrap_or(false)
            || title.to_ascii_lowercase().contains("local bridge")
        {
            return "local dev server bridge".into();
        }
        if let Some(category) = destination_category_for_host(&intent) {
            return category;
        }
    }
    let host = destination_host(flow);
    if host.is_empty() {
        return "unknown external".into();
    }
    if semantic.map(semantic_targets_localhost).unwrap_or(false)
        || title.to_ascii_lowercase().contains("local bridge")
    {
        return "local dev server bridge".into();
    }
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || host.ends_with(".localhost") {
        return "local dev server".into();
    }
    if let Some(category) = destination_category_for_flow(flow) {
        return category;
    }
    "unknown external".into()
}

fn destination_category_for_flow(flow: &NetworkFlowEvent) -> Option<String> {
    let host = destination_host(flow);
    let remote = flow
        .remote
        .as_ref()
        .map(|value| destination_host_from_value(value))
        .unwrap_or_default();
    destination_category_for_host(&host).or_else(|| destination_category_for_host(&remote))
}

fn destination_category_for_host(host: &str) -> Option<String> {
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || host.ends_with(".localhost") {
        return Some("local dev server".into());
    }
    for category in &heuristics_config().destination_categories {
        if host_matches_any_domain(host, &category.domains)
            || host_matches_any_cidr(host, &category.cidrs)
        {
            return Some(category.name.clone());
        }
    }
    None
}

fn host_matches_any_domain(host: &str, domains: &[String]) -> bool {
    domains
        .iter()
        .any(|domain| host_matches_domain(host, domain))
}

fn host_matches_domain(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{}", domain))
}

fn host_matches_any_cidr(host: &str, cidrs: &[String]) -> bool {
    let host = destination_host_from_value(host);
    let Ok(addr) = host.parse::<std::net::IpAddr>() else {
        return false;
    };
    cidrs.iter().any(|cidr| ip_matches_cidr(addr, cidr))
}

fn ip_matches_cidr(addr: std::net::IpAddr, cidr: &str) -> bool {
    let Some((network, prefix)) = cidr.trim().split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    let Ok(network) = network.parse::<std::net::IpAddr>() else {
        return false;
    };
    match (addr, network) {
        (std::net::IpAddr::V4(addr), std::net::IpAddr::V4(network)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(addr) & mask) == (u32::from(network) & mask)
        }
        (std::net::IpAddr::V6(addr), std::net::IpAddr::V6(network)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(addr) & mask) == (u128::from(network) & mask)
        }
        _ => false,
    }
}

fn destination_host(flow: &NetworkFlowEvent) -> String {
    let value = flow
        .sni
        .as_ref()
        .filter(|value| !value.is_empty())
        .or(flow.remote.as_ref())
        .map(|value| value.as_str())
        .unwrap_or("")
        .trim()
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    value
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(&value)
        .trim_matches(['[', ']'])
        .to_string()
}

fn destination_host_from_value(value: &str) -> String {
    let value = value.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    value
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(&value)
        .trim_matches(['[', ']'])
        .to_string()
}

fn normalize_destination_host(value: &str) -> String {
    let value = value.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    value
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(&value)
        .trim_matches(['[', ']'])
        .to_string()
}

fn semantic_targets_localhost(ev: &SemanticEvent) -> bool {
    ev.destination_intents
        .as_ref()
        .map(|items| items.iter().any(|value| text_targets_localhost(value)))
        .unwrap_or(false)
        || ev
            .target
            .as_deref()
            .or_else(|| {
                ev.input_summary
                    .as_ref()
                    .and_then(|input| input.get("url"))
                    .and_then(|url| url.as_str())
            })
            .map(text_targets_localhost)
            .unwrap_or(false)
}

fn semantic_destination_intent(semantic: Option<&SemanticEvent>) -> Option<String> {
    semantic
        .and_then(|ev| ev.destination_intents.as_ref())
        .and_then(|items| {
            items
                .iter()
                .map(|value| destination_host_from_value(value))
                .find(|value| !value.is_empty())
        })
}

fn text_targets_localhost(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("localhost")
        || lower.contains("127.0.0.1")
        || lower.contains("[::1]")
        || lower.contains("://0.0.0.0")
}

fn semantic_is_browser_automation(ev: &SemanticEvent) -> bool {
    let tool = ev.tool.to_ascii_lowercase();
    tool.contains("playwright")
        || tool.contains("browser_")
        || tool.contains("__browser")
        || tool.contains("chrome")
}

fn evidence_details(
    semantic: Option<&SemanticEvent>,
    flow: Option<&NetworkFlowEvent>,
    process_tree: &[ProcessNode],
    reasons: &[String],
    confidence: &str,
    score: f64,
) -> Vec<EvidenceDetail> {
    let mut details = Vec::new();
    if let Some(ev) = semantic {
        details.push(detail("Hook event", format!("{} {}", ev.event, ev.tool)));
        details.push(detail("Hook PID", pid_pair(ev.pid, ev.ppid)));
        if let Some(cwd) = ev.cwd.as_ref().filter(|value| !value.is_empty()) {
            details.push(detail("Working directory", cwd.clone()));
        }
        if let Some(target) = ev.target.as_ref().filter(|value| !value.is_empty()) {
            details.push(detail("Target", target.clone()));
        }
        if let Some(intents) = ev
            .destination_intents
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            details.push(detail("Destination intent", intents.join(", ")));
        }
        if let Some(tags) = &ev.tags {
            if !tags.is_empty() {
                details.push(detail("Hook tags", tags.join(", ")));
            }
        }
        if let Some(input) = &ev.input_summary {
            details.push(detail("Input summary", compact_json(input)));
        }
    }
    if let Some(flow) = flow {
        if let Some(sem) = semantic {
            if let Some(delta) = timing_delta_detail(&sem.ts, &flow.ts) {
                details.push(detail("Timing", delta));
            }
            if let Some(link) = process_link_detail(sem, flow, reasons) {
                details.push(detail("Process link", link));
            }
        }
        details.push(detail(
            "Destination",
            destination_snippet_with_semantic(semantic, flow),
        ));
        if let Some(remote) = flow.remote.as_ref().filter(|value| !value.is_empty()) {
            details.push(detail("Remote endpoint", remote.clone()));
        }
        details.push(detail(
            "Network PID",
            flow.pid
                .map(|pid| pid_pair(pid, flow.ppid))
                .unwrap_or_else(|| "?".into()),
        ));
        if let Some(path) = flow.process_path.as_ref().filter(|value| !value.is_empty()) {
            details.push(detail("Process", path.clone()));
        }
        if let Some(observer) = flow.observer.as_ref().filter(|value| !value.is_empty()) {
            details.push(detail("Observer", observer.clone()));
        }
        if let Some(state) = flow.state.as_ref().filter(|value| !value.is_empty()) {
            details.push(detail("Flow state", state.clone()));
        }
        if let Some(protocol) = flow.protocol.as_ref().filter(|value| !value.is_empty()) {
            details.push(detail("Protocol", protocol.clone()));
        }
        let bytes = format!(
            "out {}B / in {}B",
            flow.bytes_out.unwrap_or_default(),
            flow.bytes_in.unwrap_or_default()
        );
        details.push(detail("Bytes", bytes));
    }
    if !reasons.is_empty() {
        details.push(detail("Raw reasons", reasons.join(", ")));
    }
    if !process_tree.is_empty() {
        details.push(detail("Process tree", format_process_tree(process_tree)));
    }
    details.push(detail(
        "Correlation",
        format!("{} {:.2}", confidence, score),
    ));
    details
}

fn evidence_replay(
    semantic: Option<&SemanticEvent>,
    flow: Option<&NetworkFlowEvent>,
    reasons: &[String],
    confidence: &str,
    score: f64,
    decision: &str,
) -> Vec<EvidenceDetail> {
    let mut replay = Vec::new();
    if let Some(ev) = semantic {
        replay.push(detail("1. Tool call", format!("{} {}", ev.event, ev.tool)));
        let target = semantic_evidence_target(ev);
        if !target.is_empty() {
            replay.push(detail("2. Target", target));
        }
        let agent = if ev.agent.version.as_deref().unwrap_or("").is_empty() {
            ev.agent.name.clone()
        } else {
            format!(
                "{} {}",
                ev.agent.name,
                ev.agent.version.as_deref().unwrap_or("")
            )
        };
        replay.push(detail(
            "3. Process",
            format!("{} hook PID {}", agent_name_or_default(&agent), ev.pid),
        ));
    }
    if let Some(flow) = flow {
        let network = if let Some(intent) = semantic_destination_intent(semantic) {
            format!("{}; intended host {}", flow_evidence_line(flow), intent)
        } else {
            flow_evidence_line(flow)
        };
        replay.push(detail("4. Network", network));
    }
    if !reasons.is_empty() {
        replay.push(detail("5. Correlation", reasons.join(" + ")));
    }
    replay.push(detail(
        "6. Decision",
        format!("{}; correlation {} {:.2}", decision, confidence, score),
    ));
    replay
}

fn agent_name_or_default(value: &str) -> String {
    if value.trim().is_empty() {
        "Claude Code".into()
    } else {
        value.trim().into()
    }
}

fn format_process_tree(nodes: &[ProcessNode]) -> String {
    nodes
        .iter()
        .map(|node| {
            let mut label = format!("pid {}", node.pid);
            if let Some(ppid) = node.ppid {
                if ppid > 0 {
                    label.push_str(&format!(" <- {}", ppid));
                }
            }
            if let Some(name) = node.name.as_ref().filter(|value| !value.is_empty()) {
                label.push_str(&format!(" {}", compact_process_name(name)));
            }
            if let Some(role) = node.role.as_ref().filter(|value| !value.is_empty()) {
                label.push_str(&format!(" [{}]", role));
            }
            label
        })
        .collect::<Vec<_>>()
        .join(" ; ")
}

fn compact_process_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.contains('/') {
        trimmed
            .rsplit('/')
            .next()
            .filter(|part| !part.is_empty())
            .unwrap_or(trimmed)
            .to_string()
    } else {
        trimmed.to_string()
    }
}

fn detail(label: impl Into<String>, value: impl Into<String>) -> EvidenceDetail {
    EvidenceDetail {
        label: label.into(),
        value: value.into(),
    }
}

fn pid_pair(pid: i32, ppid: Option<i32>) -> String {
    match ppid {
        Some(parent) => format!("{} (parent {})", pid, parent),
        None => pid.to_string(),
    }
}

fn compact_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<unrenderable summary>".into())
}

fn timing_delta_detail(semantic_ts: &str, flow_ts: &str) -> Option<String> {
    let semantic = parse_rfc3339_system_time(semantic_ts)?;
    let flow = parse_rfc3339_system_time(flow_ts)?;
    match flow.duration_since(semantic) {
        Ok(delta) => Some(format!(
            "network flow {} after hook",
            format_duration(delta)
        )),
        Err(err) => Some(format!(
            "network flow active {} before hook",
            format_duration(err.duration())
        )),
    }
}

fn parse_rfc3339_system_time(value: &str) -> Option<SystemTime> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return None;
    }
    parse_rfc3339_utc(normalized)
}

fn parse_rfc3339_utc(value: &str) -> Option<SystemTime> {
    let value = value.strip_suffix('Z')?;
    let (date, time) = value.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i32 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    let mut time_parts = time.split(':');
    let hour: u32 = time_parts.next()?.parse().ok()?;
    let minute: u32 = time_parts.next()?.parse().ok()?;
    let sec_part = time_parts.next()?;
    let (second_text, frac_text) = sec_part
        .split_once('.')
        .map_or((sec_part, ""), |(s, frac)| (s, frac));
    let second: u32 = second_text.parse().ok()?;
    let nanos = parse_fractional_nanos(frac_text)?;
    let days = days_from_civil(year, month, day)?;
    let secs = days
        .checked_mul(86_400)?
        .checked_add(hour as i64 * 3_600 + minute as i64 * 60 + second as i64)?;
    if secs < 0 {
        return None;
    }
    Some(SystemTime::UNIX_EPOCH + Duration::new(secs as u64, nanos))
}

fn parse_fractional_nanos(frac: &str) -> Option<u32> {
    if frac.is_empty() {
        return Some(0);
    }
    if !frac.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    let mut padded = frac.chars().take(9).collect::<String>();
    while padded.len() < 9 {
        padded.push('0');
    }
    padded.parse().ok()
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = month as i32;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) as i64)
}

fn format_duration(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis < 1_000 {
        return format!("{}ms", millis);
    }
    let seconds = duration.as_secs_f64();
    if seconds < 60.0 {
        return format!("{:.1}s", seconds);
    }
    format!("{:.1}m", seconds / 60.0)
}

fn process_link_detail(
    semantic: &SemanticEvent,
    flow: &NetworkFlowEvent,
    reasons: &[String],
) -> Option<String> {
    let flow_pid = flow.pid?;
    let relation = if reasons.iter().any(|reason| reason == "pid_match") {
        "same PID"
    } else if reasons.iter().any(|reason| reason == "parent_match") {
        "parent/child"
    } else if reasons.iter().any(|reason| reason == "ancestor_match") {
        "same process tree"
    } else if reasons
        .iter()
        .any(|reason| reason == "common_agent_ancestor")
    {
        "shared tracked agent ancestor"
    } else if reasons.iter().any(|reason| reason == "same_agent_session") {
        "same agent session"
    } else if reasons
        .iter()
        .any(|reason| reason == "known_agent_binary_match")
    {
        "known agent binary"
    } else {
        return None;
    };
    Some(format!(
        "{}: hook PID {}{} -> network PID {}{}",
        relation,
        semantic.pid,
        semantic
            .ppid
            .map(|ppid| format!(" (parent {})", ppid))
            .unwrap_or_default(),
        flow_pid,
        flow.ppid
            .map(|ppid| format!(" (parent {})", ppid))
            .unwrap_or_default()
    ))
}

fn semantic_evidence_line(ev: &SemanticEvent) -> String {
    let agent = if ev.agent.name.is_empty() {
        ev.agent.id.clone()
    } else {
        ev.agent.name.clone()
    };
    let action = match ev.tool.as_str() {
        "Read" => "read",
        "Bash" => "ran",
        "Write" => "wrote",
        "Edit" => "edited",
        _ => "used",
    };
    let target = semantic_evidence_target(ev);
    format!("{} {} {}", agent, action, target)
}

fn semantic_evidence_target(ev: &SemanticEvent) -> String {
    if let Some(target) = ev.target.clone().filter(|t| !t.is_empty()) {
        return target;
    }
    match ev.tool.as_str() {
        "Read" | "Bash" | "Write" | "Edit" => ev
            .cwd
            .clone()
            .filter(|cwd| !cwd.is_empty())
            .unwrap_or_else(|| ev.tool.clone()),
        _ => ev.tool.clone(),
    }
}

fn flow_evidence_line(flow: &NetworkFlowEvent) -> String {
    let remote = flow
        .remote
        .clone()
        .unwrap_or_else(|| "(unknown remote)".into());
    let pid = flow
        .pid
        .map(|value| value.to_string())
        .unwrap_or_else(|| "?".into());
    let mut line = format!("PID {} connected to {}", pid, remote);
    if let Some(sni) = &flow.sni {
        if !sni.is_empty() {
            line.push_str(&format!(" (SNI: {})", sni));
        }
    }
    if let Some(bytes) = flow.bytes_out {
        if bytes > 0 {
            line.push_str(&format!(", {}B out", bytes));
        }
    }
    line
}

fn push_ui_event(app: &AppHandle, ui: UiEvent) {
    let state: State<AppState> = app.state();
    let mut events = state.events.lock().unwrap();
    if duplicate_sidechain_ui_event(&events, &ui) {
        return;
    }
    events.push(ui.clone());
    trim_ui_events(&mut events);
    drop(events);
    let _ = app.emit("event-received", &ui);
    let _ = app.emit("status-changed", ());
}

fn duplicate_sidechain_ui_event(events: &[UiEvent], ui: &UiEvent) -> bool {
    if !ui.tags.iter().any(|tag| tag == "claude_sidechain") {
        return false;
    }
    let agent_id = ui
        .agent
        .as_ref()
        .map(|agent| agent.id.as_str())
        .unwrap_or("");
    events.iter().any(|existing| {
        existing.tags.iter().any(|tag| tag == "claude_sidechain")
            && existing.ts == ui.ts
            && existing.summary == ui.summary
            && existing
                .agent
                .as_ref()
                .map(|agent| agent.id.as_str())
                .unwrap_or("")
                == agent_id
    })
}

fn trim_ui_events(events: &mut Vec<UiEvent>) {
    while events.len() > MAX_UI_EVENTS {
        let idx = events.iter().position(|ev| !ev.correlated).unwrap_or(0);
        events.remove(idx);
    }
}

fn append_ui_log(line: &str) {
    let path = ui_log_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = create_private_dir_all(parent);
    }
    #[cfg(unix)]
    let open_result = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path);
    #[cfg(not(unix))]
    let open_result = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path);
    if let Ok(mut f) = open_result {
        use std::io::Write;
        let _ = writeln!(f, "{line}");
    }
    #[cfg(unix)]
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
}

fn verbose_ui_ingest_logging() -> bool {
    matches!(
        std::env::var("AGENTSNITCH_VERBOSE_UI_INGEST_LOG").as_deref(),
        Ok("1")
    )
}

fn ui_log_path() -> String {
    if let Ok(path) = std::env::var("AGENTSNITCH_UI_LOG") {
        return path;
    }
    if let Ok(home) = std::env::var("HOME") {
        return format!("{}/.agentsnitch/ui.log", home);
    }
    std::env::temp_dir()
        .join("agentsnitch-ui.log")
        .to_string_lossy()
        .into_owned()
}

fn quiet_preferences_path() -> String {
    if let Ok(path) = std::env::var("AGENTSNITCH_QUIET_PREFS") {
        return path;
    }
    if let Ok(home) = std::env::var("HOME") {
        return format!("{}/.agentsnitch/ui-quiet-preferences.json", home);
    }
    std::env::temp_dir()
        .join("agentsnitch-ui-quiet-preferences.json")
        .to_string_lossy()
        .into_owned()
}

fn destination_memory_path() -> String {
    if let Ok(path) = std::env::var("AGENTSNITCH_DESTINATION_MEMORY") {
        return path;
    }
    if let Ok(home) = std::env::var("HOME") {
        return format!("{}/.agentsnitch/ui-destination-memory.json", home);
    }
    std::env::temp_dir()
        .join("agentsnitch-ui-destination-memory.json")
        .to_string_lossy()
        .into_owned()
}

fn app_settings_path() -> String {
    if let Ok(path) = std::env::var("AGENTSNITCH_UI_SETTINGS") {
        return path;
    }
    if let Ok(home) = std::env::var("HOME") {
        return format!("{}/.agentsnitch/ui-settings.json", home);
    }
    std::env::temp_dir()
        .join("agentsnitch-ui-settings.json")
        .to_string_lossy()
        .into_owned()
}

fn load_app_settings() -> AppSettings {
    let path = app_settings_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return apply_network_sensor_env_override(AppSettings::default());
    };
    let settings = match serde_json::from_str::<AppSettings>(&text) {
        Ok(mut settings) => {
            if settings.schema.is_empty() {
                settings.schema = "agentsnitch.ui_settings.v0".into();
            }
            settings
        }
        Err(err) => {
            append_ui_log(&format!(
                "[agentsnitch-ui] settings parse failed at {}: {}",
                path, err
            ));
            AppSettings::default()
        }
    };
    apply_network_sensor_env_override(settings)
}

fn network_sensor_env_disabled() -> bool {
    std::env::var("AGENTSNITCH_DISABLE_NETWORK_EXTENSION")
        .map(|value| value == "1")
        .unwrap_or(false)
}

fn apply_network_sensor_env_override(mut settings: AppSettings) -> AppSettings {
    if network_sensor_env_disabled() {
        settings.network_sensor_disabled = true;
    }
    settings
}

fn save_app_settings(settings: &AppSettings) -> Result<(), String> {
    let path = app_settings_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        create_private_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let text = serde_json::to_string_pretty(settings).map_err(|err| err.to_string())?;
    #[cfg(unix)]
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|err| err.to_string())?;
        file.write_all(text.as_bytes())
            .map_err(|err| err.to_string())?;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, text).map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn load_quiet_preferences() -> QuietPreferences {
    let path = quiet_preferences_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return QuietPreferences {
            schema: "agentsnitch.ui_quiet.v0".into(),
            ..QuietPreferences::default()
        };
    };
    match serde_json::from_str::<QuietPreferences>(&text) {
        Ok(mut prefs) => {
            if prefs.schema.is_empty() {
                prefs.schema = "agentsnitch.ui_quiet.v0".into();
            }
            prefs
        }
        Err(err) => {
            append_ui_log(&format!(
                "[agentsnitch-ui] quiet preferences parse failed at {}: {}",
                path, err
            ));
            QuietPreferences {
                schema: "agentsnitch.ui_quiet.v0".into(),
                ..QuietPreferences::default()
            }
        }
    }
}

fn save_quiet_preferences(prefs: &QuietPreferences) -> Result<(), String> {
    let path = quiet_preferences_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        create_private_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let text = serde_json::to_string_pretty(prefs).map_err(|err| err.to_string())?;
    #[cfg(unix)]
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|err| err.to_string())?;
        file.write_all(text.as_bytes())
            .map_err(|err| err.to_string())?;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    std::fs::write(&path, text).map_err(|err| err.to_string())?;
    Ok(())
}

fn load_destination_memory() -> DestinationMemory {
    let path = destination_memory_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return DestinationMemory::default();
    };
    match serde_json::from_str::<DestinationMemory>(&text) {
        Ok(mut memory) => {
            if memory.schema.is_empty() {
                memory.schema = "agentsnitch.destination_memory.v0".into();
            }
            memory
        }
        Err(err) => {
            append_ui_log(&format!(
                "[agentsnitch-ui] destination memory parse failed at {}: {}",
                path, err
            ));
            DestinationMemory::default()
        }
    }
}

fn save_destination_memory(memory: &DestinationMemory) -> Result<(), String> {
    let path = destination_memory_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        create_private_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let text = serde_json::to_string_pretty(memory).map_err(|err| err.to_string())?;
    #[cfg(unix)]
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|err| err.to_string())?;
        file.write_all(text.as_bytes())
            .map_err(|err| err.to_string())?;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    std::fs::write(&path, text).map_err(|err| err.to_string())?;
    Ok(())
}

fn quiet_project_key(session: &SessionSnapshot) -> Option<String> {
    let cwd = session.cwd.trim();
    if cwd.is_empty() {
        None
    } else {
        Some(cwd.to_string())
    }
}

fn annotate_destination_context(ui: &mut UiEvent, state: &State<AppState>) {
    let Some(destination) = ui_destination_for_memory(ui) else {
        return;
    };
    let session = state.session.lock().unwrap().clone();
    let Some(project) = quiet_project_key(&session) else {
        return;
    };
    let key = normalize_pattern_piece(&destination);
    if key.is_empty() || key == "unknown destination" {
        return;
    }

    let memory_for_save = {
        let mut memory = state.destination_memory.lock().unwrap();
        let project_memory = memory.projects.entry(project.clone()).or_default();
        let previous_count = project_memory.get(&key).copied().unwrap_or_default();
        let state_name = if previous_count == 0 {
            "new_for_project"
        } else {
            "seen_before_project"
        };
        ui.destination_context = Some(DestinationContext {
            project_key: project,
            state: state_name.into(),
            label: if previous_count == 0 {
                "new for this project".into()
            } else {
                "seen before in this project".into()
            },
            previous_count,
        });
        project_memory.insert(key, previous_count + 1);
        memory.clone()
    };

    if let Err(err) = save_destination_memory(&memory_for_save) {
        append_ui_log(&format!(
            "[agentsnitch-ui] destination memory save failed: {}",
            err
        ));
    }
}

fn ui_destination_for_memory(ui: &UiEvent) -> Option<String> {
    ui.destination
        .as_deref()
        .or_else(|| {
            ui.evidence
                .as_ref()
                .map(|evidence| evidence.destination.as_str())
        })
        .map(destination_memory_key)
        .filter(|value| !value.is_empty())
}

fn destination_memory_key(value: &str) -> String {
    normalize_destination_host(value.split(" (").next().unwrap_or(value))
}

fn effective_quieted_patterns(
    prefs: &QuietPreferences,
    session: &SessionSnapshot,
) -> HashSet<String> {
    let mut keys = prefs.global.clone();
    if let Some(project) = quiet_project_key(session) {
        if let Some(project_keys) = prefs.projects.get(&project) {
            keys.extend(project_keys.iter().cloned());
        }
    }
    keys
}

fn apply_persisted_quiet_patterns(state: &State<AppState>) {
    let prefs = state.quiet_preferences.lock().unwrap().clone();
    let session = state.session.lock().unwrap().clone();
    let effective = effective_quieted_patterns(&prefs, &session);
    state.quieted_patterns.lock().unwrap().extend(effective);
}

fn store_quiet_keys(
    state: &State<AppState>,
    keys: &[String],
    scope: QuietScope,
) -> Result<(), String> {
    let mut prefs = state.quiet_preferences.lock().unwrap();
    if prefs.schema.is_empty() {
        prefs.schema = "agentsnitch.ui_quiet.v0".into();
    }
    match scope {
        QuietScope::Global => {
            prefs.global.extend(keys.iter().cloned());
        }
        QuietScope::Project => {
            let session = state.session.lock().unwrap().clone();
            if let Some(project) = quiet_project_key(&session) {
                prefs
                    .projects
                    .entry(project)
                    .or_default()
                    .extend(keys.iter().cloned());
            } else {
                prefs.global.extend(keys.iter().cloned());
            }
        }
    }
    save_quiet_preferences(&prefs)
}

enum QuietScope {
    Global,
    Project,
}

fn process_incoming_semantic(app: &AppHandle, ev: SemanticEvent) {
    let log_line = format!(
        "[agentsnitch-ui] process_incoming_semantic: {} {} pid={} tags={:?}",
        ev.event, ev.tool, ev.pid, ev.tags
    );
    if verbose_ui_ingest_logging() {
        println!("{}", log_line);
        append_ui_log(&log_line);
    }
    let state: State<AppState> = app.state();
    note_agent_activity(&state);
    let mut events = state.events.lock().unwrap();
    let mut next_id = state.next_id.lock().unwrap();
    *next_id += 1;
    let ui = sem_to_ui(*next_id, ev.clone());
    let is_quiet = *state.quiet.lock().unwrap();

    let mut is_active = state.active.lock().unwrap();
    let was_active = *is_active;
    let looks_like_agent = ev.event.contains("PreTool")
        || ev.event.contains("PostTool")
        || ev.agent.id == "claude"
        || ev.agent.id.contains("cursor");

    {
        let mut snap = state.session.lock().unwrap();
        let before = quiet_project_key(&snap);
        update_session_from_event(&mut snap, &ev);
        let after = quiet_project_key(&snap);
        if before != after {
            drop(snap);
            apply_persisted_quiet_patterns(&state);
        }
    }
    {
        let mut agents = state.agents.lock().unwrap();
        update_agent_registry(&mut agents, &ev.agent);
    }

    if !*is_active && looks_like_agent && !is_quiet {
        *is_active = true;
        refresh_tray(app, true);
    }

    if duplicate_sidechain_ui_event(&events, &ui) {
        return;
    }
    events.push(ui.clone());
    trim_ui_events(&mut events);
    drop(events);
    drop(is_active);

    let _ = app.emit("event-received", &ui);
    if !was_active {
        let _ = app.emit("status-changed", ());
    }
}

fn process_incoming_network(app: &AppHandle, ev: NetworkFlowEvent) {
    let log_line = format!(
        "[agentsnitch-ui] process_incoming_network: pid={:?} remote={:?}",
        ev.pid, ev.remote
    );
    if verbose_ui_ingest_logging() {
        println!("{}", log_line);
        append_ui_log(&log_line);
    }
    let state: State<AppState> = app.state();
    if let Some(agent) = ev.agent.as_ref() {
        let mut agents = state.agents.lock().unwrap();
        update_agent_registry(&mut agents, agent);
    }
    let mut next_id = state.next_id.lock().unwrap();
    *next_id += 1;
    let mut ui = network_to_ui(*next_id, ev);
    drop(next_id);
    annotate_destination_context(&mut ui, &state);
    push_ui_event(app, ui);
}

fn process_incoming_correlation(app: &AppHandle, ev: CorrelatedEvent) {
    let log_line = format!(
        "[agentsnitch-ui] process_incoming_correlation: score={} reasons={:?}",
        ev.score, ev.reasons
    );
    if verbose_ui_ingest_logging() {
        println!("{}", log_line);
        append_ui_log(&log_line);
    }
    let state: State<AppState> = app.state();
    note_agent_activity(&state);
    {
        let mut agents = state.agents.lock().unwrap();
        if let Some(agent) = ev.agent.as_ref() {
            update_agent_registry(&mut agents, agent);
        }
        if let Some(semantics) = ev.semantics.as_ref() {
            for semantic in semantics {
                update_agent_registry(&mut agents, &semantic.agent);
            }
        }
        if let Some(flows) = ev.flows.as_ref() {
            for flow in flows {
                if let Some(agent) = flow.agent.as_ref() {
                    update_agent_registry(&mut agents, agent);
                }
            }
        }
    }
    let mut next_id = state.next_id.lock().unwrap();
    *next_id += 1;
    let mut ui = correlated_to_ui(*next_id, ev);
    drop(next_id);
    annotate_destination_context(&mut ui, &state);
    if should_suppress_quieted_pattern(&ui, &state.quieted_patterns.lock().unwrap()) {
        let _ = app.emit("status-changed", ());
        return;
    }
    let breaks_quiet = linked_event_breaks_quiet(&ui);
    let was_quiet = *state.quiet.lock().unwrap();
    let mut active = state.active.lock().unwrap();
    if !*active && (!was_quiet || breaks_quiet) {
        *active = true;
        refresh_tray(app, true);
    }
    drop(active);
    if was_quiet && breaks_quiet {
        *state.quiet.lock().unwrap() = false;
    }
    push_ui_event(app, ui);
}

fn linked_event_breaks_quiet(ui: &UiEvent) -> bool {
    let Some(evidence) = &ui.evidence else {
        return false;
    };
    evidence.severity == "hot" || evidence.risk == "high" || evidence.confidence == "high"
}

fn should_suppress_quieted_pattern(ui: &UiEvent, quieted_patterns: &HashSet<String>) -> bool {
    !linked_event_breaks_quiet(ui)
        && quieted_pattern_keys(ui)
            .iter()
            .any(|key| quieted_patterns.contains(key))
}

fn linked_pattern_key(ui: &UiEvent) -> Option<String> {
    let evidence = ui.evidence.as_ref()?;
    let title = normalize_pattern_piece(&evidence.title);
    let destination = normalize_pattern_piece(&evidence.destination);
    let hook = evidence
        .details
        .iter()
        .find(|detail| detail.label == "Hook event")
        .and_then(|detail| detail.value.split_whitespace().nth(1))
        .map(normalize_pattern_piece)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| normalize_pattern_piece(&evidence.semantic));

    if title.is_empty() || destination.is_empty() {
        return None;
    }
    Some(format!("{}|{}|{}", title, hook, destination))
}

fn quieted_pattern_keys(ui: &UiEvent) -> Vec<String> {
    let Some(evidence) = ui.evidence.as_ref() else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    if let Some(key) = linked_pattern_key(ui) {
        keys.push(format!("exact:{}", key));
    }
    let tool = linked_tool_key(evidence);
    let destination = normalize_pattern_piece(&evidence.destination);
    if !tool.is_empty() && !destination.is_empty() {
        keys.push(format!("tool_dest:{}|{}", tool, destination));
    }
    if let Some(family) = linked_tool_family(evidence) {
        if !destination.is_empty() {
            keys.push(format!("family_dest:{}|{}", family, destination));
        }
        if known_quiet_category(&evidence.destination_category) {
            keys.push(format!(
                "family_category:{}|{}",
                family,
                normalize_pattern_piece(&evidence.destination_category)
            ));
        }
    }
    if known_quiet_category(&evidence.destination_category) {
        keys.push(format!(
            "category:{}",
            normalize_pattern_piece(&evidence.destination_category)
        ));
    }
    keys
}

fn quieted_pattern_keys_for_card(ui: &UiEvent) -> Vec<String> {
    quieted_pattern_keys(ui)
        .into_iter()
        .filter(|key| !key.starts_with("category:"))
        .collect()
}

fn linked_tool_key(evidence: &LinkedEvidence) -> String {
    evidence
        .details
        .iter()
        .find(|detail| detail.label == "Hook event")
        .and_then(|detail| detail.value.split_whitespace().nth(1))
        .map(normalize_pattern_piece)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| normalize_pattern_piece(&evidence.semantic))
}

fn linked_tool_family(evidence: &LinkedEvidence) -> Option<String> {
    let tool = linked_tool_key(evidence);
    for rule in &heuristics_config().noisy_automation {
        if rule.requires_localhost && !text_targets_localhost(&tool) {
            continue;
        }
        for pattern in &rule.contains {
            if tool.contains(&pattern.to_ascii_lowercase()) {
                return Some(rule.family.clone());
            }
        }
    }
    None
}

fn known_quiet_category(category: &str) -> bool {
    heuristics_config()
        .quiet_categories
        .iter()
        .any(|quiet_category| quiet_category == category)
}

fn known_service_quiet_keys() -> Vec<String> {
    heuristics_config()
        .quiet_categories
        .iter()
        .map(|category| format!("category:{}", normalize_pattern_piece(category)))
        .collect()
}

fn normalize_pattern_piece(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | ':' | '/') {
                ch
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn message_schema(body: &str) -> Option<String> {
    serde_json::from_str::<SchemaProbe>(body)
        .ok()
        .and_then(|probe| probe.schema)
}

fn is_agent_lifecycle_message(body: &str) -> bool {
    message_schema(body).as_deref() == Some("agentsnitch.agent.v0")
}

/// Wire shape of the daemon's pause_gap record (see event.PauseGapEvent in Go).
#[derive(Debug, Clone, Deserialize)]
struct PauseGapEvent {
    #[serde(default)]
    from: String,
    #[serde(default)]
    to: String,
    #[serde(default)]
    duration_sec: f64,
}

/// Builds a feed-visible UiEvent for a daemon pause_gap record. Returns None if the
/// body cannot be parsed as a pause_gap (the caller still emits so the UI refreshes).
fn build_pause_gap_ui_event(app: &AppHandle, body: &str) -> Option<UiEvent> {
    let gap: PauseGapEvent = serde_json::from_str(body).ok()?;
    let state: State<AppState> = app.state();
    let mut next_id = state.next_id.lock().unwrap();
    *next_id += 1;
    let id = *next_id;
    drop(next_id);

    // Short HH:MM:SS timestamp, matching sem_to_ui's convention; fall back to the
    // raw value when the timestamp is shorter than an RFC3339 prefix.
    let ts = if gap.to.len() >= 19 {
        gap.to[11..19].to_string()
    } else {
        gap.to.clone()
    };
    let duration = gap.duration_sec.round() as i64;
    let summary = format!(
        "Sensing paused — {}s coverage gap (no agent activity observed or recorded)",
        duration.max(0)
    );
    let detail = if !gap.from.is_empty() && !gap.to.is_empty() {
        Some(format!("Pause gap from {} to {}", gap.from, gap.to))
    } else {
        None
    };
    Some(UiEvent {
        id,
        ts,
        summary,
        tags: vec!["pause_gap".into()],
        detail,
        destination: None,
        destination_context: None,
        correlated: false,
        evidence: None,
        agent: None,
    })
}

fn process_incoming_json(app: &AppHandle, body: &str, source: &str) {
    // A pause_gap record is the daemon telling us a sensing gap just ended; always
    // surface it so the halted window is shown as an explicit gap. We must push a
    // UiEvent into state.events (not merely emit), because the feed is read from
    // state.events via get_status — emitting alone leaves the gap invisible there.
    if body.contains("agentsnitch.pause_gap") {
        if let Some(ui) = build_pause_gap_ui_event(app, body) {
            let state: State<AppState> = app.state();
            let mut events = state.events.lock().unwrap();
            events.push(ui.clone());
            trim_ui_events(&mut events);
            drop(events);
            let _ = app.emit("event-received", &ui);
        }
        let _ = app.emit("pause-gap", body.to_string());
        let _ = app.emit("status-changed", ());
        return;
    }
    // While paused the daemon should have stopped sending, but in-flight lines may
    // still arrive. Freeze the view: drop them rather than mutating state.
    if *app.state::<AppState>().paused.lock().unwrap() {
        return;
    }
    if is_agent_lifecycle_message(body) {
        let Ok(ev) = serde_json::from_str::<AgentLifecycleEvent>(body) else {
            let err_line = format!(
                "[agentsnitch-ui] {} agent lifecycle parse fail len={}",
                source,
                body.len()
            );
            eprintln!("{}", err_line);
            append_ui_log(&err_line);
            return;
        };
        process_incoming_agent(app, ev);
        return;
    }
    if let Ok(ev) = serde_json::from_str::<SemanticEvent>(body) {
        let log_line = format!(
            "[agentsnitch-ui] {} RECEIVED len={} event={} tool={} pid={} sess={}",
            source,
            body.len(),
            ev.event,
            ev.tool,
            ev.pid,
            ev.session.id
        );
        if verbose_ui_ingest_logging() {
            println!("{}", log_line);
            append_ui_log(&log_line);
        }
        process_incoming_semantic(app, ev);
        return;
    }
    if let Ok(ev) = serde_json::from_str::<CorrelatedEvent>(body) {
        process_incoming_correlation(app, ev);
        return;
    }
    if let Ok(ev) = serde_json::from_str::<NetworkFlowEvent>(body) {
        process_incoming_network(app, ev);
        return;
    }
    let err_line = format!("[agentsnitch-ui] {} parse fail len={}", source, body.len());
    eprintln!("{}", err_line);
    append_ui_log(&err_line);
}

fn process_incoming_agent(app: &AppHandle, ev: AgentLifecycleEvent) {
    let log_line = format!(
        "[agentsnitch-ui] process_incoming_agent: {} id={} pid={:?} type={:?}",
        ev.event, ev.agent.id, ev.agent.pid, ev.agent.agent_type
    );
    if verbose_ui_ingest_logging() {
        println!("{}", log_line);
        append_ui_log(&log_line);
    }
    let state: State<AppState> = app.state();
    note_agent_activity(&state);
    {
        let mut agents = state.agents.lock().unwrap();
        update_agent_registry(&mut agents, &ev.agent);
    }
    if !*state.quiet.lock().unwrap() {
        *state.active.lock().unwrap() = true;
        refresh_tray(app, true);
    }
    let _ = app.emit("status-changed", ());
}

#[cfg(unix)]
fn start_unix_socket_listener(app: AppHandle) {
    thread::spawn(move || {
        let path = ui_socket_path();
        let _ = std::fs::remove_file(&path);
        match UnixListener::bind(&path) {
            Ok(listener) => {
                let _ = std::fs::set_permissions(
                    &path,
                    std::os::unix::fs::PermissionsExt::from_mode(0o600),
                );
                println!("[agentsnitch-ui] listening on unix socket {}", path);
                for stream in listener.incoming().flatten() {
                    if let Err(e) = handle_unix_stream(&app, stream) {
                        eprintln!("[agentsnitch-ui] unix stream err: {}", e);
                    }
                }
            }
            Err(e) => eprintln!("[agentsnitch-ui] failed to bind {}: {}", path, e),
        }
    });
}

#[cfg(unix)]
fn ui_socket_path() -> String {
    if let Ok(path) = std::env::var("AGENTSNITCH_UI_SOCK") {
        return path;
    }
    if let Ok(home) = std::env::var("HOME") {
        let dir = format!("{}/.agentsnitch", home);
        let _ = create_private_dir_all(std::path::Path::new(&dir));
        return format!("{}/ui.sock", dir);
    }
    "/tmp/agentsnitch-ui.sock".into()
}

/// Path to the daemon's control/ingestion socket. Mirrors the Go side
/// (internal/runtime.SocketPath): AGENTSNITCH_SOCK / AGENTSNITCH_SOCKET override,
/// else ~/.agentsnitch/events.sock.
fn daemon_socket_path() -> String {
    for key in ["AGENTSNITCH_SOCK", "AGENTSNITCH_SOCKET"] {
        if let Ok(path) = std::env::var(key) {
            if !path.is_empty() {
                return path;
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return format!("{}/.agentsnitch/events.sock", home);
    }
    "/tmp/agentsnitch-dev.sock".into()
}

/// Send a single pause/resume control message to the daemon over its socket. The
/// daemon trusts the UI binary by executable path and flips its sensing flag. Best
/// effort with a short timeout: the UI must never block on a wedged daemon.
#[cfg(unix)]
fn send_daemon_control(action: &str) -> Result<(), String> {
    use std::io::Write;
    use std::time::Duration;

    let path = daemon_socket_path();
    let mut stream =
        UnixStream::connect(&path).map_err(|e| format!("connect daemon socket {}: {}", path, e))?;
    let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
    let msg = format!(
        "{{\"schema\":\"agentsnitch.control.v0\",\"action\":\"{}\"}}\n",
        action
    );
    stream
        .write_all(msg.as_bytes())
        .map_err(|e| format!("write control message: {}", e))?;
    Ok(())
}

#[cfg(not(unix))]
fn send_daemon_control(_action: &str) -> Result<(), String> {
    Err("daemon control socket is unix-only".into())
}

fn create_private_dir_all(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
fn handle_unix_stream(
    app: &AppHandle,
    stream: UnixStream,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::BufReader;

    let mut reader = BufReader::new(stream);
    process_ui_socket_lines(&mut reader, |line| process_incoming_json(app, line, "UDS"))
}

#[cfg(unix)]
fn process_ui_socket_lines<R, F>(
    reader: &mut R,
    mut process_line: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: std::io::BufRead,
    F: FnMut(&str),
{
    let mut line = String::new();
    let mut total: u64 = 0;
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_UI_STREAM_BYTES {
            return Err("ui socket stream exceeded read limit".into());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        process_line(trimmed);
    }
    Ok(())
}

#[cfg(not(unix))]
fn start_unix_socket_listener(_app: AppHandle) {
    println!("[agentsnitch-ui] unix socket listener disabled on this platform");
}

#[cfg(target_os = "macos")]
fn request_network_extension_activation() {
    if network_sensor_env_disabled() {
        println!(
            "[agentsnitch-ui] Network Extension activation skipped: AGENTSNITCH_DISABLE_NETWORK_EXTENSION=1"
        );
        if let Err(err) = set_macos_network_sensor_disabled(true) {
            eprintln!(
                "[agentsnitch-ui] Network Extension env kill-switch disable failed: {}",
                err
            );
        }
        return;
    }
    if load_app_settings().network_sensor_disabled {
        println!(
            "[agentsnitch-ui] Network Extension activation skipped: network sensor disabled in settings"
        );
        if let Err(err) = set_macos_network_sensor_disabled(true) {
            eprintln!(
                "[agentsnitch-ui] Network Extension disable request unavailable: {}",
                err
            );
        }
        return;
    }
    match macos_ne_bridge::start_and_activate() {
        Ok(detail) => println!(
            "[agentsnitch-ui] Network Extension host bridge started: {}",
            detail
        ),
        Err(err) => eprintln!(
            "[agentsnitch-ui] Network Extension host bridge unavailable: {}",
            err
        ),
    }
}

#[cfg(not(target_os = "macos"))]
fn request_network_extension_activation() {
    println!("[agentsnitch-ui] NE activation is macOS-only.");
}

#[cfg(target_os = "macos")]
mod macos_ne_bridge {
    use std::env;
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int, c_void};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const RTLD_NOW: c_int = 0x2;
    const DYLIB_NAME: &str = "libAgentSnitchHostBridge.dylib";
    const EXTENSION_BUNDLE_NAME: &str = "com.somoore.agentsnitch.network-extension.systemextension";

    type BridgeFn = unsafe extern "C" fn() -> i32;
    type BridgeSetDisabledFn = unsafe extern "C" fn(c_int) -> i32;

    unsafe extern "C" {
        fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn dlerror() -> *const c_char;
    }

    pub fn start_and_activate() -> Result<String, String> {
        preflight_activation_signing()?;
        let (path, handle) = load_host_bridge()?;
        let start = unsafe { load_symbol(handle, "AgentSnitchHostBridgeStart")? };
        let activate =
            unsafe { load_symbol(handle, "AgentSnitchHostBridgeActivateSystemExtension")? };

        let start_code = unsafe { start() };
        if start_code != 0 {
            return Err(format!(
                "{} returned {}",
                "AgentSnitchHostBridgeStart", start_code
            ));
        }

        let activate_code = unsafe { activate() };
        if activate_code != 0 {
            return Err(format!(
                "{} returned {}",
                "AgentSnitchHostBridgeActivateSystemExtension", activate_code
            ));
        }

        Ok(format!(
            "{}; XPC listener requested and system extension activation submitted",
            path.display()
        ))
    }

    pub fn set_network_sensor_disabled(disabled: bool) -> Result<String, String> {
        let (path, handle) = load_host_bridge()?;
        let set_disabled = unsafe {
            load_set_disabled_symbol(handle, "AgentSnitchHostBridgeSetNetworkSensorDisabled")?
        };
        let code = unsafe { set_disabled(if disabled { 1 } else { 0 }) };
        if code != 0 {
            return Err(format!(
                "{} returned {}",
                "AgentSnitchHostBridgeSetNetworkSensorDisabled", code
            ));
        }
        Ok(format!(
            "{}; network sensor {} request submitted",
            path.display(),
            if disabled { "disable" } else { "enable" }
        ))
    }

    fn preflight_activation_signing() -> Result<(), String> {
        let exe = env::current_exe()
            .map_err(|err| format!("could not inspect current executable: {}", err))?;
        let Some(app_bundle) = app_bundle_from_exe(&exe) else {
            return Ok(());
        };

        let app_report = codesign_report(&app_bundle)?;
        validate_app_signing(&app_report)?;

        let extension_bundle = app_bundle
            .join("Contents")
            .join("Library")
            .join("SystemExtensions")
            .join(EXTENSION_BUNDLE_NAME);
        if !extension_bundle.exists() {
            return Err(format!(
                "{} is missing; Network Extension activation requires the embedded system extension bundle",
                extension_bundle.display()
            ));
        }
        let extension_report = codesign_report(&extension_bundle)?;
        validate_extension_signing(&extension_report, app_report.team_id.as_deref())?;
        Ok(())
    }

    fn app_bundle_from_exe(exe: &Path) -> Option<PathBuf> {
        exe.ancestors()
            .find(|path| path.extension().is_some_and(|ext| ext == "app"))
            .map(Path::to_path_buf)
    }

    #[derive(Debug, PartialEq, Eq)]
    struct CodeSignReport {
        team_id: Option<String>,
        ad_hoc: bool,
        text: String,
    }

    fn codesign_report(path: &Path) -> Result<CodeSignReport, String> {
        let output = Command::new("codesign")
            .args(["-dvvv", "--entitlements", ":-"])
            .arg(path)
            .output()
            .map_err(|err| format!("codesign failed to start for {}: {}", path.display(), err))?;

        let mut text = String::new();
        text.push_str(&String::from_utf8_lossy(&output.stdout));
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        if !output.status.success() && text.trim().is_empty() {
            return Err(format!(
                "codesign failed for {} with status {}",
                path.display(),
                output.status
            ));
        }
        Ok(parse_codesign_report(&text))
    }

    fn parse_codesign_report(text: &str) -> CodeSignReport {
        let team_id = text.lines().find_map(|line| {
            let line = line.trim();
            let value = line.strip_prefix("TeamIdentifier=")?.trim();
            if value.is_empty() || value == "not set" {
                None
            } else {
                Some(value.to_string())
            }
        });
        CodeSignReport {
            team_id,
            ad_hoc: text.contains("Signature=adhoc") || text.contains("(adhoc"),
            text: text.to_string(),
        }
    }

    fn validate_app_signing(report: &CodeSignReport) -> Result<(), String> {
        if report.ad_hoc {
            return Err("Network Extension activation skipped: AgentSnitch.app is ad hoc signed; sign with a real Apple Team ID and provisioning profile".into());
        }
        if report.team_id.is_none() {
            return Err(
                "Network Extension activation skipped: AgentSnitch.app has no TeamIdentifier"
                    .into(),
            );
        }
        if !report
            .text
            .contains("com.apple.developer.system-extension.install")
        {
            return Err("Network Extension activation skipped: AgentSnitch.app signed entitlements lack com.apple.developer.system-extension.install".into());
        }
        if !report
            .text
            .contains("content-filter-provider-systemextension")
        {
            return Err("Network Extension activation skipped: AgentSnitch.app signed entitlements lack content-filter-provider-systemextension".into());
        }
        Ok(())
    }

    fn validate_extension_signing(
        report: &CodeSignReport,
        app_team_id: Option<&str>,
    ) -> Result<(), String> {
        if report.ad_hoc {
            return Err(
                "Network Extension activation skipped: embedded system extension is ad hoc signed"
                    .into(),
            );
        }
        let Some(extension_team_id) = report.team_id.as_deref() else {
            return Err("Network Extension activation skipped: embedded system extension has no TeamIdentifier".into());
        };
        if let Some(app_team_id) = app_team_id {
            if extension_team_id != app_team_id {
                return Err(format!(
                    "Network Extension activation skipped: TeamIdentifier mismatch between app ({}) and embedded extension ({})",
                    app_team_id, extension_team_id
                ));
            }
        }
        if !report
            .text
            .contains("content-filter-provider-systemextension")
        {
            return Err("Network Extension activation skipped: embedded system extension signed entitlements lack content-filter-provider-systemextension".into());
        }
        Ok(())
    }

    fn load_host_bridge() -> Result<(PathBuf, *mut c_void), String> {
        let candidates = candidate_paths();
        let mut attempts = Vec::new();
        for path in candidates {
            if !path.exists() {
                attempts.push(format!("{} missing", path.display()));
                continue;
            }

            let c_path = CString::new(path.to_string_lossy().as_bytes())
                .map_err(|_| format!("{} contains an interior NUL byte", path.display()))?;
            let handle = unsafe { dlopen(c_path.as_ptr(), RTLD_NOW) };
            if handle.is_null() {
                attempts.push(format!("{}: {}", path.display(), last_dl_error()));
                continue;
            }
            return Ok((path, handle));
        }

        Err(format!(
            "{} was not loadable; checked {}",
            DYLIB_NAME,
            attempts.join("; ")
        ))
    }

    unsafe fn load_symbol(handle: *mut c_void, symbol: &str) -> Result<BridgeFn, String> {
        let c_symbol = CString::new(symbol).map_err(|_| format!("invalid symbol {}", symbol))?;
        let ptr = dlsym(handle, c_symbol.as_ptr());
        if ptr.is_null() {
            return Err(format!("{} missing: {}", symbol, last_dl_error()));
        }
        Ok(std::mem::transmute::<*mut c_void, BridgeFn>(ptr))
    }

    unsafe fn load_set_disabled_symbol(
        handle: *mut c_void,
        symbol: &str,
    ) -> Result<BridgeSetDisabledFn, String> {
        let c_symbol = CString::new(symbol).map_err(|_| format!("invalid symbol {}", symbol))?;
        let ptr = dlsym(handle, c_symbol.as_ptr());
        if ptr.is_null() {
            return Err(format!("{} missing: {}", symbol, last_dl_error()));
        }
        Ok(std::mem::transmute::<*mut c_void, BridgeSetDisabledFn>(ptr))
    }

    fn candidate_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Ok(path) = env::var("AGENTSNITCH_HOST_BRIDGE_DYLIB") {
            paths.push(PathBuf::from(path));
        }

        if let Ok(exe) = env::current_exe() {
            if let Some(exe_dir) = exe.parent() {
                paths.push(exe_dir.join(DYLIB_NAME));
                if let Some(contents_dir) = exe_dir.parent() {
                    paths.push(contents_dir.join("Frameworks").join(DYLIB_NAME));
                    paths.push(contents_dir.join("Resources").join(DYLIB_NAME));
                }
            }
        }

        if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
            paths.push(
                PathBuf::from(manifest_dir)
                    .join("..")
                    .join("..")
                    .join("extension")
                    .join("build")
                    .join(DYLIB_NAME),
            );
        }

        paths
    }

    fn last_dl_error() -> String {
        let ptr = unsafe { dlerror() };
        if ptr.is_null() {
            return "dlopen/dlsym did not provide an error".to_string();
        }
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn app_bundle_from_exe_finds_containing_app() {
            let exe = Path::new("/Applications/AgentSnitch.app/Contents/MacOS/agentsnitch-ui");
            let got = app_bundle_from_exe(exe).unwrap();
            assert_eq!(got, PathBuf::from("/Applications/AgentSnitch.app"));
        }

        #[test]
        fn app_bundle_from_exe_ignores_non_app_binaries() {
            let exe = Path::new("/tmp/agentsnitch-ui");
            assert!(app_bundle_from_exe(exe).is_none());
        }

        #[test]
        fn parse_codesign_report_extracts_team_and_ad_hoc_state() {
            let report = parse_codesign_report(
                "CodeDirectory flags=0x10002(adhoc,runtime)\nTeamIdentifier=ABCDE12345\nSignature=adhoc\n",
            );
            assert_eq!(report.team_id.as_deref(), Some("ABCDE12345"));
            assert!(report.ad_hoc);
        }

        #[test]
        fn parse_codesign_report_treats_not_set_team_as_missing() {
            let report = parse_codesign_report("TeamIdentifier=not set\nSignature=adhoc\n");
            assert_eq!(report.team_id, None);
            assert!(report.ad_hoc);
        }

        #[test]
        fn validate_app_signing_rejects_ad_hoc() {
            let report = CodeSignReport {
                team_id: Some("ABCDE12345".into()),
                ad_hoc: true,
                text: "com.apple.developer.system-extension.install content-filter-provider-systemextension".into(),
            };
            let err = validate_app_signing(&report).unwrap_err();
            assert!(err.contains("ad hoc signed"));
        }

        #[test]
        fn validate_extension_signing_rejects_team_mismatch() {
            let report = CodeSignReport {
                team_id: Some("ZZZZZ99999".into()),
                ad_hoc: false,
                text: "content-filter-provider-systemextension".into(),
            };
            let err = validate_extension_signing(&report, Some("ABCDE12345")).unwrap_err();
            assert!(err.contains("TeamIdentifier mismatch"));
        }

        #[test]
        fn validate_extension_signing_accepts_matching_entitled_extension() {
            let report = CodeSignReport {
                team_id: Some("ABCDE12345".into()),
                ad_hoc: false,
                text: "content-filter-provider-systemextension".into(),
            };
            validate_extension_signing(&report, Some("ABCDE12345")).unwrap();
        }
    }
}

fn show_panel(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.unminimize();
        let _ = win.show();
        let _ = win.set_focus();
    }
}

fn hide_panel(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.hide();
    }
}

fn create_tray(app: &AppHandle) -> tauri::Result<()> {
    let icon = Image::from_bytes(include_bytes!("../icons/tray-icon.png")).expect("tray icon");

    let show = MenuItem::with_id(app, "show", "Show AgentSnitch", true, None::<&str>)?;
    let quiet = MenuItem::with_id(app, "quiet", "Quiet current session", true, None::<&str>)?;
    let export = MenuItem::with_id(app, "export", "Export Evidence Pack", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&show, &quiet, &export, &quit])?;

    let _tray = TrayIconBuilder::with_id("main")
        .icon(icon)
        .tooltip("AgentSnitch")
        .icon_as_template(false) // false to preserve the custom owl icon design from window-icons (instead of system template tinting which was causing white box)
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event: MenuEvent| match event.id().as_ref() {
            "show" => {
                show_panel(app);
                let _ = app.emit("events-updated", ());
                let _ = app.emit("status-changed", ());
            }
            "quiet" => {
                if let Some(state) = app.try_state::<AppState>() {
                    *state.active.lock().unwrap() = false;
                    *state.quiet.lock().unwrap() = true;
                    refresh_tray(app, false);
                    let _ = app.emit("events-updated", ());
                    let _ = app.emit("status-changed", ());
                }
                hide_panel(app);
            }
            "export" => {
                let _ = app.emit("trigger-export", ());
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                ..
            } = event
            {
                let app = tray.app_handle();
                show_panel(app);
                let _ = app.emit("events-updated", ());
                let _ = app.emit("status-changed", ());
            }
        })
        .build(app)?;
    Ok(())
}

fn create_app_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let settings = MenuItem::with_id(app, "settings", "Settings...", true, Some(","))?;

    let app_menu = Submenu::with_items(
        app,
        "AgentSnitch",
        true,
        &[
            &PredefinedMenuItem::about(app, None, None)?,
            &PredefinedMenuItem::separator(app)?,
            &settings,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::services(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::hide(app, None)?,
            &PredefinedMenuItem::hide_others(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::quit(app, None)?,
        ],
    )?;
    let file_menu = Submenu::with_items(
        app,
        "File",
        true,
        &[&PredefinedMenuItem::close_window(app, None)?],
    )?;
    let edit_menu = Submenu::with_items(
        app,
        "Edit",
        true,
        &[
            &PredefinedMenuItem::undo(app, None)?,
            &PredefinedMenuItem::redo(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::cut(app, None)?,
            &PredefinedMenuItem::copy(app, None)?,
            &PredefinedMenuItem::paste(app, None)?,
            &PredefinedMenuItem::select_all(app, None)?,
        ],
    )?;
    let view_menu = Submenu::with_items(
        app,
        "View",
        true,
        &[&PredefinedMenuItem::fullscreen(app, None)?],
    )?;
    let window_menu = Submenu::with_items(
        app,
        "Window",
        true,
        &[
            &PredefinedMenuItem::minimize(app, None)?,
            &PredefinedMenuItem::maximize(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::close_window(app, None)?,
        ],
    )?;
    let help_menu = Submenu::with_items(app, "Help", true, &[])?;

    Menu::with_items(
        app,
        &[
            &app_menu,
            &file_menu,
            &edit_menu,
            &view_menu,
            &window_menu,
            &help_menu,
        ],
    )
}

fn handle_app_menu_event(app: &AppHandle, event: MenuEvent) {
    if event.id().as_ref() == "settings" {
        show_panel(app);
        let _ = app.emit("open-network-sensor-settings", ());
        let _ = app.emit("settings-changed", get_app_settings_from_handle(app));
    }
}

fn get_app_settings_from_handle(app: &AppHandle) -> AppSettings {
    app.try_state::<AppState>()
        .map(|state| state.app_settings.lock().unwrap().clone())
        .unwrap_or_default()
}

fn setup_window_behavior(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.hide();
    }
}

// ---------------- Tauri commands ----------------

#[tauri::command]
fn get_events(state: State<AppState>) -> Vec<UiEvent> {
    state.events.lock().unwrap().clone()
}

#[tauri::command]
fn get_events_json(state: State<AppState>) -> Result<String, String> {
    serde_json::to_string(&*state.events.lock().unwrap()).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_status(state: State<AppState>, app: AppHandle) -> Status {
    let reset = reconcile_session_liveness(&state, &app);
    let active = *state.active.lock().unwrap();
    let quiet = *state.quiet.lock().unwrap();
    let paused = *state.paused.lock().unwrap();
    let recent = state.events.lock().unwrap().clone();
    let count = recent.len();
    let snap = state.session.lock().unwrap().clone();
    let quieted_count = state.quieted_patterns.lock().unwrap().len();
    let agents = sorted_agents(&state.agents.lock().unwrap());
    let mut summary = session_summary(&recent, quieted_count);
    apply_agent_summary(
        &mut summary,
        &agents,
        active,
        &state.runtime.lock().unwrap(),
    );
    let status = Status {
        active,
        header: compute_header(&snap, active, &agents),
        event_count: count,
        quiet,
        paused,
        summary,
        agents,
        recent,
    };
    if reset {
        let _ = app.emit("events-updated", ());
        let _ = app.emit("status-changed", ());
    }
    status
}

#[tauri::command]
fn get_app_settings(state: State<AppState>) -> AppSettings {
    state.app_settings.lock().unwrap().clone()
}

#[tauri::command]
fn set_network_sensor_disabled(
    disabled: bool,
    state: State<AppState>,
    app: AppHandle,
) -> Result<AppSettingsUpdate, String> {
    let mut settings = {
        let mut guard = state.app_settings.lock().unwrap();
        guard.network_sensor_disabled = disabled;
        guard.schema = "agentsnitch.ui_settings.v0".into();
        guard.clone()
    };
    save_app_settings(&settings)?;

    let mut warning = None;
    let detail = if disabled {
        match set_macos_network_sensor_disabled(true) {
            Ok(detail) => detail,
            Err(err) => {
                warning = Some(err.clone());
                format!(
                    "network sensor disabled setting saved; live disable failed: {}",
                    err
                )
            }
        }
    } else {
        match set_macos_network_sensor_disabled(false) {
            Ok(detail) => {
                request_network_extension_activation();
                detail
            }
            Err(err) => {
                warning = Some(err.clone());
                format!(
                    "network sensor enabled setting saved; live enable failed: {}",
                    err
                )
            }
        }
    };

    settings = state.app_settings.lock().unwrap().clone();
    let _ = app.emit("settings-changed", &settings);
    Ok(AppSettingsUpdate {
        settings,
        detail,
        warning,
    })
}

#[cfg(target_os = "macos")]
fn set_macos_network_sensor_disabled(disabled: bool) -> Result<String, String> {
    macos_ne_bridge::set_network_sensor_disabled(disabled)
}

#[cfg(not(target_os = "macos"))]
fn set_macos_network_sensor_disabled(_disabled: bool) -> Result<String, String> {
    Ok("network sensor setting saved; Network Extension is macOS-only".into())
}

#[tauri::command]
fn resize_main_window(app: AppHandle, width: f64, height: f64) -> Result<(), String> {
    let win = app
        .get_webview_window("main")
        .ok_or_else(|| "main window not found".to_string())?;
    let width = width.clamp(520.0, 1180.0);
    let height = height.clamp(420.0, 920.0);
    win.set_size(Size::Logical(LogicalSize { width, height }))
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_session(state: State<AppState>, app: AppHandle) -> Result<(), String> {
    reset_session_state(&state);
    refresh_tray(&app, false);
    let _ = app.emit("events-updated", ());
    let _ = app.emit("status-changed", ());
    Ok(())
}

#[tauri::command]
fn quiet_session(state: State<AppState>, app: AppHandle) -> Result<(), String> {
    *state.active.lock().unwrap() = false;
    *state.quiet.lock().unwrap() = true;
    refresh_tray(&app, false);
    let _ = app.emit("events-updated", ());
    let _ = app.emit("status-changed", ());
    hide_panel(&app);
    Ok(())
}

/// Toggle Pause (halt sensing) / Live (resume). Pause is distinct from Quiet
/// (which keeps sensing and only suppresses known-low-risk noise) and Clear (which
/// wipes the view). While paused the daemon stops observing and recording; the UI
/// freezes live updates and shows a loud banner. The daemon writes a pause_gap
/// record on resume so the halted window is recorded as an explicit gap.
#[tauri::command]
fn set_paused(paused: bool, state: State<AppState>, app: AppHandle) -> Result<bool, String> {
    {
        let guard = state.paused.lock().unwrap();
        if *guard == paused {
            return Ok(paused); // no-op; already in this state
        }
    }
    // Signal the daemon FIRST and only commit the UI state on success. If we cannot
    // even reach the daemon, committing "paused" would be a lie: the banner/tray
    // would report sensing is halted and process_incoming_json would drop live
    // events, while the daemon keeps recording — a misleading frozen view. For a
    // tool whose whole promise is "never an invisible hole", the honest behavior on
    // failure is to leave the prior state and surface the error.
    let control = if paused { "pause" } else { "resume" };
    if let Err(e) = send_daemon_control(control) {
        return Err(format!(
            "daemon control {} failed; UI state unchanged: {}",
            control, e
        ));
    }
    *state.paused.lock().unwrap() = paused;
    let active = *state.active.lock().unwrap();
    refresh_tray(&app, active);
    let _ = app.emit("pause-changed", paused);
    let _ = app.emit("status-changed", ());
    Ok(paused)
}

#[tauri::command]
fn dismiss_event(id: u64, state: State<AppState>, app: AppHandle) -> Result<(), String> {
    let mut events = state.events.lock().unwrap();
    let before = events.len();
    events.retain(|ev| ev.id != id);
    if events.len() == before {
        return Err(format!("event {} not found", id));
    }
    drop(events);
    let _ = app.emit("events-updated", ());
    let _ = app.emit("status-changed", ());
    Ok(())
}

#[tauri::command]
fn quiet_pattern(id: u64, state: State<AppState>, app: AppHandle) -> Result<(), String> {
    let keys = {
        let events = state.events.lock().unwrap();
        let Some(event) = events.iter().find(|ev| ev.id == id) else {
            return Err(format!("event {} not found", id));
        };
        let keys = quieted_pattern_keys_for_card(event);
        if keys.is_empty() {
            return Err(format!("event {} has no linked pattern", id));
        }
        keys
    };

    {
        let mut quieted = state.quieted_patterns.lock().unwrap();
        for key in &keys {
            quieted.insert(key.clone());
        }
    }
    store_quiet_keys(&state, &keys, QuietScope::Project)?;
    let mut events = state.events.lock().unwrap();
    events.retain(|event| {
        linked_event_breaks_quiet(event)
            || !quieted_pattern_keys(event)
                .iter()
                .any(|event_key| keys.contains(event_key))
    });
    drop(events);
    let _ = app.emit("events-updated", ());
    let _ = app.emit("status-changed", ());
    Ok(())
}

#[tauri::command]
fn quiet_known_services(state: State<AppState>, app: AppHandle) -> Result<(), String> {
    let keys = known_service_quiet_keys();
    {
        let mut quieted = state.quieted_patterns.lock().unwrap();
        for key in &keys {
            quieted.insert(key.clone());
        }
    }
    store_quiet_keys(&state, &keys, QuietScope::Global)?;
    let mut events = state.events.lock().unwrap();
    events.retain(|event| {
        linked_event_breaks_quiet(event)
            || !quieted_pattern_keys(event)
                .iter()
                .any(|event_key| keys.contains(event_key))
    });
    drop(events);
    let _ = app.emit("events-updated", ());
    let _ = app.emit("status-changed", ());
    Ok(())
}

#[tauri::command]
fn quiet_category(category: String, state: State<AppState>, app: AppHandle) -> Result<(), String> {
    if !known_quiet_category(&category) {
        return Err(format!("{} is not a quietable category", category));
    }
    let keys = vec![format!("category:{}", normalize_pattern_piece(&category))];
    {
        let mut quieted = state.quieted_patterns.lock().unwrap();
        for key in &keys {
            quieted.insert(key.clone());
        }
    }
    store_quiet_keys(&state, &keys, QuietScope::Global)?;
    let mut events = state.events.lock().unwrap();
    events.retain(|event| {
        linked_event_breaks_quiet(event)
            || !quieted_pattern_keys(event)
                .iter()
                .any(|event_key| keys.contains(event_key))
    });
    drop(events);
    let _ = app.emit("events-updated", ());
    let _ = app.emit("status-changed", ());
    Ok(())
}

#[tauri::command]
fn export_transcript(state: State<AppState>) -> Result<String, String> {
    build_export_transcript(&state)
}

fn build_export_transcript(state: &AppState) -> Result<String, String> {
    let evs = state.events.lock().unwrap().clone();
    let active = *state.active.lock().unwrap();
    let quiet = *state.quiet.lock().unwrap();
    let session = state.session.lock().unwrap().clone();
    let quieted_count = state.quieted_patterns.lock().unwrap().len();
    let agents = sorted_agents(&state.agents.lock().unwrap());
    let runtime = state.runtime.lock().unwrap().clone();
    let mut summary = session_summary(&evs, quieted_count);
    apply_agent_summary(&mut summary, &agents, active, &runtime);
    let mut out = Vec::new();
    out.push(
        serde_json::to_string(&export_header(
            &evs, active, quiet, &session, &agents, summary,
        ))
        .map_err(|e| e.to_string())?,
    );
    for e in &evs {
        out.push(serde_json::to_string(&export_record(e)).map_err(|e| e.to_string())?);
    }
    Ok(out.join("\n"))
}

#[tauri::command]
fn export_evidence_pack_file(state: State<AppState>) -> Result<String, String> {
    let text = build_export_transcript(&state)?;
    write_evidence_pack_file(&text)
}

fn evidence_pack_path() -> std::path::PathBuf {
    let base = std::env::var("AGENTSNITCH_EXPORT_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|_| {
            std::env::var("HOME").map(|home| std::path::Path::new(&home).join("Downloads"))
        })
        .unwrap_or_else(|_| std::env::temp_dir());
    let secs = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    base.join(format!("AgentSnitch-Evidence-Pack-{}.jsonl", secs))
}

fn write_evidence_pack_file(text: &str) -> Result<String, String> {
    let path = evidence_pack_path();
    if let Some(parent) = path.parent() {
        create_private_dir_all(parent).map_err(|err| err.to_string())?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|err| err.to_string())?;
        file.write_all(text.as_bytes())
            .map_err(|err| err.to_string())?;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    std::fs::write(&path, text).map_err(|err| err.to_string())?;
    Ok(path.to_string_lossy().into_owned())
}

fn export_header(
    events: &[UiEvent],
    active: bool,
    quiet: bool,
    session: &SessionSnapshot,
    agents: &[AgentInfo],
    summary: SessionSummary,
) -> serde_json::Value {
    let linked_count = events
        .iter()
        .filter(|event| event.correlated && event.evidence.is_some())
        .count();
    serde_json::json!({
        "schema": "agentsnitch.export.v0",
        "record_type": "session",
        "review_type": "evidence_pack",
        "title": "AgentSnitch Evidence Pack",
        "exported_at": export_timestamp(),
        "event_count": events.len(),
        "linked_count": linked_count,
        "active": active,
        "quiet": quiet,
        "session": session,
        "agents": agents,
        "summary": summary.clone(),
        "narrative": export_narrative(events, &summary),
        "timeline": export_timeline(events),
    })
}

fn session_summary(events: &[UiEvent], quieted_patterns: usize) -> SessionSummary {
    let mut summary = SessionSummary {
        quieted_patterns,
        ..SessionSummary::default()
    };
    let mut new_destinations = HashSet::new();
    let mut project_new_destinations = HashSet::new();
    let mut project_seen_destinations = HashSet::new();

    for event in events {
        let kind = event_kind(event);
        if kind == "linked" {
            summary.linked += 1;
        }
        if event_has_network_evidence(event) {
            summary.network += 1;
        }
        if ui_event_has_sensitive_context(event) {
            summary.sensitive_context += 1;
        }
        if ui_event_observer(event).is_some() {
            summary.observer_coverage += 1;
        }
        if let Some(context) = event.destination_context.as_ref() {
            let destination = ui_destination_for_memory(event).unwrap_or_default();
            if !destination.is_empty() {
                match context.state.as_str() {
                    "new_for_project" => {
                        project_new_destinations.insert(destination);
                    }
                    "seen_before_project" => {
                        project_seen_destinations.insert(destination);
                    }
                    _ => {}
                }
            }
        }

        let evidence = event.evidence.as_ref();
        if let Some(evidence) = evidence {
            if linked_event_breaks_quiet(event) {
                summary.high_signal += 1;
            }
            match evidence.destination_category.as_str() {
                "known Claude service" | "Playwright bridge traffic" => {
                    summary.known_claude_traffic += 1
                }
                "telemetry/logging" => summary.telemetry_traffic += 1,
                "local dev server bridge" | "local dev server" | "local dev tunnel" => {
                    summary.local_bridge_traffic += 1
                }
                "package registry" => summary.package_registry_traffic += 1,
                "unknown external" | "cloud provider" if !evidence.destination.is_empty() => {
                    new_destinations.insert(destination_memory_key(&evidence.destination));
                }
                _ => {}
            }
            continue;
        }

        if let Some(destination) = event
            .destination
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            let host = destination_memory_key(destination);
            match destination_category_for_host(&host).as_deref() {
                Some("known Claude service" | "Playwright bridge traffic") => {
                    summary.known_claude_traffic += 1
                }
                Some("telemetry/logging") => summary.telemetry_traffic += 1,
                Some("local dev server bridge" | "local dev server" | "local dev tunnel") => {
                    summary.local_bridge_traffic += 1
                }
                Some("package registry") => summary.package_registry_traffic += 1,
                _ => {
                    new_destinations.insert(destination_memory_key(&host));
                }
            }
        }
    }

    let mut samples = new_destinations
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    samples.sort();
    summary.new_destinations = samples.len();
    summary.new_destination_samples = samples.into_iter().take(3).collect();
    summary.project_new_destinations = project_new_destinations.len();
    summary.project_seen_destinations = project_seen_destinations.len();
    summary
}

fn apply_agent_summary(
    summary: &mut SessionSummary,
    agents: &[AgentInfo],
    active: bool,
    runtime: &SessionRuntime,
) {
    let process_count = agents.iter().filter(|agent| agent.pid.is_some()).count();
    summary.agent_processes = if process_count > 0 {
        process_count
    } else if active && runtime.agent_process_running {
        1
    } else {
        0
    };
}

fn ui_event_has_sensitive_context(event: &UiEvent) -> bool {
    event.tags.iter().any(|tag| {
        let tag = tag.to_ascii_lowercase();
        tag.contains("sensitive") || tag.contains("credential") || tag.contains("secret")
    }) || event
        .evidence
        .as_ref()
        .map(|evidence| {
            evidence
                .why
                .iter()
                .any(|reason| reason == "after_sensitive_read")
                || evidence.risk == "high"
                || evidence.severity == "hot"
                || evidence
                    .details
                    .iter()
                    .any(|detail| detail.value.to_ascii_lowercase().contains("sensitive"))
        })
        .unwrap_or(false)
}

fn ui_event_observer(event: &UiEvent) -> Option<String> {
    event
        .evidence
        .as_ref()
        .and_then(|evidence| {
            evidence
                .destination_provenance
                .iter()
                .chain(evidence.details.iter())
                .find(|detail| detail.label == "Observer")
                .map(|detail| detail.value.clone())
        })
        .or_else(|| {
            event.detail.as_deref().and_then(|detail| {
                detail.split(" • ").find_map(|part| {
                    let (key, value) = part.split_once(':')?;
                    if key.trim().eq_ignore_ascii_case("source") {
                        let value = value.trim();
                        if !value.is_empty() {
                            return Some(value.to_string());
                        }
                    }
                    None
                })
            })
        })
}

fn export_narrative(events: &[UiEvent], summary: &SessionSummary) -> serde_json::Value {
    let top_destinations = events
        .iter()
        .filter_map(|event| event.destination.as_deref())
        .filter(|destination| !destination.is_empty())
        .take(6)
        .collect::<Vec<_>>();
    let new_destinations = if summary.project_new_destinations > 0 {
        summary.project_new_destinations
    } else {
        summary.new_destinations
    };
    serde_json::json!({
        "headline": format!(
            "{} linked evidence cards, {} sensitive-context events, {} new destinations",
            summary.linked, summary.sensitive_context, new_destinations
        ),
        "triage_focus": if summary.high_signal > 0 { "attention" } else { "routine review" },
        "top_destinations": top_destinations,
    })
}

fn export_timeline(events: &[UiEvent]) -> Vec<serde_json::Value> {
    events
        .iter()
        .map(|event| {
            serde_json::json!({
                "ts": event.ts,
                "kind": event_kind(event),
                "summary": event.summary,
                "destination": event.destination.clone(),
                "destination_context": event.destination_context.clone(),
                "risk": event.evidence.as_ref().map(|evidence| evidence.risk.as_str()).unwrap_or("low"),
            })
        })
        .collect()
}

fn event_kind(event: &UiEvent) -> &'static str {
    if event.correlated && event.evidence.is_some() {
        "linked"
    } else if event.tags.iter().any(|tag| tag == "network_egress") {
        "network"
    } else {
        "hook"
    }
}

fn event_has_network_evidence(event: &UiEvent) -> bool {
    event_kind(event) == "network"
        || event
            .evidence
            .as_ref()
            .map(|evidence| !evidence.flow.is_empty() || !evidence.destination.is_empty())
            .unwrap_or(false)
}

fn ui_event_destination_category(event: &UiEvent) -> Option<String> {
    if let Some(evidence) = event.evidence.as_ref() {
        if !evidence.destination_category.is_empty() {
            return Some(evidence.destination_category.clone());
        }
    }
    let detail = event.detail.as_deref().unwrap_or("");
    detail.split(" • ").find_map(|part| {
        let (key, value) = part.split_once(':')?;
        if key.trim().eq_ignore_ascii_case("category") {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
        None
    })
}

fn export_record(e: &UiEvent) -> serde_json::Value {
    let kind = event_kind(e);
    let evidence = e.evidence.as_ref();
    let destination = e
        .destination
        .as_deref()
        .or_else(|| evidence.map(|ev| ev.destination.as_str()));
    serde_json::json!({
        "schema": "agentsnitch.export.v0",
        "record_type": "event",
        "id": e.id,
        "ts": e.ts,
        "kind": kind,
        "summary": e.summary,
        "tags": e.tags,
        "agent": e.agent,
        "detail": e.detail,
        "correlated": e.correlated,
        "severity": evidence.map(|ev| ev.severity.as_str()).unwrap_or("info"),
        "risk": evidence.map(|ev| ev.risk.as_str()).unwrap_or("low"),
        "decision": evidence.map(|ev| ev.decision.as_str()).unwrap_or("observed"),
        "destination": destination,
        "destination_context": e.destination_context.clone(),
        "destination_category": ui_event_destination_category(e),
        "why_human": evidence.map(|ev| ev.why_human.as_str()),
        "raw_reasons": evidence.map(|ev| ev.why.clone()).unwrap_or_default(),
        "evidence": evidence,
    })
}

fn export_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => format!("unix:{}", duration.as_secs()),
        Err(_) => "unix:0".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn app_settings_default_keeps_network_sensor_disabled() {
        let settings = AppSettings::default();
        assert!(settings.network_sensor_disabled);
        assert_eq!(settings.schema, "agentsnitch.ui_settings.v0");
    }

    #[test]
    fn network_sensor_env_kill_switch_forces_disabled_settings() {
        std::env::set_var("AGENTSNITCH_DISABLE_NETWORK_EXTENSION", "1");
        let settings = apply_network_sensor_env_override(AppSettings {
            schema: "agentsnitch.ui_settings.v0".into(),
            network_sensor_disabled: false,
        });
        std::env::remove_var("AGENTSNITCH_DISABLE_NETWORK_EXTENSION");

        assert!(settings.network_sensor_disabled);
    }

    #[test]
    fn embedded_heuristics_drive_destination_categories() {
        assert_eq!(
            destination_category_for_host("api.anthropic.com").as_deref(),
            Some("known Claude service")
        );
        assert_eq!(
            destination_category_for_host("160.79.104.10").as_deref(),
            Some("known Claude service")
        );
        assert_eq!(
            destination_category_for_host("registry.npmjs.com").as_deref(),
            Some("package registry")
        );
        assert_eq!(
            destination_category_for_host("17.46.190.35.bc.googleusercontent.com").as_deref(),
            Some("cloud provider")
        );
        assert!(known_quiet_category("telemetry/logging"));
    }

    #[test]
    fn event_schema_covers_rust_wire_structs() {
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/agentsnitch.event.schema.json"
        ))
        .unwrap();

        assert_schema_properties(
            &schema,
            "NetworkFlowEvent",
            &[
                "schema",
                "ts",
                "agent",
                "flow_id",
                "observer",
                "pid",
                "ppid",
                "process_path",
                "process_bundle_id",
                "process_team_id",
                "signing_info",
                "local",
                "remote",
                "sni",
                "protocol",
                "direction",
                "bytes_out",
                "bytes_in",
                "state",
            ],
        );
        assert_schema_properties(
            &schema,
            "SemanticEvent",
            &[
                "schema",
                "ts",
                "agent",
                "session",
                "event",
                "tool",
                "target",
                "cwd",
                "pid",
                "ppid",
                "tags",
                "destination_intents",
                "tool_use_id",
                "input_summary",
                "output_summary",
                "raw_ref",
            ],
        );
        assert_schema_properties(
            &schema,
            "AgentInfo",
            &[
                "id",
                "type",
                "name",
                "pid",
                "parent_agent_id",
                "spawn_method",
                "first_seen",
                "last_seen",
                "cwd",
                "version",
            ],
        );
    }

    fn assert_schema_properties(schema: &serde_json::Value, name: &str, expected: &[&str]) {
        let properties = schema["$defs"][name]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("schema definition {} missing properties", name));
        let actual = properties
            .keys()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        let expected = expected.iter().copied().collect::<HashSet<_>>();
        assert_eq!(actual, expected, "{} properties differ", name);
    }

    fn semantic(tool: &str, tags: Vec<&str>) -> SemanticEvent {
        SemanticEvent {
            schema: "agentsnitch.semantic.v0".into(),
            ts: "2026-06-02T21:00:00Z".into(),
            agent: AgentInfo {
                id: "claude".into(),
                name: "Claude Code".into(),
                version: None,
                ..AgentInfo::default()
            },
            session: SessionInfo {
                id: "session-1".into(),
            },
            event: "PreToolUse".into(),
            tool: tool.into(),
            target: None,
            cwd: Some("/tmp/project".into()),
            pid: 123,
            ppid: Some(122),
            tags: Some(tags.into_iter().map(String::from).collect()),
            destination_intents: None,
            tool_use_id: Some("toolu-1".into()),
            input_summary: Some(serde_json::json!({})),
            output_summary: None,
            raw_ref: None,
        }
    }

    fn linked_fixture(title: &str, destination: &str, severity: &str) -> LinkedEvidence {
        let risk = if severity == "hot" { "high" } else { severity };
        LinkedEvidence {
            title: title.into(),
            semantic: "Claude Code used mcp__playwright__browser_screenshot".into(),
            flow: format!("PID 123 connected to {}:443", destination),
            why: vec!["within_10s".into()],
            why_human: "Matched because: within 10 seconds.".into(),
            destination: destination.into(),
            destination_category: "unknown external".into(),
            destination_provenance: vec![],
            severity: severity.into(),
            risk: risk.into(),
            review_status: "Review".into(),
            review_subtitle: "medium-confidence link within 10 seconds".into(),
            decision: "observed".into(),
            details: vec![],
            replay: vec![],
            process_tree: vec![],
            confidence: "medium".into(),
            score: 0.85,
        }
    }

    #[test]
    fn semantic_schema_is_not_routed_as_agent_lifecycle() {
        let body = serde_json::to_string(&semantic("Agent", vec![])).unwrap();
        assert_eq!(
            message_schema(&body).as_deref(),
            Some("agentsnitch.semantic.v0")
        );
        assert!(!is_agent_lifecycle_message(&body));
        assert!(serde_json::from_str::<AgentLifecycleEvent>(&body).is_err());
    }

    #[test]
    fn agent_schema_is_routed_as_agent_lifecycle() {
        let body = serde_json::json!({
            "schema": "agentsnitch.agent.v0",
            "ts": "2026-06-03T18:34:06Z",
            "event": "new_subagent",
            "agent": {
                "id": "subhook_toolu_017A7jYHiDxn5K8M6mvYT3QL",
                "type": "sub",
                "name": "Audit Connect/Teams/Members",
                "pid": 300,
                "parent_agent_id": "main_100",
                "spawn_method": "hook"
            }
        })
        .to_string();

        assert_eq!(
            message_schema(&body).as_deref(),
            Some("agentsnitch.agent.v0")
        );
        assert!(is_agent_lifecycle_message(&body));
        let ev = serde_json::from_str::<AgentLifecycleEvent>(&body).unwrap();
        assert_eq!(ev.agent.agent_type.as_deref(), Some("sub"));
        assert_eq!(ev.agent.name, "Audit Connect/Teams/Members");
    }

    #[test]
    fn ordinary_bash_is_not_marked_correlated_in_ui() {
        let ui = sem_to_ui(1, semantic("Bash", vec![]));
        assert!(!ui.correlated);
    }

    #[test]
    fn network_to_ui_prefers_destination_and_keeps_flow_context() {
        let ui = network_to_ui(
            3,
            NetworkFlowEvent {
                schema: "agentsnitch.network.v0".into(),
                ts: "2026-06-02T21:00:02Z".into(),
                agent: None,
                flow_id: Some("flow-1".into()),
                observer: Some("network_extension".into()),
                pid: Some(123),
                ppid: Some(122),
                process_path: Some("/opt/homebrew/bin/claude".into()),
                process_bundle_id: None,
                process_team_id: None,
                signing_info: None,
                local: None,
                remote: Some("93.184.216.34:443".into()),
                sni: Some("api.example.com".into()),
                protocol: Some("tcp".into()),
                direction: Some("out".into()),
                bytes_out: Some(128),
                bytes_in: Some(0),
                state: Some("new".into()),
            },
        );

        assert_eq!(
            ui.summary,
            "Network -> api.example.com (93.184.216.34:443) (pid 123)"
        );
        assert!(ui.tags.contains(&"network_egress".into()));
        assert!(ui.tags.contains(&"network_new".into()));
        assert!(ui.tags.contains(&"network_extension".into()));
        let detail = ui.detail.unwrap_or_default();
        assert!(detail.contains("remote: 93.184.216.34:443"));
        assert!(detail.contains("state: new"));
        assert!(detail.contains("process: claude"));
        assert!(detail.contains("category: unknown external"));
    }

    #[test]
    fn network_to_ui_categories_known_raw_ip_when_reverse_dns_is_unknown() {
        let ui = network_to_ui(
            5,
            NetworkFlowEvent {
                schema: "agentsnitch.network.v0".into(),
                ts: "2026-06-02T21:00:02Z".into(),
                agent: None,
                flow_id: Some("flow-claude".into()),
                observer: Some("lsof".into()),
                pid: Some(123),
                ppid: Some(122),
                process_path: Some("/opt/homebrew/bin/claude".into()),
                process_bundle_id: None,
                process_team_id: None,
                signing_info: None,
                local: None,
                remote: Some("160.79.104.10:443".into()),
                sni: Some("10.104.79.160.bc.example.invalid".into()),
                protocol: Some("tcp".into()),
                direction: Some("out".into()),
                bytes_out: None,
                bytes_in: None,
                state: Some("established".into()),
            },
        );

        assert_eq!(
            ui.destination.as_deref(),
            Some("10.104.79.160.bc.example.invalid (160.79.104.10:443)")
        );
        assert!(ui
            .detail
            .unwrap_or_default()
            .contains("category: known Claude service"));
    }

    #[test]
    fn network_to_ui_includes_known_destination_category_for_raw_ip() {
        let ui = network_to_ui(
            4,
            NetworkFlowEvent {
                schema: "agentsnitch.network.v0".into(),
                ts: "2026-06-02T21:00:02Z".into(),
                agent: None,
                flow_id: Some("flow-claude".into()),
                observer: Some("lsof".into()),
                pid: Some(123),
                ppid: Some(122),
                process_path: Some("/opt/homebrew/bin/claude".into()),
                process_bundle_id: None,
                process_team_id: None,
                signing_info: None,
                local: None,
                remote: Some("160.79.104.10:443".into()),
                sni: None,
                protocol: Some("tcp".into()),
                direction: Some("out".into()),
                bytes_out: None,
                bytes_in: None,
                state: Some("established".into()),
            },
        );

        assert_eq!(ui.destination.as_deref(), Some("160.79.104.10:443"));
        assert!(ui
            .detail
            .unwrap_or_default()
            .contains("category: known Claude service"));
    }

    #[test]
    fn explicit_egress_semantics_are_tagged_interesting_not_correlated_in_ui() {
        for ev in [
            semantic("Bash", vec!["external_egress_attempt"]),
            semantic("mcp__github__search_repositories", vec![]),
            semantic("WebFetch", vec![]),
            semantic("WebSearch", vec![]),
        ] {
            let ui = sem_to_ui(1, ev);
            assert!(!ui.correlated);
            assert!(ui.tags.iter().any(|tag| tag == "egress_like"));
        }
    }

    #[test]
    fn mcp_evidence_preserves_tool_name_when_target_is_empty() {
        let line = semantic_evidence_line(&semantic(
            "mcp__claude-in-chrome__browser_batch",
            vec!["mcp_tool_use"],
        ));
        assert_eq!(
            line,
            "Claude Code used mcp__claude-in-chrome__browser_batch"
        );
    }

    #[test]
    fn linked_evidence_title_surfaces_mcp_connector_and_action() {
        let sem = semantic(
            "mcp__claude_ai_Ideabrowser__get_founder_profile",
            vec!["mcp_tool_use"],
        );

        assert_eq!(
            linked_evidence_title(Some("Tool call → outbound connection: details"), Some(&sem)),
            "Ideabrowser Get Founder Profile → outbound connection"
        );
    }

    #[test]
    fn linked_evidence_title_preserves_specific_summary() {
        let sem = semantic(
            "mcp__claude_ai_Ideabrowser__get_founder_profile",
            vec!["mcp_tool_use"],
        );

        assert_eq!(
            linked_evidence_title(
                Some("Sensitive read → outbound connection: details"),
                Some(&sem)
            ),
            "Sensitive read → outbound connection"
        );
    }

    #[test]
    fn linked_evidence_translates_reasons_destination_and_severity() {
        let mut sem = semantic("Read", vec!["sensitive_read", "env_file"]);
        sem.target = Some("/tmp/project/.env".into());
        sem.input_summary = Some(serde_json::json!({"file_path": "/tmp/project/.env"}));
        let flow = NetworkFlowEvent {
            schema: "agentsnitch.network.v0".into(),
            ts: "2026-06-02T21:00:02Z".into(),
            agent: None,
            flow_id: Some("flow-1".into()),
            observer: Some("network_extension".into()),
            pid: Some(123),
            ppid: Some(122),
            process_path: Some("/Users/scott/.local/bin/claude".into()),
            process_bundle_id: None,
            process_team_id: None,
            signing_info: None,
            local: None,
            remote: Some("93.184.216.34:443".into()),
            sni: Some("api.example.com".into()),
            protocol: Some("tcp".into()),
            direction: Some("out".into()),
            bytes_out: Some(2048),
            bytes_in: Some(512),
            state: Some("new".into()),
        };
        let evidence = linked_evidence(
            Some("Sensitive read → outbound connection: details".into()),
            Some(&sem),
            Some(&flow),
            &[
                ProcessNode {
                    pid: 123,
                    ppid: Some(122),
                    name: Some("Read".into()),
                    source: Some("hook".into()),
                    role: Some("hook,flow".into()),
                },
                ProcessNode {
                    pid: 122,
                    ppid: Some(1),
                    name: Some("/opt/homebrew/bin/claude".into()),
                    source: Some("snapshot-ancestor".into()),
                    role: Some("hook_ancestor,flow_ancestor".into()),
                },
            ],
            &[
                "within_10s".into(),
                "pid_match".into(),
                "after_sensitive_read".into(),
            ],
            "high",
            0.95,
        );

        assert_eq!(evidence.severity, "hot");
        assert_eq!(evidence.risk, "high");
        assert_eq!(evidence.review_status, "Needs Review");
        assert_eq!(
            evidence.review_subtitle,
            "high-confidence link within 10 seconds"
        );
        assert_eq!(evidence.decision, "observed");
        assert_eq!(evidence.destination, "api.example.com (93.184.216.34:443)");
        assert!(evidence
            .destination_provenance
            .iter()
            .any(|detail| detail.label == "SNI / PTR host" && detail.value == "api.example.com"));
        assert!(evidence
            .destination_provenance
            .iter()
            .any(
                |detail| detail.label == "Observed endpoint" && detail.value == "93.184.216.34:443"
            ));
        assert!(evidence
            .destination_provenance
            .iter()
            .any(|detail| detail.label == "Observer" && detail.value == "network_extension"));
        assert!(evidence
            .destination_provenance
            .iter()
            .any(|detail| detail.label == "Category" && detail.value == "unknown external"));
        assert_eq!(
            evidence.why_human,
            "Matched because: within 10 seconds, same PID, after reading a sensitive file (.env)."
        );
        assert!(evidence
            .details
            .iter()
            .any(|detail| detail.label == "Bytes" && detail.value == "out 2048B / in 512B"));
        assert!(evidence.details.iter().any(
            |detail| detail.label == "Timing" && detail.value == "network flow 2.0s after hook"
        ));
        assert!(evidence
            .details
            .iter()
            .any(|detail| detail.label == "Process link"
                && detail.value
                    == "same PID: hook PID 123 (parent 122) -> network PID 123 (parent 122)"));
        assert!(evidence
            .details
            .iter()
            .any(|detail| detail.label == "Process tree"
                && detail
                    .value
                    .contains("pid 122 <- 1 claude [hook_ancestor,flow_ancestor]")));
        assert_eq!(evidence.process_tree.len(), 2);
        assert!(evidence
            .details
            .iter()
            .any(|detail| detail.label == "Correlation" && detail.value == "high 0.95"));
        assert!(evidence
            .replay
            .iter()
            .any(|detail| detail.label == "6. Decision" && detail.value.contains("observed")));
    }

    #[test]
    fn linked_evidence_prefers_semantic_destination_intent() {
        let mut sem = semantic("Bash", vec!["external_egress_attempt"]);
        sem.target = Some("curl https://webhook.site/example".into());
        sem.destination_intents = Some(vec!["webhook.site".into()]);
        let flow = NetworkFlowEvent {
            schema: "agentsnitch.network.v0".into(),
            ts: "2026-06-02T21:00:02Z".into(),
            agent: None,
            flow_id: Some("flow-1".into()),
            observer: Some("network_statistics".into()),
            pid: Some(123),
            ppid: Some(122),
            process_path: Some("/usr/bin/curl".into()),
            process_bundle_id: None,
            process_team_id: None,
            signing_info: None,
            local: None,
            remote: Some("93.184.216.34:443".into()),
            sni: None,
            protocol: Some("tcp".into()),
            direction: Some("out".into()),
            bytes_out: Some(42),
            bytes_in: Some(24),
            state: Some("established".into()),
        };

        let evidence = linked_evidence(
            Some("Tool call → outbound connection".into()),
            Some(&sem),
            Some(&flow),
            &[],
            &["within_10s".into(), "pid_match".into()],
            "high",
            1.0,
        );

        assert_eq!(evidence.destination, "webhook.site (93.184.216.34:443)");
        assert!(evidence
            .details
            .iter()
            .any(|detail| detail.label == "Destination intent" && detail.value == "webhook.site"));
    }

    #[test]
    fn linked_evidence_translates_common_agent_ancestor_reason() {
        let mut sem = semantic("Read", vec!["sensitive_read", "env_file"]);
        sem.target = Some("/tmp/project/.env".into());
        let flow = NetworkFlowEvent {
            schema: "agentsnitch.network.v0".into(),
            ts: "2026-06-02T21:00:02Z".into(),
            agent: None,
            flow_id: Some("flow-1".into()),
            observer: Some("network_extension".into()),
            pid: Some(300),
            ppid: Some(200),
            process_path: Some("/usr/bin/curl".into()),
            process_bundle_id: None,
            process_team_id: None,
            signing_info: None,
            local: None,
            remote: Some("93.184.216.34:443".into()),
            sni: None,
            protocol: Some("tcp".into()),
            direction: Some("out".into()),
            bytes_out: None,
            bytes_in: None,
            state: Some("new".into()),
        };

        let evidence = linked_evidence(
            None,
            Some(&sem),
            Some(&flow),
            &[],
            &[
                "within_10s".into(),
                "common_agent_ancestor".into(),
                "after_sensitive_read".into(),
            ],
            "medium",
            0.75,
        );

        assert_eq!(
            evidence.why_human,
            "Matched because: within 10 seconds, shared tracked agent ancestor, after reading a sensitive file (.env)."
        );
        assert!(evidence
            .details
            .iter()
            .any(|detail| detail.label == "Process link"
                && detail
                    .value
                    .starts_with("shared tracked agent ancestor: hook PID")));
    }

    #[test]
    fn destination_categories_reduce_known_service_noise() {
        let mut sem = semantic("mcp__playwright__browser_navigate", vec!["mcp_tool_use"]);
        sem.target = Some("http://localhost:5173/paste".into());
        let mut flow = NetworkFlowEvent {
            schema: "agentsnitch.network.v0".into(),
            ts: "2026-06-02T21:00:02Z".into(),
            agent: None,
            flow_id: Some("flow-1".into()),
            observer: Some("network_extension".into()),
            pid: Some(123),
            ppid: Some(122),
            process_path: Some("/usr/bin/curl".into()),
            process_bundle_id: None,
            process_team_id: None,
            signing_info: None,
            local: None,
            remote: Some("104.18.32.47:443".into()),
            sni: Some("bridge.claudeusercontent.com".into()),
            protocol: Some("tcp".into()),
            direction: Some("out".into()),
            bytes_out: Some(512),
            bytes_in: None,
            state: Some("new".into()),
        };

        assert_eq!(
            destination_category(
                Some(&sem),
                Some(&flow),
                "Local bridge → outbound connection"
            ),
            "local dev server bridge"
        );

        sem.target = None;
        assert_eq!(
            destination_category(Some(&sem), Some(&flow), "Tool call → outbound connection"),
            "Playwright bridge traffic"
        );

        flow.sni = Some("api.anthropic.com".into());
        assert_eq!(
            destination_category(None, Some(&flow), "Tool call → outbound connection"),
            "known Claude service"
        );
        flow.sni = None;
        flow.remote = Some("160.79.104.10:443".into());
        assert_eq!(
            destination_category(None, Some(&flow), "Tool call → outbound connection"),
            "known Claude service"
        );
        flow.remote = Some("104.18.32.47:443".into());
        flow.sni = Some("api.anthropic.com".into());
        flow.bytes_out = Some(72 * 1024 * 1024);
        assert_eq!(
            evidence_risk(
                Some(&sem),
                &["high_bytes".into()],
                Some(&flow),
                "known Claude service"
            ),
            "low"
        );

        flow.sni = Some("http-intake.logs.us5.datadoghq.com".into());
        assert_eq!(
            destination_category(None, Some(&flow), "Tool call → outbound connection"),
            "telemetry/logging"
        );

        flow.sni = Some("api.statsigapi.net".into());
        assert_eq!(
            destination_category(None, Some(&flow), "Tool call → outbound connection"),
            "telemetry/logging"
        );

        flow.sni = Some("registry.npmjs.com".into());
        assert_eq!(
            destination_category(None, Some(&flow), "Tool call → outbound connection"),
            "package registry"
        );

        flow.sni = Some("demo.ngrok-free.app".into());
        assert_eq!(
            destination_category(None, Some(&flow), "Tool call → outbound connection"),
            "local dev tunnel"
        );
        assert_eq!(
            evidence_risk(
                Some(&sem),
                &["within_10s".into()],
                Some(&flow),
                "local dev tunnel"
            ),
            "medium"
        );
    }

    #[test]
    fn session_summary_counts_known_safe_and_new_destinations() {
        let mut claude = linked_fixture(
            "Tool call → outbound connection",
            "api.anthropic.com",
            "medium",
        );
        claude.destination_category = "known Claude service".into();
        claude.risk = "low".into();
        let mut telemetry = linked_fixture(
            "Tool call → outbound connection",
            "http-intake.logs.us5.datadoghq.com",
            "medium",
        );
        telemetry.destination_category = "telemetry/logging".into();
        telemetry.risk = "low".into();
        let mut unknown = linked_fixture(
            "Tool call → outbound connection",
            "unseen.example.invalid",
            "medium",
        );
        unknown.destination_category = "unknown external".into();
        unknown.risk = "medium".into();
        let events = vec![
            UiEvent {
                id: 1,
                ts: "21:00:01".into(),
                summary: "Claude".into(),
                tags: vec!["correlated".into()],
                detail: None,
                destination: Some("api.anthropic.com".into()),
                destination_context: None,
                correlated: true,
                evidence: Some(claude),
                agent: None,
            },
            UiEvent {
                id: 2,
                ts: "21:00:02".into(),
                summary: "Telemetry".into(),
                tags: vec!["correlated".into()],
                detail: None,
                destination: Some("http-intake.logs.us5.datadoghq.com".into()),
                destination_context: None,
                correlated: true,
                evidence: Some(telemetry),
                agent: None,
            },
            UiEvent {
                id: 3,
                ts: "21:00:03".into(),
                summary: "Unknown".into(),
                tags: vec!["correlated".into()],
                detail: None,
                destination: Some("unseen.example.invalid".into()),
                destination_context: None,
                correlated: true,
                evidence: Some(unknown),
                agent: None,
            },
            UiEvent {
                id: 4,
                ts: "21:00:04".into(),
                summary: "Network".into(),
                tags: vec!["network_egress".into()],
                detail: None,
                destination: Some("registry.npmjs.com".into()),
                destination_context: None,
                correlated: false,
                evidence: None,
                agent: None,
            },
        ];

        let summary = session_summary(&events, 7);
        assert_eq!(summary.known_claude_traffic, 1);
        assert_eq!(summary.telemetry_traffic, 1);
        assert_eq!(summary.package_registry_traffic, 1);
        assert_eq!(summary.new_destinations, 1);
        assert_eq!(
            summary.new_destination_samples,
            vec!["unseen.example.invalid"]
        );
        assert_eq!(summary.linked, 3);
        assert_eq!(summary.network, 4);
        assert_eq!(summary.quieted_patterns, 7);
    }

    #[test]
    fn session_summary_dedupes_destination_display_variants() {
        let mut evidence = linked_fixture(
            "Tool call → outbound connection",
            "unseen.example.invalid (93.184.216.34:443)",
            "medium",
        );
        evidence.destination_category = "unknown external".into();
        let events = vec![
            UiEvent {
                id: 1,
                ts: "21:00:01".into(),
                summary: "Linked".into(),
                tags: vec!["correlated".into()],
                detail: None,
                destination: Some("unseen.example.invalid (93.184.216.34:443)".into()),
                destination_context: Some(DestinationContext {
                    project_key: "/tmp/project".into(),
                    state: "new_for_project".into(),
                    label: "new for this project".into(),
                    previous_count: 0,
                }),
                correlated: true,
                evidence: Some(evidence),
                agent: None,
            },
            UiEvent {
                id: 2,
                ts: "21:00:02".into(),
                summary: "Network".into(),
                tags: vec!["network_egress".into()],
                detail: None,
                destination: Some("unseen.example.invalid".into()),
                destination_context: Some(DestinationContext {
                    project_key: "/tmp/project".into(),
                    state: "new_for_project".into(),
                    label: "new for this project".into(),
                    previous_count: 0,
                }),
                correlated: false,
                evidence: None,
                agent: None,
            },
        ];

        let summary = session_summary(&events, 0);
        assert_eq!(summary.new_destinations, 1);
        assert_eq!(
            summary.new_destination_samples,
            vec!["unseen.example.invalid"]
        );
        assert_eq!(summary.project_new_destinations, 1);
    }

    #[cfg(unix)]
    #[test]
    fn ui_socket_line_reader_processes_newline_framed_events() {
        let mut reader = std::io::Cursor::new(
            b"\n{\"schema\":\"agentsnitch.semantic.v0\"}\n {\"schema\":\"agentsnitch.network.v0\"} \n",
        );
        let mut lines = Vec::new();

        process_ui_socket_lines(&mut reader, |line| lines.push(line.to_string())).unwrap();

        assert_eq!(
            lines,
            vec![
                "{\"schema\":\"agentsnitch.semantic.v0\"}",
                "{\"schema\":\"agentsnitch.network.v0\"}"
            ]
        );
    }

    #[test]
    fn effective_quieted_patterns_include_global_and_project_keys() {
        let mut prefs = QuietPreferences {
            schema: "agentsnitch.ui_quiet.v0".into(),
            global: HashSet::from(["category:known claude service".into()]),
            projects: HashMap::new(),
        };
        prefs.projects.insert(
            "/tmp/project".into(),
            HashSet::from(["tool_dest:mcp__playwright__browser_evaluate|api.example.com".into()]),
        );

        let keys = effective_quieted_patterns(
            &prefs,
            &SessionSnapshot {
                id: "session-1".into(),
                agent_name: "Claude Code".into(),
                cwd: "/tmp/project".into(),
                started_ts: "2026-06-02T21:00:00Z".into(),
            },
        );

        assert!(keys.contains("category:known claude service"));
        assert!(keys.contains("tool_dest:mcp__playwright__browser_evaluate|api.example.com"));
    }

    #[test]
    fn compute_header_uses_real_session_age() {
        let snap = SessionSnapshot {
            id: "session-1".into(),
            agent_name: "Claude Code".into(),
            cwd: "/tmp/frontend".into(),
            started_ts: "2026-06-03T22:00:00Z".into(),
        };
        let now = DateTime::parse_from_rfc3339("2026-06-03T22:13:20Z")
            .unwrap()
            .with_timezone(&Utc);

        assert_eq!(
            compute_header_at(&snap, true, now, false, 0),
            "Claude Code active in frontend • 13m"
        );
    }

    #[test]
    fn compute_header_does_not_fake_age_for_unparseable_start() {
        let snap = SessionSnapshot {
            id: "session-1".into(),
            agent_name: "Claude Code".into(),
            cwd: "/tmp/frontend".into(),
            started_ts: "not-a-timestamp".into(),
        };
        let now = DateTime::parse_from_rfc3339("2026-06-03T22:13:20Z")
            .unwrap()
            .with_timezone(&Utc);

        assert_eq!(
            compute_header_at(&snap, true, now, false, 0),
            "Claude Code active in frontend • active"
        );
    }

    #[test]
    fn compute_header_only_mentions_subagents_when_detected() {
        let snap = SessionSnapshot {
            id: "session-1".into(),
            agent_name: "claude".into(),
            cwd: "/tmp/agentsnitch".into(),
            started_ts: "2026-06-03T22:00:00Z".into(),
        };
        let now = DateTime::parse_from_rfc3339("2026-06-03T22:13:20Z")
            .unwrap()
            .with_timezone(&Utc);

        assert_eq!(
            compute_header_at(&snap, true, now, false, 0),
            "Claude Code active in agentsnitch • 13m"
        );
        assert_eq!(
            compute_header_at(&snap, true, now, true, 0),
            "Claude Code (subagents) active in agentsnitch • 13m"
        );
    }

    #[test]
    fn compute_header_pluralizes_when_multiple_projects_active() {
        let snap = SessionSnapshot {
            id: "session-1".into(),
            agent_name: "Claude Code".into(),
            cwd: "/tmp/frontend".into(),
            started_ts: "2026-06-03T22:00:00Z".into(),
        };
        let now = DateTime::parse_from_rfc3339("2026-06-03T22:13:20Z")
            .unwrap()
            .with_timezone(&Utc);

        // With >1 project, the single-folder name is replaced by "N projects" so
        // the header does not misleadingly claim only one project is active.
        assert_eq!(
            compute_header_at(&snap, true, now, false, 2),
            "Claude Code active in 2 projects • 13m"
        );
        // A single project keeps the folder name.
        assert_eq!(
            compute_header_at(&snap, true, now, false, 1),
            "Claude Code active in frontend • 13m"
        );
    }

    #[test]
    fn distinct_agent_projects_counts_main_folders_and_ignores_subs() {
        let agents = vec![
            AgentInfo {
                id: "main_1".into(),
                name: "claude".into(),
                agent_type: Some("main".into()),
                cwd: Some("/Users/me/github/agentsnitch".into()),
                ..AgentInfo::default()
            },
            AgentInfo {
                id: "main_2".into(),
                name: "claude".into(),
                agent_type: Some("main".into()),
                cwd: Some("/Users/me/github/sir".into()),
                ..AgentInfo::default()
            },
            // Same project as main_1 (trailing slash) — must not double-count.
            AgentInfo {
                id: "main_3".into(),
                name: "claude".into(),
                agent_type: Some("main".into()),
                cwd: Some("/Users/me/github/agentsnitch/".into()),
                ..AgentInfo::default()
            },
            // Subagent — ignored even with a distinct cwd.
            AgentInfo {
                id: "sub_1".into(),
                name: "QA login".into(),
                agent_type: Some("sub".into()),
                cwd: Some("/Users/me/github/other".into()),
                ..AgentInfo::default()
            },
            // Main with no cwd — ignored (cannot attribute a project).
            AgentInfo {
                id: "main_4".into(),
                name: "claude".into(),
                agent_type: Some("main".into()),
                ..AgentInfo::default()
            },
        ];
        assert_eq!(distinct_agent_projects(&agents), 2);
    }

    #[test]
    fn distinct_agent_projects_separates_same_basename_different_path() {
        // Two mains whose cwds share a folder name but live at different paths are
        // distinct projects; keying on the full cwd (not the basename) keeps the
        // count at 2 so the header pluralizes correctly.
        let agents = vec![
            AgentInfo {
                id: "main_1".into(),
                name: "claude".into(),
                agent_type: Some("main".into()),
                cwd: Some("/tmp/a/app".into()),
                ..AgentInfo::default()
            },
            AgentInfo {
                id: "main_2".into(),
                name: "claude".into(),
                agent_type: Some("main".into()),
                cwd: Some("/tmp/b/app".into()),
                ..AgentInfo::default()
            },
        ];
        assert_eq!(distinct_agent_projects(&agents), 2);
    }

    #[test]
    fn update_agent_registry_creates_inferred_parent_for_subagent() {
        let mut agents = HashMap::new();
        update_agent_registry(
            &mut agents,
            &AgentInfo {
                id: "subhook_toolu_123".into(),
                name: "Building Dashboard/Editor".into(),
                agent_type: Some("sub".into()),
                pid: Some(62677),
                parent_agent_id: Some("main_62674".into()),
                spawn_method: Some("hook".into()),
                cwd: Some("/tmp/project".into()),
                ..AgentInfo::default()
            },
        );

        let sub = agents.get("subhook_toolu_123").expect("sub-agent");
        assert_eq!(sub.agent_type.as_deref(), Some("sub"));
        assert_eq!(sub.parent_agent_id.as_deref(), Some("main_62674"));

        let parent = agents.get("main_62674").expect("inferred parent");
        assert_eq!(parent.agent_type.as_deref(), Some("main"));
        assert_eq!(parent.pid, Some(62674));
        assert_eq!(parent.spawn_method.as_deref(), Some("inferred"));
    }

    #[test]
    fn agent_process_classifier_tracks_cli_agents_not_desktop_or_self() {
        assert!(agent_process_line_matches_family(
            "123 /opt/homebrew/bin/claude /opt/homebrew/bin/claude",
            AgentFamily::Any
        ));
        assert!(agent_process_line_matches_family(
            "124 /opt/homebrew/bin/codex /opt/homebrew/bin/codex",
            AgentFamily::Any
        ));
        assert!(agent_process_line_matches_family(
            "125 /usr/bin/node node /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js",
            AgentFamily::Any
        ));
        assert!(!agent_process_line_matches_family(
            "126 /Applications/Claude.app/Contents/MacOS/Claude Claude",
            AgentFamily::Any
        ));
        assert!(!agent_process_line_matches_family(
            "127 /Applications/AgentSnitch.app/Contents/MacOS/agentsnitch-ui agentsnitch-ui",
            AgentFamily::Any
        ));
        assert!(!agent_process_line_matches_family(
            "128 /bin/grep grep claude",
            AgentFamily::Any
        ));
    }

    #[test]
    fn claude_process_classifier_keeps_desktop_out() {
        assert!(agent_process_line_matches_family(
            "123 /opt/homebrew/bin/claude /opt/homebrew/bin/claude",
            AgentFamily::Claude
        ));
        assert!(!agent_process_line_matches_family(
            "124 /opt/homebrew/bin/codex /opt/homebrew/bin/codex",
            AgentFamily::Claude
        ));
        assert!(!agent_process_line_matches_family(
            "126 /Applications/Claude.app/Contents/MacOS/Claude Claude",
            AgentFamily::Claude
        ));
    }

    #[test]
    fn session_process_check_is_agent_family_specific() {
        let lines = [
            "100 /Applications/Codex.app/Contents/MacOS/Codex /Applications/Codex.app/Contents/MacOS/Codex",
            "101 /Applications/Codex.app/Contents/Resources/codex /Applications/Codex.app/Contents/Resources/codex app-server",
            "102 /Applications/Claude.app/Contents/MacOS/Claude /Applications/Claude.app/Contents/MacOS/Claude",
            "103 /Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper --type=utility",
        ];
        assert!(!agent_process_lines_running_for_session(
            lines,
            AgentFamily::Claude
        ));

        let with_cli = [
            "100 /Applications/Codex.app/Contents/MacOS/Codex /Applications/Codex.app/Contents/MacOS/Codex",
            "200 /opt/homebrew/bin/claude /opt/homebrew/bin/claude",
        ];
        assert!(agent_process_lines_running_for_session(
            with_cli,
            AgentFamily::Claude
        ));
    }

    #[test]
    fn session_family_prefers_claude_session_over_running_codex() {
        let snap = SessionSnapshot {
            id: "session-1".into(),
            agent_name: "Claude Code (subagents)".into(),
            cwd: "/tmp/frontend".into(),
            started_ts: "2026-06-03T22:00:00Z".into(),
        };
        let agents = HashMap::from([(
            "claude".into(),
            AgentInfo {
                id: "claude".into(),
                name: "Claude Code".into(),
                agent_type: Some("main".into()),
                ..AgentInfo::default()
            },
        )]);

        assert_eq!(session_agent_family(&snap, &agents), AgentFamily::Claude);
    }

    #[test]
    fn session_activity_anchor_uses_session_start_for_existing_sessions() {
        let runtime = SessionRuntime::default();
        let snap = SessionSnapshot {
            id: "session-1".into(),
            agent_name: "Claude Code".into(),
            cwd: "/tmp/frontend".into(),
            started_ts: "2026-06-03T22:00:00Z".into(),
        };
        let anchor = session_activity_anchor(&runtime, &snap).unwrap();
        let expected = SystemTime::from(
            DateTime::parse_from_rfc3339("2026-06-03T22:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );

        assert_eq!(anchor, expected);
    }

    #[test]
    fn reset_session_state_returns_to_empty_idle() {
        let state = AppState::default();
        state.events.lock().unwrap().push(UiEvent {
            id: 1,
            ts: "21:00:01".into(),
            summary: "Hook".into(),
            tags: vec!["hook".into()],
            detail: None,
            destination: None,
            destination_context: None,
            correlated: false,
            evidence: None,
            agent: None,
        });
        state.agents.lock().unwrap().insert(
            "claude".into(),
            AgentInfo {
                id: "claude".into(),
                name: "Claude Code".into(),
                agent_type: Some("main".into()),
                ..AgentInfo::default()
            },
        );
        *state.active.lock().unwrap() = true;
        *state.next_id.lock().unwrap() = 7;
        state.runtime.lock().unwrap().last_agent_activity = Some(SystemTime::now());
        *state.session.lock().unwrap() = SessionSnapshot {
            id: "session-1".into(),
            agent_name: "Claude Code".into(),
            cwd: "/tmp/frontend".into(),
            started_ts: "2026-06-03T22:00:00Z".into(),
        };

        reset_session_state(&state);

        assert!(state.events.lock().unwrap().is_empty());
        assert!(state.agents.lock().unwrap().is_empty());
        assert!(!*state.active.lock().unwrap());
        assert_eq!(*state.next_id.lock().unwrap(), 0);
        assert!(state.session.lock().unwrap().id.is_empty());
        assert!(state.runtime.lock().unwrap().last_agent_activity.is_none());
    }

    #[test]
    fn export_record_includes_debuggable_evidence_fields() {
        let mut evidence = linked_fixture(
            "Sensitive read → outbound connection",
            "api.example.com",
            "hot",
        );
        evidence.semantic = "Claude Code read /tmp/project/.env".into();
        evidence.flow = "PID 123 connected to 93.184.216.34:443 (SNI: api.example.com)".into();
        evidence.why = vec!["within_10s".into(), "pid_match".into()];
        evidence.why_human = "Matched because: within 10 seconds, same PID.".into();
        evidence.destination_category = "known Claude service".into();
        evidence.risk = "high".into();
        evidence.details = vec![EvidenceDetail {
            label: "Raw reasons".into(),
            value: "within_10s, pid_match".into(),
        }];
        evidence.replay = vec![EvidenceDetail {
            label: "6. Decision".into(),
            value: "observed; correlation high 0.95".into(),
        }];
        evidence.process_tree = vec![ProcessNode {
            pid: 123,
            ppid: Some(122),
            name: Some("claude".into()),
            source: Some("network".into()),
            role: Some("hook,flow".into()),
        }];
        evidence.confidence = "high".into();
        evidence.score = 0.95;
        let record = export_record(&UiEvent {
            id: 7,
            ts: "21:00:02".into(),
            summary: "Sensitive read → outbound connection".into(),
            tags: vec!["correlated".into()],
            detail: None,
            destination: Some("api.example.com".into()),
            destination_context: None,
            correlated: true,
            evidence: Some(evidence),
            agent: None,
        });

        assert_eq!(record["kind"], "linked");
        assert_eq!(record["schema"], "agentsnitch.export.v0");
        assert_eq!(record["record_type"], "event");
        assert_eq!(record["severity"], "hot");
        assert_eq!(record["risk"], "high");
        assert_eq!(record["decision"], "observed");
        assert_eq!(record["destination"], "api.example.com");
        assert_eq!(record["destination_category"], "known Claude service");
        assert_eq!(
            record["why_human"],
            "Matched because: within 10 seconds, same PID."
        );
        assert_eq!(record["raw_reasons"][0], "within_10s");
        assert_eq!(record["evidence"]["details"][0]["label"], "Raw reasons");
        assert_eq!(record["evidence"]["replay"][0]["label"], "6. Decision");
        assert_eq!(record["evidence"]["process_tree"][0]["pid"], 123);
    }

    #[test]
    fn export_record_includes_raw_network_destination() {
        let event = network_to_ui(
            8,
            NetworkFlowEvent {
                schema: "agentsnitch.network.v0".into(),
                ts: "2026-06-02T21:00:02Z".into(),
                agent: None,
                flow_id: Some("flow-raw".into()),
                observer: Some("network_extension".into()),
                pid: Some(456),
                ppid: Some(122),
                process_path: Some("/usr/bin/curl".into()),
                process_bundle_id: None,
                process_team_id: None,
                signing_info: None,
                local: None,
                remote: Some("93.184.216.34:443".into()),
                sni: Some("example.com".into()),
                protocol: Some("tcp".into()),
                direction: Some("out".into()),
                bytes_out: Some(256),
                bytes_in: None,
                state: Some("new".into()),
            },
        );
        let record = export_record(&event);

        assert_eq!(record["kind"], "network");
        assert_eq!(record["destination"], "example.com (93.184.216.34:443)");
        assert_eq!(record["destination_category"], "unknown external");
        assert_eq!(record["severity"], "info");
        assert_eq!(record["raw_reasons"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn export_header_includes_session_context_for_harnesses() {
        let events = vec![
            UiEvent {
                id: 1,
                ts: "21:00:00".into(),
                summary: "Hook".into(),
                tags: vec![],
                detail: None,
                destination: None,
                destination_context: None,
                correlated: false,
                evidence: None,
                agent: None,
            },
            UiEvent {
                id: 2,
                ts: "21:00:02".into(),
                summary: "Linked".into(),
                tags: vec!["correlated".into()],
                detail: None,
                destination: Some("api.example.com".into()),
                destination_context: None,
                correlated: true,
                evidence: Some(linked_fixture(
                    "Sensitive read → outbound connection",
                    "api.example.com",
                    "hot",
                )),
                agent: None,
            },
        ];
        let snap = SessionSnapshot {
            id: "session-1".into(),
            agent_name: "Claude Code".into(),
            cwd: "/tmp/project".into(),
            started_ts: "2026-06-02T21:00:00Z".into(),
        };
        let mut summary = session_summary(&events, 3);
        apply_agent_summary(&mut summary, &[], true, &SessionRuntime::default());
        let header = export_header(&events, true, false, &snap, &[], summary);

        assert_eq!(header["schema"], "agentsnitch.export.v0");
        assert_eq!(header["record_type"], "session");
        assert_eq!(header["review_type"], "evidence_pack");
        assert_eq!(header["title"], "AgentSnitch Evidence Pack");
        assert_eq!(header["event_count"], 2);
        assert_eq!(header["linked_count"], 1);
        assert_eq!(header["active"], true);
        assert_eq!(header["quiet"], false);
        assert_eq!(header["session"]["id"], "session-1");
        assert_eq!(header["summary"]["linked"], 1);
        assert_eq!(header["summary"]["high_signal"], 1);
        assert_eq!(header["summary"]["quieted_patterns"], 3);
        assert!(header["narrative"]["headline"]
            .as_str()
            .unwrap()
            .contains("linked evidence cards"));
        assert_eq!(header["timeline"].as_array().unwrap().len(), 2);
        assert!(header["exported_at"].as_str().unwrap().starts_with("unix:"));
    }

    #[test]
    fn evidence_pack_file_writes_local_jsonl_export() {
        let dir = std::env::temp_dir().join(format!(
            "agentsnitch-export-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::env::set_var("AGENTSNITCH_EXPORT_DIR", &dir);
        let path = write_evidence_pack_file("{\"schema\":\"agentsnitch.export.v0\"}\n").unwrap();
        assert!(path.contains("AgentSnitch-Evidence-Pack-"));
        assert!(path.ends_with(".jsonl"));
        let got = std::fs::read_to_string(&path).unwrap();
        assert!(got.contains("agentsnitch.export.v0"));
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
        std::env::remove_var("AGENTSNITCH_EXPORT_DIR");
    }

    #[test]
    fn export_narrative_falls_back_to_session_new_destinations() {
        let summary = SessionSummary {
            new_destinations: 2,
            project_new_destinations: 0,
            linked: 0,
            sensitive_context: 0,
            ..SessionSummary::default()
        };
        let narrative = export_narrative(&[], &summary);
        assert!(narrative["headline"]
            .as_str()
            .unwrap()
            .contains("2 new destinations"));
    }

    #[test]
    fn quiet_breakthrough_only_allows_high_signal_linked_cards() {
        let mut hot = UiEvent {
            id: 1,
            ts: "21:00:02".into(),
            summary: "Sensitive read → outbound connection".into(),
            tags: vec!["correlated".into()],
            detail: None,
            destination: Some("api.example.com".into()),
            destination_context: None,
            correlated: true,
            evidence: Some(linked_fixture(
                "Sensitive read → outbound connection",
                "api.example.com",
                "hot",
            )),
            agent: None,
        };
        assert!(linked_event_breaks_quiet(&hot));

        let evidence = hot.evidence.as_mut().unwrap();
        evidence.title = "Tool call → outbound connection".into();
        evidence.severity = "medium".into();
        evidence.risk = "medium".into();
        evidence.confidence = "medium".into();
        evidence.score = 0.75;
        assert!(!linked_event_breaks_quiet(&hot));

        hot.evidence = None;
        assert!(!linked_event_breaks_quiet(&hot));
    }

    #[test]
    fn linked_pattern_key_uses_title_hook_tool_and_destination() {
        let event = UiEvent {
            id: 1,
            ts: "21:00:02".into(),
            summary: "Local bridge → outbound connection".into(),
            tags: vec!["correlated".into(), "confidence_medium".into()],
            detail: None,
            destination: Some("Example.COM".into()),
            destination_context: None,
            correlated: true,
            evidence: Some({
                let mut evidence = linked_fixture(
                    "Local bridge → outbound connection",
                    "Example.COM",
                    "medium",
                );
                evidence.semantic = "Claude Code used http://localhost:5173/paste".into();
                evidence.flow = "PID 123 connected to 93.184.216.34:443 (SNI: Example.COM)".into();
                evidence.why = vec!["within_10s".into(), "ancestor_match".into()];
                evidence.why_human =
                    "Matched because: within 10 seconds, same process tree.".into();
                evidence.details = vec![EvidenceDetail {
                    label: "Hook event".into(),
                    value: "PreToolUse mcp__playwright__browser_screenshot".into(),
                }];
                evidence.destination_category = "known Claude service".into();
                evidence.risk = "low".into();
                evidence
            }),
            agent: None,
        };

        assert_eq!(
            linked_pattern_key(&event).as_deref(),
            Some(
                "local bridge outbound connection|mcp__playwright__browser_screenshot|example.com"
            )
        );
    }

    #[test]
    fn quieted_pattern_suppresses_lower_signal_but_not_hot_breakthrough() {
        let mut event = UiEvent {
            id: 1,
            ts: "21:00:02".into(),
            summary: "Tool call → outbound connection".into(),
            tags: vec!["correlated".into(), "confidence_medium".into()],
            detail: None,
            destination: Some("api.example.com".into()),
            destination_context: None,
            correlated: true,
            evidence: Some({
                let mut evidence = linked_fixture(
                    "Tool call → outbound connection",
                    "api.example.com",
                    "medium",
                );
                evidence.why = vec!["within_10s".into(), "mcp_server_flow".into()];
                evidence.why_human = "Matched because: within 10 seconds, MCP server flow.".into();
                evidence.details = vec![EvidenceDetail {
                    label: "Hook event".into(),
                    value: "PreToolUse mcp__playwright__browser_screenshot".into(),
                }];
                evidence.destination_category = "known Claude service".into();
                evidence.risk = "low".into();
                evidence
            }),
            agent: None,
        };
        let mut quieted = HashSet::new();
        for key in quieted_pattern_keys_for_card(&event) {
            quieted.insert(key);
        }

        assert!(should_suppress_quieted_pattern(&event, &quieted));

        let mut sibling = event.clone();
        if let Some(evidence) = sibling.evidence.as_mut() {
            evidence.destination = "other.anthropic.com".into();
            evidence.destination_category = "known Claude service".into();
        }
        assert!(should_suppress_quieted_pattern(&sibling, &quieted));

        let evidence = event.evidence.as_mut().unwrap();
        evidence.title = "Sensitive read → outbound connection".into();
        evidence.severity = "hot".into();
        evidence.risk = "high".into();
        evidence.confidence = "high".into();
        evidence.score = 0.95;
        for key in quieted_pattern_keys_for_card(&event) {
            quieted.insert(key);
        }

        assert!(!should_suppress_quieted_pattern(&event, &quieted));
    }

    #[test]
    fn known_service_quiet_keys_suppress_known_service_cards_only() {
        let mut known = UiEvent {
            id: 1,
            ts: "21:00:02".into(),
            summary: "Tool call → outbound connection".into(),
            tags: vec!["correlated".into()],
            detail: None,
            destination: Some("api.anthropic.com".into()),
            destination_context: None,
            correlated: true,
            evidence: Some({
                let mut evidence = linked_fixture(
                    "Tool call → outbound connection",
                    "api.anthropic.com",
                    "medium",
                );
                evidence.destination_category = "known Claude service".into();
                evidence.risk = "low".into();
                evidence.details = vec![EvidenceDetail {
                    label: "Hook event".into(),
                    value: "PreToolUse mcp__playwright__browser_evaluate".into(),
                }];
                evidence
            }),
            agent: None,
        };
        let quieted = known_service_quiet_keys()
            .into_iter()
            .collect::<HashSet<_>>();
        assert!(should_suppress_quieted_pattern(&known, &quieted));

        let evidence = known.evidence.as_mut().unwrap();
        evidence.destination = "webhook.site".into();
        evidence.destination_category = "unknown external".into();
        evidence.risk = "medium".into();
        assert!(!should_suppress_quieted_pattern(&known, &quieted));
    }

    #[test]
    fn trim_ui_events_preserves_linked_evidence_before_routine_hooks() {
        let mut events = Vec::new();
        events.push(UiEvent {
            id: 1,
            ts: "00:00:01".into(),
            summary: "Linked evidence".into(),
            tags: vec!["correlated".into()],
            detail: None,
            destination: None,
            destination_context: None,
            correlated: true,
            evidence: None,
            agent: None,
        });
        for id in 2..=(MAX_UI_EVENTS as u64 + 25) {
            events.push(UiEvent {
                id,
                ts: "00:00:02".into(),
                summary: "Routine hook".into(),
                tags: vec![],
                detail: None,
                destination: None,
                destination_context: None,
                correlated: false,
                evidence: None,
                agent: None,
            });
        }

        trim_ui_events(&mut events);

        assert_eq!(events.len(), MAX_UI_EVENTS);
        assert!(events.iter().any(|ev| ev.id == 1 && ev.correlated));
    }

    #[test]
    fn ui_log_uses_configured_restricted_file() {
        let path = std::env::temp_dir().join(format!(
            "agentsnitch-ui-test-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::env::set_var("AGENTSNITCH_UI_LOG", &path);
        append_ui_log("hello");
        let got = std::fs::read_to_string(&path).unwrap();
        assert!(got.contains("hello"));
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_file(path);
        std::env::remove_var("AGENTSNITCH_UI_LOG");
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .menu(create_app_menu)
        .on_menu_event(handle_app_menu_event)
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            get_events,
            get_events_json,
            get_status,
            get_app_settings,
            set_network_sensor_disabled,
            resize_main_window,
            clear_session,
            quiet_session,
            set_paused,
            dismiss_event,
            quiet_pattern,
            quiet_known_services,
            quiet_category,
            export_transcript,
            export_evidence_pack_file
        ])
        .setup(|app| {
            println!("AgentSnitch UI starting (tray + popup + event receiver)");

            let handle = app.handle().clone();
            if let Some(state) = handle.try_state::<AppState>() {
                let prefs = load_quiet_preferences();
                let effective = effective_quieted_patterns(&prefs, &SessionSnapshot::default());
                let settings = load_app_settings();
                let destination_memory = load_destination_memory();
                if let Err(err) = save_app_settings(&settings) {
                    eprintln!("[agentsnitch-ui] settings save failed: {}", err);
                }
                *state.quiet_preferences.lock().unwrap() = prefs;
                *state.quieted_patterns.lock().unwrap() = effective;
                *state.destination_memory.lock().unwrap() = destination_memory;
                *state.app_settings.lock().unwrap() = settings;
            }
            if let Err(e) = create_tray(&handle) {
                eprintln!("tray create failed: {}", e);
            }
            setup_window_behavior(&handle);

            let h2 = handle.clone();
            start_unix_socket_listener(h2);

            request_network_extension_activation();

            refresh_tray(&handle, false);

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            #[cfg(target_os = "macos")]
            if let RunEvent::Reopen { .. } = event {
                show_panel(app);
            }
            #[cfg(not(target_os = "macos"))]
            let _ = (app, event);
        });
}
