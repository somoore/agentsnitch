package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Schema versions for wire stability.
const (
	SchemaSemanticV0      = "agentsnitch.semantic.v0"
	SchemaNetworkV0       = "agentsnitch.network.v0"
	SchemaCorrelatedV0    = "agentsnitch.correlated.v0"
	SchemaAgentV0         = "agentsnitch.agent.v0"
	SchemaInspectedHTTPV0 = "agentsnitch.inspected_http.v0"
	// SchemaControlV0 is a UI->daemon control message (e.g. pause/resume sensing).
	// It is not product evidence; it never produces a card.
	SchemaControlV0 = "agentsnitch.control.v0"
	// SchemaPauseGapV0 records an interval during which sensing was intentionally
	// halted (Pause). It is written to the transcript and forwarded to the UI so a
	// pause is recorded *as a gap* rather than an invisible hole in the record.
	SchemaPauseGapV0 = "agentsnitch.pause_gap.v0"
)

// Control actions carried by a ControlMessage.
const (
	ControlActionPause  = "pause"
	ControlActionResume = "resume"
)

// ControlMessage is a UI->daemon command sent over the daemon socket. The daemon
// trusts it only from the installed UI binary (same path check as network senders)
// and never treats it as agent evidence.
type ControlMessage struct {
	Schema string `json:"schema"`
	Action string `json:"action"`
}

// PauseGapEvent marks a window during which the daemon stopped sensing because the
// user engaged Pause. Anything an agent did during [From, To] was deliberately not
// observed or recorded; this event makes that gap explicit in the transcript and UI.
type PauseGapEvent struct {
	Schema      string    `json:"schema"`
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	DurationSec float64   `json:"duration_sec"`
}

// NewPauseGapEvent builds a PauseGapEvent for [from, to].
func NewPauseGapEvent(from, to time.Time) PauseGapEvent {
	if to.Before(from) {
		to = from
	}
	return PauseGapEvent{
		Schema:      SchemaPauseGapV0,
		From:        from.UTC(),
		To:          to.UTC(),
		DurationSec: to.Sub(from).Seconds(),
	}
}

// AgentInfo identifies the source AI coding agent.
type AgentInfo struct {
	ID            string    `json:"id"`
	Type          string    `json:"type,omitempty"`
	Name          string    `json:"name"`
	PID           int       `json:"pid,omitempty"`
	ParentAgentID string    `json:"parent_agent_id,omitempty"`
	SpawnMethod   string    `json:"spawn_method,omitempty"`
	FirstSeen     time.Time `json:"first_seen,omitempty"`
	LastSeen      time.Time `json:"last_seen,omitempty"`
	Cwd           string    `json:"cwd,omitempty"`
	Version       string    `json:"version,omitempty"`
}

func (a AgentInfo) MarshalJSON() ([]byte, error) {
	fields := map[string]interface{}{}
	if a.ID != "" {
		fields["id"] = a.ID
	}
	if a.Type != "" {
		fields["type"] = a.Type
	}
	if a.Name != "" {
		fields["name"] = a.Name
	}
	if a.PID > 0 {
		fields["pid"] = a.PID
	}
	if a.ParentAgentID != "" {
		fields["parent_agent_id"] = a.ParentAgentID
	}
	if a.SpawnMethod != "" {
		fields["spawn_method"] = a.SpawnMethod
	}
	if !a.FirstSeen.IsZero() {
		fields["first_seen"] = a.FirstSeen.UTC().Format(time.RFC3339Nano)
	}
	if !a.LastSeen.IsZero() {
		fields["last_seen"] = a.LastSeen.UTC().Format(time.RFC3339Nano)
	}
	if a.Cwd != "" {
		fields["cwd"] = a.Cwd
	}
	if a.Version != "" {
		fields["version"] = a.Version
	}
	return json.Marshal(fields)
}

// SessionInfo identifies the agent session (from hook payload when available).
type SessionInfo struct {
	ID string `json:"id,omitempty"`
}

// SemanticEvent is the normalized event emitted by the thin Hook Emitter
// for every hook invocation (PreToolUse, PostToolUse, etc.). It is a pure
// sensor signal — no policy or decision is attached.
//
// This is the primary data shape crossing the unix socket from emitter to
// daemon/correlator.
type SemanticEvent struct {
	Schema string `json:"schema"`

	TS time.Time `json:"ts"`

	Agent   AgentInfo   `json:"agent"`
	Session SessionInfo `json:"session"`

	// Event is the hook event name, e.g. "PreToolUse", "PostToolUse", "Stop".
	Event string `json:"event"`

	// Tool is the agent's tool name (normalized), e.g. "Read", "Bash", "mcp__...".
	Tool string `json:"tool,omitempty"`

	// Target is a best-effort primary target for the tool (file path for Read,
	// primary dest for network-ish, etc.). May be empty.
	Target string `json:"target,omitempty"`

	// CWD is the working directory at the time of the hook (from payload or enriched).
	CWD string `json:"cwd,omitempty"`

	// PID is the PID of the emitter process (child of the agent tree).
	// PPID is its parent (often the shell or agent child that invoked the hook).
	PID  int `json:"pid,omitempty"`
	PPID int `json:"ppid,omitempty"`

	// Tags are lightweight classification labels produced by internal/classify
	// (e.g. "sensitive_read", "external_egress_attempt", "mcp_tool_use").
	Tags []string `json:"tags,omitempty"`

	// DestinationIntents are hostnames/addresses implied by the tool input
	// before the OS network observer proves what the process actually did.
	DestinationIntents []string `json:"destination_intents,omitempty"`

	// ToolUseID is the agent's opaque identifier for this tool invocation (for correlation).
	ToolUseID string `json:"tool_use_id,omitempty"`

	// InputSummary is a redacted/summarized view of tool_input (never contains raw secrets).
	InputSummary map[string]interface{} `json:"input_summary,omitempty"`

	// OutputSummary is populated for PostToolUse (e.g. truncated output, markers found).
	OutputSummary map[string]interface{} `json:"output_summary,omitempty"`

	// RawRef is an optional pointer (e.g. into transcript) for debugging; never secrets.
	RawRef string `json:"raw_ref,omitempty"`
}

// MarshalJSON ensures ts is emitted as RFC3339 with subsecond precision
// and keeps the shape stable.
func (e SemanticEvent) MarshalJSON() ([]byte, error) {
	type alias struct {
		Schema        string                 `json:"schema"`
		TS            string                 `json:"ts"`
		Agent         AgentInfo              `json:"agent"`
		Session       SessionInfo            `json:"session"`
		Event         string                 `json:"event"`
		Tool          string                 `json:"tool"`
		Target        string                 `json:"target"`
		CWD           string                 `json:"cwd"`
		PID           int                    `json:"pid"`
		PPID          int                    `json:"ppid"`
		Tags          []string               `json:"tags"`
		Destinations  []string               `json:"destination_intents,omitempty"`
		ToolUseID     string                 `json:"tool_use_id"`
		InputSummary  map[string]interface{} `json:"input_summary"`
		OutputSummary map[string]interface{} `json:"output_summary,omitempty"`
		RawRef        string                 `json:"raw_ref,omitempty"`
	}
	tags := e.Tags
	if tags == nil {
		tags = []string{}
	}
	inputSummary := e.InputSummary
	if inputSummary == nil {
		inputSummary = map[string]interface{}{}
	}
	a := alias{
		Schema:        e.Schema,
		TS:            e.TS.UTC().Format(time.RFC3339Nano),
		Agent:         e.Agent,
		Session:       e.Session,
		Event:         e.Event,
		Tool:          e.Tool,
		Target:        e.Target,
		CWD:           e.CWD,
		PID:           e.PID,
		PPID:          e.PPID,
		Tags:          tags,
		Destinations:  e.DestinationIntents,
		ToolUseID:     e.ToolUseID,
		InputSummary:  inputSummary,
		OutputSummary: e.OutputSummary,
		RawRef:        e.RawRef,
	}
	return json.Marshal(a)
}

// String returns a compact human-readable summary for logs / dev-receiver.
func (e SemanticEvent) String() string {
	ts := e.TS.UTC().Format("15:04:05.000")
	agent := e.Agent.ID
	if e.Agent.Name != "" {
		agent = e.Agent.Name
	}
	summary := fmt.Sprintf("%s [%s] %s %s", ts, agent, e.Event, e.Tool)
	if e.Target != "" {
		summary += " " + e.Target
	}
	if len(e.Tags) > 0 {
		summary += " tags=" + fmt.Sprintf("%v", e.Tags)
	}
	if e.PID != 0 {
		summary += fmt.Sprintf(" pid=%d", e.PID)
	}
	if e.CWD != "" {
		summary += " cwd=" + e.CWD
	}
	return summary
}

// HumanSummary is an alias for String for clarity in UI/daemon layers.
func (e SemanticEvent) HumanSummary() string { return e.String() }

// NormalizeSemanticEvent fills daemon-safe defaults for semantic hook events.
func NormalizeSemanticEvent(e *SemanticEvent) {
	if e == nil {
		return
	}
	if e.Schema == "" {
		e.Schema = SchemaSemanticV0
	}
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	e.Agent.ID = strings.TrimSpace(e.Agent.ID)
	e.Agent.Type = strings.TrimSpace(e.Agent.Type)
	e.Agent.Name = strings.TrimSpace(e.Agent.Name)
	e.Agent.ParentAgentID = strings.TrimSpace(e.Agent.ParentAgentID)
	e.Agent.SpawnMethod = strings.TrimSpace(e.Agent.SpawnMethod)
	e.Agent.Cwd = strings.TrimSpace(e.Agent.Cwd)
	e.Session.ID = strings.TrimSpace(e.Session.ID)
	e.Event = strings.TrimSpace(e.Event)
	e.Tool = strings.TrimSpace(e.Tool)
	e.Target = strings.TrimSpace(e.Target)
	e.CWD = strings.TrimSpace(e.CWD)
	e.ToolUseID = strings.TrimSpace(e.ToolUseID)
	e.RawRef = strings.TrimSpace(e.RawRef)
	if e.Tags == nil {
		e.Tags = []string{}
	}
	e.DestinationIntents = normalizeStringSlice(e.DestinationIntents)
	if e.InputSummary == nil {
		e.InputSummary = map[string]interface{}{}
	}
}

func normalizeStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// ValidateSemanticEvent enforces the minimum real hook contract needed for
// explainable correlation. It validates sensor shape, not policy meaning.
func ValidateSemanticEvent(e SemanticEvent) error {
	if e.Schema != SchemaSemanticV0 {
		return fmt.Errorf("unsupported semantic schema %q", e.Schema)
	}
	if e.TS.IsZero() {
		return errors.New("semantic event missing timestamp")
	}
	if e.Agent.ID == "" {
		return errors.New("semantic event missing agent id")
	}
	if e.Session.ID == "" {
		return errors.New("semantic event missing session id")
	}
	if e.Event == "" {
		return errors.New("semantic event missing hook event name")
	}
	if e.Tool == "" {
		return errors.New("semantic event missing tool")
	}
	if e.CWD == "" {
		return errors.New("semantic event missing cwd")
	}
	if e.PID <= 0 {
		return errors.New("semantic event missing positive pid")
	}
	if e.PPID <= 0 {
		return errors.New("semantic event missing positive ppid")
	}
	if e.ToolUseID == "" {
		return errors.New("semantic event missing tool_use_id")
	}
	if e.Tags == nil {
		return errors.New("semantic event missing tags array")
	}
	if e.InputSummary == nil {
		return errors.New("semantic event missing input_summary")
	}
	return nil
}

// NetworkFlowEvent is the ground-truth flow record populated by the Network
// Extension or daemon observers.
type NetworkFlowEvent struct {
	Schema string    `json:"schema"`
	TS     time.Time `json:"ts"`

	Agent *AgentInfo `json:"agent,omitempty"`

	FlowID string `json:"flow_id,omitempty"`
	// Observer identifies the sensor path that produced this flow, e.g.
	// "network_extension" for NEFilterDataProvider, "network_statistics" for
	// nettop/NetworkStatistics, or "lsof" for the fallback.
	Observer string `json:"observer,omitempty"`

	PID             int    `json:"pid,omitempty"`
	PPID            int    `json:"ppid,omitempty"`
	ProcessPath     string `json:"process_path,omitempty"`
	ProcessBundleID string `json:"process_bundle_id,omitempty"`
	ProcessTeamID   string `json:"process_team_id,omitempty"`

	SigningInfo map[string]interface{} `json:"signing_info,omitempty"`

	Local  string `json:"local,omitempty"`
	Remote string `json:"remote,omitempty"`
	// SNI is only the TLS Server Name Indication captured by a sensor that can
	// observe it. Do not store reverse-DNS/PTR values here.
	SNI string `json:"sni,omitempty"`
	// Hostname is the strongest hostname attached to this flow, when the sensor
	// produced one directly. HostnameSource explains where it came from.
	Hostname       string `json:"hostname,omitempty"`
	HostnameSource string `json:"hostname_source,omitempty"`
	// PTRHostname is reverse-DNS owner metadata for the remote IP. It is a hint,
	// not proof that the connection was made to that DNS name.
	PTRHostname string `json:"ptr_hostname,omitempty"`

	Protocol  string `json:"protocol,omitempty"`  // tcp, udp
	Direction string `json:"direction,omitempty"` // in, out

	BytesOut int64 `json:"bytes_out,omitempty"`
	BytesIn  int64 `json:"bytes_in,omitempty"`

	State string `json:"state,omitempty"` // new, established, closed, ...
}

// NormalizeNetworkFlow fills daemon-safe defaults and canonicalizes low-cardinality
// fields before validation/correlation.
func NormalizeNetworkFlow(f *NetworkFlowEvent) {
	if f == nil {
		return
	}
	if f.Schema == "" {
		f.Schema = SchemaNetworkV0
	}
	if f.TS.IsZero() {
		f.TS = time.Now().UTC()
	}
	f.Protocol = strings.ToLower(strings.TrimSpace(f.Protocol))
	f.Direction = strings.ToLower(strings.TrimSpace(f.Direction))
	f.State = strings.ToLower(strings.TrimSpace(f.State))
	f.Remote = strings.TrimSpace(f.Remote)
	f.Local = strings.TrimSpace(f.Local)
	f.SNI = strings.TrimSpace(f.SNI)
	f.Hostname = strings.TrimSpace(f.Hostname)
	f.HostnameSource = strings.ToLower(strings.TrimSpace(f.HostnameSource))
	f.PTRHostname = strings.TrimSpace(f.PTRHostname)
	f.Observer = strings.ToLower(strings.TrimSpace(f.Observer))
	if f.Agent != nil {
		f.Agent.ID = strings.TrimSpace(f.Agent.ID)
		f.Agent.Type = strings.TrimSpace(f.Agent.Type)
		f.Agent.Name = strings.TrimSpace(f.Agent.Name)
		f.Agent.ParentAgentID = strings.TrimSpace(f.Agent.ParentAgentID)
		f.Agent.SpawnMethod = strings.TrimSpace(f.Agent.SpawnMethod)
		f.Agent.Cwd = strings.TrimSpace(f.Agent.Cwd)
		if f.Agent.ID == "" && f.Agent.Name == "" && f.Agent.PID == 0 {
			f.Agent = nil
		}
	}
	f.ProcessPath = strings.TrimSpace(f.ProcessPath)
	f.ProcessBundleID = strings.TrimSpace(f.ProcessBundleID)
	f.ProcessTeamID = strings.TrimSpace(f.ProcessTeamID)
	if f.ProcessPath == "" && f.SigningInfo != nil {
		f.ProcessPath = signingInfoString(f.SigningInfo, "path")
	}
	if f.ProcessBundleID == "" && f.SigningInfo != nil {
		f.ProcessBundleID = signingInfoString(f.SigningInfo, "identifier")
	}
	if f.ProcessTeamID == "" && f.SigningInfo != nil {
		f.ProcessTeamID = signingInfoString(f.SigningInfo, "team")
	}
}

func signingInfoString(info map[string]interface{}, key string) string {
	value, ok := info[key]
	if !ok || value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

// ValidateNetworkFlow enforces the minimum contract required for OS network
// truth to enter the daemon. It deliberately validates metadata shape only;
// whether a flow is interesting is a correlator decision.
func ValidateNetworkFlow(f NetworkFlowEvent) error {
	if f.Schema != SchemaNetworkV0 {
		return fmt.Errorf("unsupported network schema %q", f.Schema)
	}
	if f.PID <= 0 {
		return errors.New("network flow missing positive pid")
	}
	if !hasProcessIdentity(f) {
		return errors.New("network flow missing process path or bundle id")
	}
	if f.Remote == "" {
		return errors.New("network flow missing remote endpoint")
	}
	switch f.Protocol {
	case "tcp", "udp", "quic":
	default:
		return fmt.Errorf("unsupported network protocol %q", f.Protocol)
	}
	switch f.Direction {
	case "out", "in":
	default:
		return fmt.Errorf("unsupported network direction %q", f.Direction)
	}
	switch f.State {
	case "new", "established", "closed", "data":
	default:
		return fmt.Errorf("unsupported network state %q", f.State)
	}
	if f.BytesOut < 0 || f.BytesIn < 0 {
		return errors.New("network flow byte counts cannot be negative")
	}
	switch f.Observer {
	case "", "network_extension", "network_statistics", "lsof":
	default:
		return fmt.Errorf("unsupported network observer %q", f.Observer)
	}
	return nil
}

func hasProcessIdentity(f NetworkFlowEvent) bool {
	if f.ProcessBundleID != "" {
		return true
	}
	if f.ProcessPath == "" {
		return false
	}
	if f.Observer == "network_statistics" {
		return true
	}
	return strings.Contains(f.ProcessPath, "/")
}

// CorrelatedEvent is a derived record produced by the correlator/daemon
// linking one or more SemanticEvents with NetworkFlowEvents, plus an
// interestingness score and human reasons. Stub for Phase 1+.
type CorrelatedEvent struct {
	Schema string `json:"schema"`

	TS time.Time `json:"ts"`

	Agent *AgentInfo `json:"agent,omitempty"`

	SemanticIDs []string `json:"semantic_ids,omitempty"` // references to SemanticEvent.ToolUseID or derived hook IDs
	FlowIDs     []string `json:"flow_ids,omitempty"`

	Score      float64  `json:"score"`
	Confidence string   `json:"confidence,omitempty"`
	Reasons    []string `json:"reasons,omitempty"`

	Summary string `json:"summary,omitempty"`

	// Full embedded copies (or refs) for the session transcript.
	Semantics []SemanticEvent    `json:"semantics,omitempty"`
	Flows     []NetworkFlowEvent `json:"flows,omitempty"`

	// ProcessTree is a compact PID/PPID snippet around the linked hook and flow.
	// It is optional but useful for debugging why process-tree correlation fired.
	ProcessTree []ProcessNode `json:"process_tree,omitempty"`
}

// ProcessNode is a compact, local-only process graph node embedded in linked
// evidence records. Name is the best available executable/tool/process label.
type ProcessNode struct {
	PID    int    `json:"pid"`
	PPID   int    `json:"ppid,omitempty"`
	Name   string `json:"name,omitempty"`
	Source string `json:"source,omitempty"`
	Role   string `json:"role,omitempty"`
}

// AgentLifecycleEvent is a lightweight derived signal emitted when the daemon
// detects a main or sub-agent process for the current local session.
type AgentLifecycleEvent struct {
	Schema string    `json:"schema"`
	TS     time.Time `json:"ts"`
	Event  string    `json:"event"`
	Agent  AgentInfo `json:"agent"`
}

// InspectedHTTPExchange is local HTTPS Inspect Mode evidence. It is emitted only
// by the managed localhost proxy and is deliberately narrower than a raw packet
// capture: secret-bearing headers are redacted, body previews are retention-bound,
// and correlation language stays limited to what the proxy actually observed.
type InspectedHTTPExchange struct {
	Schema      string                   `json:"schema"`
	TS          time.Time                `json:"ts"`
	SessionID   string                   `json:"session_id,omitempty"`
	SpanID      string                   `json:"span_id,omitempty"`
	ToolUseID   string                   `json:"tool_use_id,omitempty"`
	Request     InspectedHTTPRequest     `json:"request"`
	Response    InspectedHTTPResponse    `json:"response"`
	TLS         InspectedHTTPTLS         `json:"tls"`
	Network     InspectedHTTPNetwork     `json:"network"`
	Retention   InspectedHTTPRetention   `json:"retention"`
	Correlation InspectedHTTPCorrelation `json:"correlation"`
}

type InspectedHTTPRequest struct {
	Method           string                `json:"method"`
	Scheme           string                `json:"scheme"`
	Host             string                `json:"host"`
	Path             string                `json:"path"`
	QueryRedacted    bool                  `json:"query_redacted"`
	Headers          []InspectedHTTPHeader `json:"headers"`
	ContentType      string                `json:"content_type,omitempty"`
	BodySize         int64                 `json:"body_size"`
	BodySHA256       string                `json:"body_sha256,omitempty"`
	Preview          string                `json:"preview,omitempty"`
	PreviewTruncated bool                  `json:"preview_truncated"`
	RedactionCount   int                   `json:"redaction_count"`
	PayloadRef       string                `json:"payload_ref,omitempty"`
}

type InspectedHTTPResponse struct {
	Status           int    `json:"status"`
	ContentType      string `json:"content_type,omitempty"`
	BodySize         int64  `json:"body_size"`
	BodySHA256       string `json:"body_sha256,omitempty"`
	Preview          string `json:"preview,omitempty"`
	PreviewTruncated bool   `json:"preview_truncated"`
	RedactionCount   int    `json:"redaction_count"`
	PayloadRef       string `json:"payload_ref,omitempty"`
}

type InspectedHTTPHeader struct {
	Name        string `json:"name"`
	Present     bool   `json:"present"`
	Redacted    bool   `json:"redacted"`
	ValueSHA256 string `json:"value_sha256,omitempty"`
	Preview     string `json:"preview,omitempty"`
}

type InspectedHTTPTLS struct {
	InspectionMode     string `json:"inspection_mode"`
	CAFingerprint      string `json:"ca_fingerprint,omitempty"`
	LeafCertGenerated  bool   `json:"leaf_cert_generated"`
	UpstreamTLSVersion string `json:"upstream_tls_version,omitempty"`
}

type InspectedHTTPNetwork struct {
	Remote     string `json:"remote,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	BytesOut   int64  `json:"bytes_out"`
	BytesIn    int64  `json:"bytes_in"`
	DurationMS int64  `json:"duration_ms"`
}

type InspectedHTTPRetention struct {
	PayloadMode       string `json:"payload_mode"`
	PreviewBytes      int    `json:"preview_bytes"`
	FullPayloadStored bool   `json:"full_payload_stored"`
	Retention         string `json:"retention"`
}

type InspectedHTTPCorrelation struct {
	Basis      []string `json:"basis"`
	Confidence string   `json:"confidence"`
}

// ValidateCorrelatedEvent enforces the linked-evidence contract shown by the UI
// and doctor. Correlation is a derived claim, so it must carry both source
// events, explain why they were linked, and avoid stronger language than the
// evidence supports.
func ValidateCorrelatedEvent(c CorrelatedEvent) error {
	if c.Schema != SchemaCorrelatedV0 {
		return fmt.Errorf("unsupported correlated schema %q", c.Schema)
	}
	if c.TS.IsZero() {
		return errors.New("correlated event missing timestamp")
	}
	if c.Score <= 0 || c.Score > 1 {
		return fmt.Errorf("correlated event score %f outside range (0,1]", c.Score)
	}
	switch c.Confidence {
	case "low", "medium", "high":
	default:
		return fmt.Errorf("unsupported correlated confidence %q", c.Confidence)
	}
	if len(c.Reasons) == 0 {
		return errors.New("correlated event missing reasons")
	}
	for _, reason := range c.Reasons {
		if strings.TrimSpace(reason) == "" {
			return errors.New("correlated event contains empty reason")
		}
	}
	if strings.TrimSpace(c.Summary) == "" {
		return errors.New("correlated event missing summary")
	}
	if usesOverclaimingLanguage(c.Summary) {
		return errors.New("correlated event summary uses overclaiming language")
	}
	if len(c.Semantics) == 0 {
		return errors.New("correlated event missing embedded semantic event")
	}
	if len(c.Flows) == 0 {
		return errors.New("correlated event missing embedded network flow")
	}
	for i, sem := range c.Semantics {
		NormalizeSemanticEvent(&sem)
		if err := ValidateSemanticEvent(sem); err != nil {
			return fmt.Errorf("correlated semantic[%d] invalid: %w", i, err)
		}
	}
	for i, flow := range c.Flows {
		NormalizeNetworkFlow(&flow)
		if err := ValidateNetworkFlow(flow); err != nil {
			return fmt.Errorf("correlated flow[%d] invalid: %w", i, err)
		}
	}
	return nil
}

func NormalizeInspectedHTTPExchange(x *InspectedHTTPExchange) {
	if x == nil {
		return
	}
	if x.Schema == "" {
		x.Schema = SchemaInspectedHTTPV0
	}
	if x.TS.IsZero() {
		x.TS = time.Now().UTC()
	}
	x.SessionID = strings.TrimSpace(x.SessionID)
	x.SpanID = strings.TrimSpace(x.SpanID)
	x.ToolUseID = strings.TrimSpace(x.ToolUseID)
	x.Request.Method = strings.ToUpper(strings.TrimSpace(x.Request.Method))
	x.Request.Scheme = strings.ToLower(strings.TrimSpace(x.Request.Scheme))
	x.Request.Host = strings.ToLower(strings.TrimSpace(x.Request.Host))
	x.Request.Path = strings.TrimSpace(x.Request.Path)
	x.Request.ContentType = strings.TrimSpace(x.Request.ContentType)
	x.Response.ContentType = strings.TrimSpace(x.Response.ContentType)
	x.Request.PayloadRef = strings.TrimSpace(x.Request.PayloadRef)
	x.Response.PayloadRef = strings.TrimSpace(x.Response.PayloadRef)
	x.TLS.InspectionMode = strings.TrimSpace(x.TLS.InspectionMode)
	x.TLS.CAFingerprint = strings.TrimSpace(x.TLS.CAFingerprint)
	x.TLS.UpstreamTLSVersion = strings.TrimSpace(x.TLS.UpstreamTLSVersion)
	x.Network.Remote = strings.TrimSpace(x.Network.Remote)
	x.Network.RemoteIP = strings.TrimSpace(x.Network.RemoteIP)
	x.Retention.PayloadMode = strings.TrimSpace(x.Retention.PayloadMode)
	x.Retention.Retention = strings.TrimSpace(x.Retention.Retention)
	x.Correlation.Confidence = strings.TrimSpace(x.Correlation.Confidence)
	x.Correlation.Basis = normalizeStringSlice(x.Correlation.Basis)
	for i := range x.Request.Headers {
		x.Request.Headers[i].Name = strings.ToLower(strings.TrimSpace(x.Request.Headers[i].Name))
	}
}

func ValidateInspectedHTTPExchange(x InspectedHTTPExchange) error {
	NormalizeInspectedHTTPExchange(&x)
	if x.Schema != SchemaInspectedHTTPV0 {
		return fmt.Errorf("unsupported inspected HTTP schema %q", x.Schema)
	}
	if x.TS.IsZero() {
		return errors.New("inspected HTTP exchange missing timestamp")
	}
	if x.Request.Method == "" {
		return errors.New("inspected HTTP exchange missing request method")
	}
	if x.Request.Scheme != "http" && x.Request.Scheme != "https" {
		return fmt.Errorf("unsupported inspected HTTP scheme %q", x.Request.Scheme)
	}
	if x.Request.Host == "" {
		return errors.New("inspected HTTP exchange missing request host")
	}
	if x.Request.Path == "" {
		return errors.New("inspected HTTP exchange missing request path")
	}
	if x.Request.BodySize < 0 || x.Response.BodySize < 0 {
		return errors.New("inspected HTTP exchange body sizes cannot be negative")
	}
	if x.Network.BytesOut < 0 || x.Network.BytesIn < 0 || x.Network.DurationMS < 0 {
		return errors.New("inspected HTTP exchange network metrics cannot be negative")
	}
	switch x.TLS.InspectionMode {
	case "metadata_only", "local_mitm", "trust_failed", "pinned_or_custom_trust", "unsupported_protocol":
	default:
		return fmt.Errorf("unsupported inspected HTTP TLS mode %q", x.TLS.InspectionMode)
	}
	switch x.Correlation.Confidence {
	case "low", "medium", "high":
	default:
		return fmt.Errorf("unsupported inspected HTTP confidence %q", x.Correlation.Confidence)
	}
	if len(x.Correlation.Basis) == 0 {
		return errors.New("inspected HTTP exchange missing correlation basis")
	}
	return nil
}

func usesOverclaimingLanguage(summary string) bool {
	lower := strings.ToLower(summary)
	for _, term := range []string{"exfiltrated", "exfiltration", "leaked", "stolen"} {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

// HasTag (added for correlator/daemon convenience; does not affect wire).
func (e SemanticEvent) HasTag(tag string) bool {
	for _, t := range e.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// IsEgressLike (added for correlator).
func (e SemanticEvent) IsEgressLike() bool {
	for _, t := range e.Tags {
		if t == "external_egress_attempt" || t == "mcp_tool_use" {
			return true
		}
	}
	if strings.HasPrefix(strings.ToLower(e.Tool), "mcp__") {
		return true
	}
	return e.Tool == "WebFetch" || e.Tool == "WebSearch"
}

// IsExternal (added for correlator; naive).
func (f NetworkFlowEvent) IsExternal() bool {
	if f.Remote == "" {
		return false
	}
	for _, bad := range []string{"127.0.0.1", "localhost", "::1", "[::1]"} {
		if strings.Contains(f.Remote, bad) {
			return false
		}
	}
	return true
}

// Correlation is a type alias to the current derived record for TryCorrelate.
type Correlation = CorrelatedEvent
