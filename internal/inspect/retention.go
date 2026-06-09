package inspect

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/somoore/agentsnitch/internal/event"
)

type PayloadRecord struct {
	Schema    string     `json:"schema"`
	Captured  time.Time  `json:"captured_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Retention string     `json:"retention,omitempty"`
	SessionID string     `json:"session_id,omitempty"`
	SpanID    string     `json:"span_id,omitempty"`
	ToolUseID string     `json:"tool_use_id,omitempty"`
	Request   string     `json:"request_redacted_body"`
	Response  string     `json:"response_redacted_body"`
}

func StorePayloadRecord(paths Paths, exchange *event.InspectedHTTPExchange, requestBody, responseBody string) error {
	if exchange == nil {
		return nil
	}
	if err := EnsureDirs(paths); err != nil {
		return err
	}
	if err := PurgeExpiredPayloads(paths, time.Now().UTC()); err != nil {
		return err
	}
	id, err := payloadID()
	if err != nil {
		return err
	}
	ref := filepath.Join("payloads", id+".json")
	path := filepath.Join(paths.DataDir, id+".json")
	captured := time.Now().UTC()
	record := PayloadRecord{
		Schema:    "agentsnitch.inspect_payload.v0",
		Captured:  captured,
		ExpiresAt: payloadExpiry(captured, exchange.Retention.Retention),
		Retention: exchange.Retention.Retention,
		SessionID: exchange.SessionID,
		SpanID:    exchange.SpanID,
		ToolUseID: exchange.ToolUseID,
		Request:   requestBody,
		Response:  responseBody,
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	exchange.Request.PayloadRef = ref + "#request"
	exchange.Response.PayloadRef = ref + "#response"
	return nil
}

func PurgePayloadsForEndedSessions(paths Paths, sessionIDs []string) error {
	if len(sessionIDs) == 0 {
		return nil
	}
	sessionSet := make(map[string]struct{}, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		if sessionID != "" {
			sessionSet[sessionID] = struct{}{}
		}
	}
	if len(sessionSet) == 0 {
		return nil
	}
	entries, err := os.ReadDir(paths.DataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(paths.DataDir, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var record PayloadRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			continue
		}
		if record.Retention != FullPayloadUntilSession {
			continue
		}
		if _, ok := sessionSet[record.SessionID]; !ok {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func PurgeExpiredPayloads(paths Paths, now time.Time) error {
	entries, err := os.ReadDir(paths.DataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(paths.DataDir, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var record PayloadRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			continue
		}
		if record.ExpiresAt != nil && !record.ExpiresAt.After(now) {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

func payloadExpiry(captured time.Time, retention string) *time.Time {
	var expires time.Time
	switch retention {
	case FullPayloadOneHour:
		expires = captured.Add(time.Hour)
	case FullPayloadTwentyFour:
		expires = captured.Add(24 * time.Hour)
	default:
		return nil
	}
	return &expires
}

func payloadID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
