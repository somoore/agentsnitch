package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/somoore/agentsnitch/internal/event"
)

// Status is a daemon-written diagnostic snapshot used by doctor. It is not an
// ingestion path and must not be used to seed product events.
type Status struct {
	DaemonStartedAt time.Time `json:"daemon_started_at"`
	UpdatedAt       time.Time `json:"updated_at"`

	LastSemantic   *event.SemanticEvent    `json:"last_semantic,omitempty"`
	LastNetwork    *event.NetworkFlowEvent `json:"last_network,omitempty"`
	LastCorrelated *event.CorrelatedEvent  `json:"last_correlated,omitempty"`

	LastTranscriptPath string    `json:"last_transcript_path,omitempty"`
	LastTranscriptKind string    `json:"last_transcript_kind,omitempty"`
	LastTranscriptAt   time.Time `json:"last_transcript_at,omitempty"`
}

func StatusPath() string {
	if p := os.Getenv("AGENTSNITCH_STATUS"); p != "" {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dir := filepath.Join(home, ".agentsnitch")
		_ = os.MkdirAll(dir, 0o700)
		return filepath.Join(dir, "status.json")
	}
	return "/tmp/agentsnitch-status.json"
}

func ReadStatus() (Status, error) {
	raw, err := os.ReadFile(StatusPath())
	if err != nil {
		return Status{}, err
	}
	var status Status
	if err := json.Unmarshal(raw, &status); err != nil {
		return Status{}, err
	}
	return status, nil
}

func WriteStatus(status Status) error {
	path := StatusPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if status.UpdatedAt.IsZero() {
		status.UpdatedAt = time.Now().UTC()
	}
	raw, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".status-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Chmod(path, 0o600)
}
