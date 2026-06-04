package runtime

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/somoore/agentsnitch/internal/event"
)

func TestStatusRoundTripsWithRestrictivePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	t.Setenv("AGENTSNITCH_STATUS", path)

	now := time.Now().UTC()
	want := Status{
		DaemonStartedAt:    now,
		UpdatedAt:          now,
		LastTranscriptPath: filepath.Join(t.TempDir(), "events.jsonl"),
		LastTranscriptKind: "network",
		LastTranscriptAt:   now,
		LastNetwork: &event.NetworkFlowEvent{
			Schema:      event.SchemaNetworkV0,
			TS:          now,
			Observer:    "lsof",
			PID:         123,
			ProcessPath: "/usr/bin/curl",
			Remote:      "93.184.216.34:443",
			Protocol:    "tcp",
			Direction:   "out",
			State:       "new",
		},
	}

	if err := WriteStatus(want); err != nil {
		t.Fatalf("WriteStatus returned error: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("status permissions = %o, want 0600", got)
	}

	got, err := ReadStatus()
	if err != nil {
		t.Fatalf("ReadStatus returned error: %v", err)
	}
	if got.LastNetwork == nil || got.LastNetwork.Remote != want.LastNetwork.Remote {
		t.Fatalf("last network did not round-trip: %#v", got.LastNetwork)
	}
	if got.LastTranscriptPath != want.LastTranscriptPath || got.LastTranscriptKind != "network" {
		t.Fatalf("transcript metadata did not round-trip: %#v", got)
	}
}
