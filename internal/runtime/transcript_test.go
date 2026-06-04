package runtime

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTranscriptWriterAppendsJSONLWithRestrictivePermissions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENTSNITCH_TRANSCRIPTS_DIR", dir)

	writer := NewTranscriptWriter()
	if err := writer.Append("session/../../one", "semantic", map[string]string{"tool": "Read"}); err != nil {
		t.Fatalf("Append returned error: %v", err)
	}
	if err := writer.Append("session/../../one", "network", map[string]string{"remote": "93.184.216.34:443"}); err != nil {
		t.Fatalf("Append returned error: %v", err)
	}

	path := TranscriptPath("session/../../one")
	rel, err := filepath.Rel(dir, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("transcript path escaped dir: %s", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("transcript permissions = %o, want 0600", got)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
		var rec TranscriptRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatalf("line %d did not unmarshal: %v", count, err)
		}
		if rec.Schema != SchemaTranscriptV0 {
			t.Fatalf("line %d schema = %q", count, rec.Schema)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("line count = %d, want 2", count)
	}
}

func TestSafeSessionIDFallback(t *testing.T) {
	if got := safeSessionID("../../"); got != "unassigned" {
		t.Fatalf("safeSessionID fallback = %q", got)
	}
}
