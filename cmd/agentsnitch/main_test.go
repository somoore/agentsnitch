package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/agentsnitch/internal/inspect"
)

func TestShellExportValueQuotesSingleQuotes(t *testing.T) {
	got := shellExportValue("alpha'beta")
	want := "'alpha'\\''beta'"
	if got != want {
		t.Fatalf("shellExportValue = %q, want %q", got, want)
	}
}

func TestInspectCertificateForCLIParsesGeneratedCA(t *testing.T) {
	base := t.TempDir()
	paths := inspect.Paths{
		BaseDir:    base,
		CAPath:     filepath.Join(base, "ca.pem"),
		KeyPath:    filepath.Join(base, "ca-key.pem"),
		BundlePath: filepath.Join(base, "bundle.pem"),
		LeafDir:    filepath.Join(base, "leaf-cache"),
		DataDir:    filepath.Join(base, "payloads"),
	}

	info, err := inspect.NewCertManager(paths).EnsureCA()
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	cert, err := inspectCertificateForCLI(paths.CAPath)
	if err != nil {
		t.Fatalf("inspectCertificateForCLI: %v", err)
	}
	if !strings.Contains(cert.Subject.String(), "AgentSnitch Local HTTPS Inspection CA") {
		t.Fatalf("unexpected cert subject: %s", cert.Subject.String())
	}
	if info.Fingerprint != inspect.Fingerprint(cert) {
		t.Fatalf("fingerprint mismatch")
	}
}

func TestInspectCertificateForCLIRejectsInvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
		t.Fatalf("write invalid pem: %v", err)
	}
	if _, err := inspectCertificateForCLI(path); err == nil {
		t.Fatal("expected invalid PEM to fail")
	}
}

func TestDisableInspectCleansProcessTrustAndPayloadData(t *testing.T) {
	base := t.TempDir()
	settingsPath := filepath.Join(base, "settings.json")
	inspectDir := filepath.Join(base, "inspect")
	t.Setenv("AGENTSNITCH_UI_SETTINGS", settingsPath)
	t.Setenv("AGENTSNITCH_INSPECT_DIR", inspectDir)

	settings := inspect.DefaultSettings()
	settings.HTTPSInspectEnabled = true
	settings.HTTPSInspectProcessScoped = true
	settings.HTTPSInspectCapturePreviews = true
	settings.HTTPSInspectCaptureFull = true
	if err := inspect.SaveSettings(settings); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	paths := inspect.DefaultPaths()
	if err := inspect.EnsureDirs(paths); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	if err := os.WriteFile(paths.BundlePath, []byte("bundle"), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	payloadPath := filepath.Join(paths.DataDir, "payload.json")
	if err := os.WriteFile(payloadPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	disableInspect([]string{"--remove-process-trust=true", "--purge-data=true"})

	got, err := inspect.LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if got.HTTPSInspectEnabled || got.HTTPSInspectCaptureFull {
		t.Fatalf("settings not disabled: %+v", got)
	}
	if _, err := os.Stat(paths.BundlePath); !os.IsNotExist(err) {
		t.Fatalf("bundle still exists or unexpected stat error: %v", err)
	}
	entries, err := os.ReadDir(paths.DataDir)
	if err != nil {
		t.Fatalf("read payload dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("payload dir entries = %d, want 0", len(entries))
	}
}
