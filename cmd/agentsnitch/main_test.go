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
	paths := inspect.Paths{
		BaseDir:    t.TempDir(),
		CAPath:     filepath.Join(t.TempDir(), "ca.pem"),
		KeyPath:    filepath.Join(t.TempDir(), "ca-key.pem"),
		BundlePath: filepath.Join(t.TempDir(), "bundle.pem"),
		LeafDir:    filepath.Join(t.TempDir(), "leaf-cache"),
		DataDir:    filepath.Join(t.TempDir(), "payloads"),
	}
	paths.CAPath = filepath.Join(paths.BaseDir, "ca.pem")
	paths.KeyPath = filepath.Join(paths.BaseDir, "ca-key.pem")
	paths.BundlePath = filepath.Join(paths.BaseDir, "bundle.pem")
	paths.LeafDir = filepath.Join(paths.BaseDir, "leaf-cache")
	paths.DataDir = filepath.Join(paths.BaseDir, "payloads")

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
