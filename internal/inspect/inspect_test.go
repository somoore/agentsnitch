package inspect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/somoore/agentsnitch/internal/event"
)

// exchangeSink collects proxy callbacks safely: onEvent runs on the httptest
// server goroutine while the test goroutine reads, so the old bare slice was a
// data race under -race.
type exchangeSink struct {
	mu     sync.Mutex
	events []event.InspectedHTTPExchange
}

func (s *exchangeSink) add(exchange event.InspectedHTTPExchange) {
	s.mu.Lock()
	s.events = append(s.events, exchange)
	s.mu.Unlock()
}

func (s *exchangeSink) snapshot() []event.InspectedHTTPExchange {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]event.InspectedHTTPExchange, len(s.events))
	copy(out, s.events)
	return out
}

func (s *exchangeSink) waitFor(t *testing.T, count int) []event.InspectedHTTPExchange {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if events := s.snapshot(); len(events) >= count {
			return events
		}
		time.Sleep(10 * time.Millisecond)
	}
	return s.snapshot()
}

func testPaths(t *testing.T) Paths {
	t.Helper()
	base := t.TempDir()
	return Paths{
		BaseDir:    base,
		CAPath:     filepath.Join(base, "ca.pem"),
		KeyPath:    filepath.Join(base, "ca-key.pem"),
		BundlePath: filepath.Join(base, "process-scoped-ca-bundle.pem"),
		LeafDir:    filepath.Join(base, "leaf-cache"),
		DataDir:    filepath.Join(base, "payloads"),
	}
}

func TestCertManagerLifecycleAndPermissions(t *testing.T) {
	paths := testPaths(t)
	manager := NewCertManager(paths)
	info, err := manager.EnsureCA()
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if !info.Present || !strings.HasPrefix(info.Fingerprint, "SHA256:") {
		t.Fatalf("unexpected CA info: %+v", info)
	}
	keyInfo, err := os.Stat(paths.KeyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o, want 0600", keyInfo.Mode().Perm())
	}
	if err := CheckKeyPermissions(paths); err != nil {
		t.Fatalf("CheckKeyPermissions: %v", err)
	}
	leaf, err := manager.LeafCertificate("example.com")
	if err != nil {
		t.Fatalf("LeafCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "example.com" {
		t.Fatalf("leaf DNSNames = %v", cert.DNSNames)
	}
	rotated, err := manager.RotateCA()
	if err != nil {
		t.Fatalf("RotateCA: %v", err)
	}
	if rotated.Fingerprint == info.Fingerprint {
		t.Fatalf("rotation reused fingerprint %s", rotated.Fingerprint)
	}
	if err := manager.DeleteCA(); err != nil {
		t.Fatalf("DeleteCA: %v", err)
	}
	after, err := manager.Info()
	if err != nil {
		t.Fatalf("Info after delete: %v", err)
	}
	if after.Present {
		t.Fatalf("CA still present after delete: %+v", after)
	}
}

func TestRedactionHeadersAndBody(t *testing.T) {
	if !HeaderShouldRedact("Authorization") || !HeaderShouldRedact("cookie") {
		t.Fatal("expected sensitive headers to redact")
	}
	body := []byte("Authorization: Bearer example-token-value\nOPENAI_" + "API_KEY=<example-token>\n")
	result := RedactBody(body, 32)
	if result.Count < 2 {
		t.Fatalf("redaction count = %d, want >= 2", result.Count)
	}
	if strings.Contains(result.Preview, "abcdefghijklmnop") || strings.Contains(result.Preview, "sk-123") {
		t.Fatalf("preview leaked secret: %q", result.Preview)
	}
	if !result.PreviewTrunc {
		t.Fatalf("preview should be truncated")
	}
	if result.SHA256 == "" {
		t.Fatalf("missing body hash")
	}
}

func TestPurgePayloadsForEndedSessionsRemovesOnlySessionEndRecords(t *testing.T) {
	paths := testPaths(t)
	if err := os.MkdirAll(paths.DataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	ended := writePayloadRecordForInspectTest(t, paths, "ended.json", PayloadRecord{
		Schema:    "agentsnitch.inspect_payload.v0",
		Captured:  time.Now().UTC(),
		Retention: FullPayloadUntilSession,
		SessionID: "ended-session",
		Request:   "request",
		Response:  "response",
	})
	manual := writePayloadRecordForInspectTest(t, paths, "manual.json", PayloadRecord{
		Schema:    "agentsnitch.inspect_payload.v0",
		Captured:  time.Now().UTC(),
		Retention: FullPayloadManual,
		SessionID: "ended-session",
		Request:   "request",
		Response:  "response",
	})
	live := writePayloadRecordForInspectTest(t, paths, "live.json", PayloadRecord{
		Schema:    "agentsnitch.inspect_payload.v0",
		Captured:  time.Now().UTC(),
		Retention: FullPayloadUntilSession,
		SessionID: "live-session",
		Request:   "request",
		Response:  "response",
	})

	if err := PurgePayloadsForEndedSessions(paths, []string{"ended-session"}); err != nil {
		t.Fatalf("PurgePayloadsForEndedSessions: %v", err)
	}
	if _, err := os.Stat(ended); !os.IsNotExist(err) {
		t.Fatalf("ended session payload still exists or unexpected stat error: %v", err)
	}
	for _, path := range []string{manual, live} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("payload should remain at %s: %v", path, err)
		}
	}
}

func TestScopeBypassAndDomainControls(t *testing.T) {
	settings := DefaultSettings()
	if DestinationInScope(settings, "127.0.0.1") || DestinationInScope(settings, "service.local") {
		t.Fatal("local destinations should be bypassed")
	}
	if !DestinationInScope(settings, "api.example.com") {
		t.Fatal("public managed destination should be in scope by default")
	}
	settings.HTTPSInspectDomainsMode = "selected"
	settings.HTTPSInspectDomains = []string{"*.example.com"}
	if !DestinationInScope(settings, "api.example.com") {
		t.Fatal("wildcard allowlist did not match")
	}
	if DestinationInScope(settings, "api.other.com") {
		t.Fatal("non-allowlisted domain matched selected mode")
	}
	settings.HTTPSInspectNeverDomains = []string{"api.example.com"}
	if DestinationInScope(settings, "api.example.com") {
		t.Fatal("denylist should override allowlist")
	}
}

func TestProcessScopedEnvIncludesTrustAndProxy(t *testing.T) {
	env := ProcessScopedEnv("/tmp/ca.pem", "http://127.0.0.1:12345")
	for _, key := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS", "NPM_CONFIG_CAFILE", "npm_config_cafile", "PNPM_CONFIG_CAFILE", "YARN_CA_FILE"} {
		if env[key] != "/tmp/ca.pem" {
			t.Fatalf("%s = %q", key, env[key])
		}
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "npm_config_proxy", "npm_config_https_proxy", "NPM_CONFIG_PROXY", "NPM_CONFIG_HTTPS_PROXY"} {
		if env[key] != "http://127.0.0.1:12345" {
			t.Fatalf("%s = %q", key, env[key])
		}
	}
	if env["HTTPS_PROXY"] == "" || !strings.Contains(env["NO_PROXY"], "localhost") {
		t.Fatalf("proxy env missing: %+v", env)
	}
	if env["AGENTSNITCH_MANAGED_PROXY"] != "1" || env["AGENTSNITCH_INSPECT_MODE"] != "process_scoped" {
		t.Fatalf("managed inspect labels missing: %+v", env)
	}
}

func TestProxyRequiresToken(t *testing.T) {
	settings := DefaultSettings()
	settings.HTTPSInspectEnabled = true
	proxy := NewProxy(settings, NewCertManager(testPaths(t)), nil)
	if err := proxy.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Shutdown(nil)

	proxyURL, _ := url.Parse("http://" + proxy.Status().Address)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   2 * time.Second,
	}
	resp, err := client.Get("http://example.com/")
	if err != nil {
		t.Fatalf("unauthorized proxy request returned transport error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
	if proxy.AuthenticatedURL() == "" || !strings.Contains(proxy.AuthenticatedURL(), "agentsnitch:") {
		t.Fatalf("authenticated proxy URL missing token userinfo: %q", proxy.AuthenticatedURL())
	}
}

func TestSessionScopedProxyAuthBindsContextWithoutHeaders(t *testing.T) {
	settings := DefaultSettings()
	settings.HTTPSInspectEnabled = true
	settings.HTTPSInspectNeverDomains = []string{"api.example.com"}
	seen := &exchangeSink{}
	proxy := NewProxy(settings, NewCertManager(testPaths(t)), seen.add)
	proxy.dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("stop after metadata")
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Shutdown(nil)

	proxyURL, err := url.Parse(inspectSessionURLForTest(proxy, "claude/run 1"))
	if err != nil {
		t.Fatalf("parse scoped proxy URL: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   2 * time.Second,
	}
	_, _ = client.Get("https://api.example.com/path")
	events := seen.waitFor(t, 1)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].SessionID != "claude-run-1" {
		t.Fatalf("session id = %q, want scoped proxy user", events[0].SessionID)
	}
	if events[0].Correlation.Confidence != "medium" {
		t.Fatalf("confidence = %q, want medium session-bound metadata", events[0].Correlation.Confidence)
	}
}

func TestSessionScopedProxyURLPreservesToken(t *testing.T) {
	got := SessionScopedProxyURL("http://agentsnitch:secret-token@127.0.0.1:49152", "run one/alpha")
	if !strings.HasPrefix(got, "http://agentsnitch.run-one-alpha:secret-token@127.0.0.1:49152") {
		t.Fatalf("scoped URL = %q", got)
	}
	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("agentsnitch.run-one-alpha:secret-token")))
	ctx := contextFromRequest(req)
	if ctx.Token != "secret-token" || ctx.SessionID != "run-one-alpha" {
		t.Fatalf("context = %+v", ctx)
	}
}

func TestProxyMITMEmitsRedactedInspectedExchange(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"token":"ghp_abcdefghijklmnopqrstuvwxyz"}`))
	}))
	defer upstream.Close()

	settings := DefaultSettings()
	settings.HTTPSInspectEnabled = true
	settings.HTTPSInspectCapturePreviews = true
	settings.HTTPSInspectCaptureFull = true
	settings.HTTPSInspectPreviewBytes = 128
	settings.HTTPSInspectFullRetention = FullPayloadOneHour
	paths := testPaths(t)
	manager := NewCertManager(paths)
	var rawBody = strings.Repeat("x", 512) + "\nAWS_" + "SECRET_ACCESS_KEY=<example-token>"
	seen := &exchangeSink{}
	proxy := NewProxy(settings, manager, seen.add)
	proxy.paths = paths
	proxy.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	proxy.upstreamTLSConfig = &tls.Config{InsecureSkipVerify: true}
	if err := proxy.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Shutdown(nil)

	caPEM, err := os.ReadFile(paths.CAPath)
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append CA")
	}
	proxyURL, _ := url.Parse(proxy.AuthenticatedURL())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: roots,
			},
		},
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest("POST", "https://api.example.com/upload?secret=1", strings.NewReader(rawBody))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer abcdefghijklmnop")
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-AgentSnitch-Session", "s1")
	req.Header.Set("X-AgentSnitch-Tool-Use-ID", "tool-1")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client do: %v", err)
	}
	_ = resp.Body.Close()
	events := seen.waitFor(t, 1)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	exchange := events[0]
	if exchange.TLS.InspectionMode != "local_mitm" {
		t.Fatalf("mode = %q", exchange.TLS.InspectionMode)
	}
	if exchange.Network.RemoteIP != "127.0.0.1" || exchange.Network.RemotePort == 0 {
		t.Fatalf("remote metrics missing for MITM exchange: %+v", exchange.Network)
	}
	if exchange.SessionID != "s1" || exchange.ToolUseID != "tool-1" {
		t.Fatalf("context not preserved: %+v", exchange)
	}
	if exchange.Request.Headers[0].Name == "authorization" && !exchange.Request.Headers[0].Redacted {
		t.Fatalf("authorization header not redacted: %+v", exchange.Request.Headers)
	}
	if strings.Contains(exchange.Response.Preview, "ghp_") {
		t.Fatalf("response preview leaked token: %q", exchange.Response.Preview)
	}
	if strings.Contains(exchange.Request.Preview, rawBody) || len(exchange.Request.Preview) > settings.HTTPSInspectPreviewBytes {
		t.Fatalf("request preview was not capped: len=%d", len(exchange.Request.Preview))
	}
	if exchange.Request.PayloadRef == "" || exchange.Response.PayloadRef == "" {
		t.Fatalf("full payload refs missing: request=%q response=%q", exchange.Request.PayloadRef, exchange.Response.PayloadRef)
	}
	entries, err := os.ReadDir(paths.DataDir)
	if err != nil {
		t.Fatalf("read payload dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("payload records = %d, want 1", len(entries))
	}
	payloadRaw, err := os.ReadFile(filepath.Join(paths.DataDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read payload record: %v", err)
	}
	if strings.Contains(string(payloadRaw), "<example-token>") {
		t.Fatalf("payload record leaked secret: %s", payloadRaw)
	}
	if !strings.Contains(string(payloadRaw), "[REDACTED:env_secret]") {
		t.Fatalf("payload record missing redacted body: %s", payloadRaw)
	}
	if err := event.ValidateInspectedHTTPExchange(exchange); err != nil {
		t.Fatalf("validate exchange: %v", err)
	}
}

func TestMetadataOnlyConnectRecordsNetworkMetrics(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte("pong"))
	}()

	settings := DefaultSettings()
	settings.HTTPSInspectEnabled = true
	settings.HTTPSInspectNeverDomains = []string{"api.example.com"}
	seen := &exchangeSink{}
	proxy := NewProxy(settings, NewCertManager(testPaths(t)), seen.add)
	proxy.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, upstream.Addr().String())
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Shutdown(nil)

	proxyURL, _ := url.Parse(proxy.AuthenticatedURL())
	conn, err := net.DialTimeout("tcp", proxyURL.Host, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	fmt.Fprintf(conn, "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\nProxy-Authorization: Basic %s\r\n\r\n", basicProxyToken(proxy.Token()))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect status = %d", resp.StatusCode)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	_ = conn.Close()

	events := seen.waitFor(t, 1)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	exchange := events[0]
	if exchange.TLS.InspectionMode != "metadata_only" {
		t.Fatalf("mode = %q", exchange.TLS.InspectionMode)
	}
	if exchange.Network.RemoteIP != "127.0.0.1" || exchange.Network.RemotePort == 0 {
		t.Fatalf("remote metrics missing: %+v", exchange.Network)
	}
	if exchange.Network.BytesOut != 4 || exchange.Network.BytesIn != 4 {
		t.Fatalf("byte metrics = out %d in %d, want 4/4", exchange.Network.BytesOut, exchange.Network.BytesIn)
	}
}

func TestConnectScopeDenialTunnelsMetadataOnly(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte("pong"))
	}()

	settings := DefaultSettings()
	settings.HTTPSInspectEnabled = true
	seen := &exchangeSink{}
	proxy := NewProxy(settings, NewCertManager(testPaths(t)), seen.add)
	proxy.SetScopeFunc(func(ctx Context, host string) (Context, bool) {
		if ctx.SessionID != "managed-run" || host != "api.example.com" {
			t.Fatalf("scope context = %+v host=%q", ctx, host)
		}
		return ctx, false
	})
	proxy.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, upstream.Addr().String())
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Shutdown(nil)

	proxyURL, _ := url.Parse(AuthenticatedProxyURLForSession(proxy.Status().Address, proxy.Token(), "managed-run"))
	conn, err := net.DialTimeout("tcp", proxyURL.Host, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	fmt.Fprintf(conn, "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\nProxy-Authorization: Basic %s\r\n\r\n", basicScopedProxyToken("managed-run", proxy.Token()))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect status = %d", resp.StatusCode)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	_ = conn.Close()

	events := seen.waitFor(t, 1)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	exchange := events[0]
	if exchange.TLS.InspectionMode != "metadata_only" || exchange.SessionID != "managed-run" {
		t.Fatalf("exchange = %+v, want scoped metadata-only", exchange)
	}
	if containsString(exchange.Correlation.Basis, "tls_terminated_locally") {
		t.Fatalf("scope-denied tunnel claimed local TLS inspection: %+v", exchange.Correlation.Basis)
	}
}

// TestProxyRejectsOversizedResponse verifies the body cap is a clean refusal,
// not a silent truncation: the client must get a 502 and no exchange may claim
// a complete body it never forwarded.
func TestProxyRejectsOversizedResponse(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(bytes.Repeat([]byte("z"), 4096))
	}))
	defer upstream.Close()

	settings := DefaultSettings()
	settings.HTTPSInspectEnabled = true
	settings.HTTPSInspectCapturePreviews = true
	paths := testPaths(t)
	seen := &exchangeSink{}
	proxy := NewProxy(settings, NewCertManager(paths), seen.add)
	proxy.maxBodyBytes = 1024
	proxy.paths = paths
	proxy.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	proxy.upstreamTLSConfig = &tls.Config{InsecureSkipVerify: true}
	if err := proxy.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Shutdown(nil)

	proxyURL, _ := url.Parse(proxy.AuthenticatedURL())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://api.example.com/big")
	if err == nil {
		defer resp.Body.Close()
		got, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502", resp.StatusCode)
		}
		if len(got) != 0 {
			t.Fatalf("502 carried a partial body: %d bytes", len(got))
		}
	}
	if events := seen.snapshot(); len(events) != 0 {
		t.Fatalf("oversized exchange must not be recorded: %+v", events)
	}
}

// TestProxyRejectsOversizedRequest verifies the inbound cap rejects before the
// upstream sees a partial body.
func TestProxyRejectsOversizedRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	settings := DefaultSettings()
	settings.HTTPSInspectEnabled = true
	seen := &exchangeSink{}
	proxy := NewProxy(settings, NewCertManager(testPaths(t)), seen.add)
	proxy.maxBodyBytes = 1024
	proxy.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Shutdown(nil)

	proxyURL, _ := url.Parse(proxy.AuthenticatedURL())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Post("http://api.example.com/upload", "text/plain", bytes.NewReader(bytes.Repeat([]byte("a"), 4096)))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if events := seen.snapshot(); len(events) != 0 {
		t.Fatalf("oversized request must not be recorded: %+v", events)
	}
}

// TestPlainHTTPHonorsDestinationScope is the DEV-03/SEC-A06 regression: plain
// http:// requests must obey never-domains and the active-ToolSpan gate just
// like CONNECT, and an excluded request must still be forwarded transparently.
func TestPlainHTTPHonorsDestinationScope(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("origin-body"))
	}))
	defer upstream.Close()

	settings := DefaultSettings()
	settings.HTTPSInspectEnabled = true
	settings.HTTPSInspectNeverDomains = []string{"denied.example"}
	seen := &exchangeSink{}
	proxy := NewProxy(settings, NewCertManager(testPaths(t)), seen.add)
	proxy.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Shutdown(nil)

	proxyURL, _ := url.Parse(proxy.AuthenticatedURL())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	// Never-domain: forwarded, but no evidence is captured.
	resp, err := client.Get("http://denied.example/out-of-scope")
	if err != nil {
		t.Fatalf("out-of-scope request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "origin-body" {
		t.Fatalf("out-of-scope body = %q, want transparent forward", body)
	}
	if events := seen.snapshot(); len(events) != 0 {
		t.Fatalf("never-domain plain HTTP was captured: %+v", events)
	}

	// In scope: captured with the real http scheme and host.
	resp, err = client.Get("http://api.example.com/in-scope")
	if err != nil {
		t.Fatalf("in-scope request failed: %v", err)
	}
	_ = resp.Body.Close()
	events := seen.waitFor(t, 1)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].Request.Scheme != "http" || events[0].Request.Host != "api.example.com" {
		t.Fatalf("captured request = %+v", events[0].Request)
	}
}

// TestProxyHeadResponseWithLargeDeclaredLength verifies that a HEAD response
// declaring a body larger than the inspection cap is forwarded successfully
// instead of rejected as 502: upstreams legitimately report the full resource
// size in Content-Length for HEAD while sending no body at all.
func TestProxyHeadResponseWithLargeDeclaredLength(t *testing.T) {
	const declared = 64 << 20
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(declared))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	settings := DefaultSettings()
	settings.HTTPSInspectEnabled = true
	seen := &exchangeSink{}
	proxy := NewProxy(settings, NewCertManager(testPaths(t)), seen.add)
	proxy.maxBodyBytes = 1024 // far below the declared length
	proxy.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Shutdown(nil)

	proxyURL, _ := url.Parse(proxy.AuthenticatedURL())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Head("http://api.example.com/large-artifact")
	if err != nil {
		t.Fatalf("HEAD request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (HEAD must not be rejected for a declared body size)", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("HEAD body read: %v", err)
	}
	if len(body) != 0 {
		t.Fatalf("HEAD response carried %d body bytes, want none", len(body))
	}
}

// TestPlainHTTPStreamAbortsOnUpstreamDisconnect is the truncated-stream
// regression: when an out-of-scope chunked response is cut off before the
// terminating chunk, the proxy must abort the downstream response instead of
// finalizing it, so the client observes the framing error rather than silently
// accepting truncated content as complete.
func TestPlainHTTPStreamAbortsOnUpstreamDisconnect(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer upstream.Close()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			// Send one chunk, then vanish without the terminating 0-chunk.
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"))
			_ = conn.Close()
		}
	}()

	settings := DefaultSettings()
	settings.HTTPSInspectEnabled = true
	seen := &exchangeSink{}
	proxy := NewProxy(settings, NewCertManager(testPaths(t)), seen.add)
	proxy.SetScopeFunc(func(ctx Context, host string) (Context, bool) { return ctx, false })
	proxy.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, upstream.Addr().String())
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Shutdown(nil)

	proxyURL, _ := url.Parse(proxy.AuthenticatedURL())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get("http://api.example.com/stream")
	if err != nil {
		// The abort may surface as a transport error; the important property
		// is that the client never sees a clean, complete 200.
		return
	}
	defer resp.Body.Close()
	// A failed upstream round trip is a legitimate 502: the proxy saw no
	// framing to preserve. The bug this guards against is a 200 whose body
	// ends cleanly despite the upstream having been cut off mid-stream.
	if resp.StatusCode != http.StatusOK {
		return
	}
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("client read a truncated 200 response without error; the proxy must abort the downstream response when the upstream framing fails")
	}
}

// TestPlainHTTPHonorsActiveToolSpan ensures an inactive ToolSpan scope function
// also suppresses plain-HTTP capture (the managed-run exclusion promise).
func TestPlainHTTPHonorsActiveToolSpan(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	settings := DefaultSettings()
	settings.HTTPSInspectEnabled = true
	seen := &exchangeSink{}
	proxy := NewProxy(settings, NewCertManager(testPaths(t)), seen.add)
	proxy.SetScopeFunc(func(ctx Context, host string) (Context, bool) { return ctx, false })
	proxy.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Shutdown(nil)

	proxyURL, _ := url.Parse(proxy.AuthenticatedURL())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get("http://api.example.com/no-span")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()
	time.Sleep(50 * time.Millisecond)
	if events := seen.snapshot(); len(events) != 0 {
		t.Fatalf("plain HTTP outside a ToolSpan was captured: %+v", events)
	}
}

func TestProxyTrustFailureDowngradesToMetadata(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	settings := DefaultSettings()
	settings.HTTPSInspectEnabled = true
	paths := testPaths(t)
	seen := &exchangeSink{}
	proxy := NewProxy(settings, NewCertManager(paths), seen.add)
	proxy.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Shutdown(nil)
	proxyURL, _ := url.Parse(proxy.AuthenticatedURL())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	_, err := client.Get("https://api.example.com/pinned")
	if err == nil {
		t.Fatal("client unexpectedly trusted inspect CA")
	}
	events := seen.waitFor(t, 1)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].TLS.InspectionMode != "pinned_or_custom_trust" {
		t.Fatalf("mode = %q", events[0].TLS.InspectionMode)
	}
}

func TestProcessScopedCurlTrustsInspectCAWhenAvailable(t *testing.T) {
	curl := findExecutableForTest(t, "curl")
	upstream, proxy, seen := processScopedClientFixture(t)
	defer upstream.Close()
	defer proxy.Shutdown(nil)

	cmd := exec.Command(curl, "-fsS", "--max-time", "5", "--resolve", "api.example.com:443:"+upstream.Listener.Addr().(*net.TCPAddr).IP.String(), "https://api.example.com/hello")
	cmd.Env = append(os.Environ(), envPairs(ProcessScopedEnv(proxy.certs.paths.BundlePath, proxy.AuthenticatedURL()))...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("curl failed: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("curl output = %q, want ok", out)
	}
	events := seen.waitFor(t, 1)
	if len(events) < 1 {
		t.Fatal("no inspected exchange was emitted")
	}
	if events[0].TLS.InspectionMode != "local_mitm" {
		t.Fatalf("mode = %q", events[0].TLS.InspectionMode)
	}
}

func TestProcessScopedPythonRequestsTrustsInspectCAWhenAvailable(t *testing.T) {
	python := findExecutableForTest(t, "python3")
	if _, err := exec.Command(python, "-c", "import requests").CombinedOutput(); err != nil {
		t.Skip("python requests module is not installed")
	}
	upstream, proxy, seen := processScopedClientFixture(t)
	defer upstream.Close()
	defer proxy.Shutdown(nil)

	script := `import requests; print(requests.get("https://api.example.com/hello", timeout=5).text)`
	cmd := exec.Command(python, "-c", script)
	cmd.Env = append(os.Environ(), envPairs(ProcessScopedEnv(proxy.certs.paths.BundlePath, proxy.AuthenticatedURL()))...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python requests failed: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("python output = %q, want ok", out)
	}
	events := seen.waitFor(t, 1)
	if len(events) < 1 {
		t.Fatal("no inspected exchange was emitted")
	}
	if events[0].TLS.InspectionMode != "local_mitm" {
		t.Fatalf("mode = %q", events[0].TLS.InspectionMode)
	}
}

func TestProcessScopedNodeTrustsInspectCAWhenAvailable(t *testing.T) {
	node := findExecutableForTest(t, "node")
	upstream, proxy, seen := processScopedClientFixture(t)
	defer upstream.Close()
	defer proxy.Shutdown(nil)

	script := `
const net = require('net');
const tls = require('tls');
const proxyUrl = new URL(process.env.HTTPS_PROXY);
const token = Buffer.from(proxyUrl.username + ':' + proxyUrl.password).toString('base64');
const socket = net.connect(Number(proxyUrl.port), proxyUrl.hostname);
socket.setTimeout(5000);
socket.once('connect', () => {
  socket.write('CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\nProxy-Authorization: Basic ' + token + '\r\n\r\n');
});
let prelude = '';
socket.on('data', function onPrelude(chunk) {
  prelude += chunk.toString('utf8');
  if (!prelude.includes('\r\n\r\n')) return;
  socket.off('data', onPrelude);
  if (!prelude.startsWith('HTTP/1.1 200')) throw new Error(prelude);
  const secure = tls.connect({ socket, servername: 'api.example.com' }, () => {
    secure.write('GET /hello HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n');
  });
  let body = '';
  secure.on('data', (chunk) => { body += chunk.toString('utf8'); });
  secure.on('end', () => {
    if (!body.includes('\r\n\r\nok')) throw new Error(body);
    console.log('ok');
  });
});
`
	cmd := exec.Command(node, "-e", script)
	cmd.Env = append(os.Environ(), envPairs(ProcessScopedEnv(proxy.certs.paths.BundlePath, proxy.AuthenticatedURL()))...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node failed: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("node output = %q, want ok", out)
	}
	events := seen.waitFor(t, 1)
	if len(events) < 1 {
		t.Fatal("no inspected exchange was emitted")
	}
	if events[0].TLS.InspectionMode != "local_mitm" {
		t.Fatalf("mode = %q", events[0].TLS.InspectionMode)
	}
}

func TestProcessScopedGitTrustsInspectCAWhenAvailable(t *testing.T) {
	git := findExecutableForTest(t, "git")
	upstream, proxy, seen := processScopedClientFixture(t)
	defer upstream.Close()
	defer proxy.Shutdown(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, git, "-c", "protocol.version=0", "ls-remote", "https://api.example.com/repo.git")
	cmd.Env = append(os.Environ(), envPairs(ProcessScopedEnv(proxy.certs.paths.BundlePath, proxy.AuthenticatedURL()))...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("git timed out: %v\n%s", ctx.Err(), out)
	}
	lower := strings.ToLower(string(out))
	for _, bad := range []string{"certificate", "x509", "ssl certificate problem"} {
		if strings.Contains(lower, bad) {
			t.Fatalf("git failed before trusting inspect CA: %v\n%s", err, out)
		}
	}
	events := seen.waitFor(t, 1)
	if len(events) < 1 {
		t.Fatal("no inspected exchange was emitted")
	}
	if events[0].TLS.InspectionMode != "local_mitm" {
		t.Fatalf("mode = %q", events[0].TLS.InspectionMode)
	}
}

func TestProcessScopedNPMTrustsInspectCAWhenAvailable(t *testing.T) {
	npm := findExecutableForTest(t, "npm")
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/-/ping") {
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	paths := testPaths(t)
	settings := DefaultSettings()
	settings.HTTPSInspectEnabled = true
	settings.HTTPSInspectCapturePreviews = true
	seen := &exchangeSink{}
	manager := NewCertManager(paths)
	proxy := NewProxy(settings, manager, seen.add)
	proxy.paths = paths
	proxy.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	proxy.upstreamTLSConfig = &tls.Config{InsecureSkipVerify: true}
	if err := proxy.Start(); err != nil {
		upstream.Close()
		t.Fatalf("proxy start: %v", err)
	}
	defer upstream.Close()
	defer proxy.Shutdown(nil)

	tmp := t.TempDir()
	userConfig := filepath.Join(tmp, ".npmrc")
	if err := os.WriteFile(userConfig, nil, 0o600); err != nil {
		t.Fatalf("write npmrc: %v", err)
	}
	cmd := exec.Command(
		npm,
		"ping",
		"--registry=https://api.example.com/",
		"--fetch-timeout=5000",
		"--fetch-retries=0",
		"--loglevel=error",
		"--userconfig="+userConfig,
	)
	env := ProcessScopedEnv(proxy.certs.paths.BundlePath, proxy.AuthenticatedURL())
	env["HOME"] = tmp
	env["npm_config_cache"] = filepath.Join(tmp, "cache")
	cmd.Env = append(os.Environ(), envPairs(env)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("npm ping failed: %v\n%s", err, out)
	}
	events := seen.waitFor(t, 1)
	if len(events) < 1 {
		t.Fatal("no inspected exchange was emitted")
	}
	if events[0].TLS.InspectionMode != "local_mitm" {
		t.Fatalf("mode = %q", events[0].TLS.InspectionMode)
	}
}

func basicProxyToken(token string) string {
	return base64.StdEncoding.EncodeToString([]byte("agentsnitch:" + token))
}

func basicScopedProxyToken(sessionID, token string) string {
	return base64.StdEncoding.EncodeToString([]byte("agentsnitch." + SafeProxySessionID(sessionID) + ":" + token))
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func inspectSessionURLForTest(proxy *Proxy, sessionID string) string {
	return AuthenticatedProxyURLForSession(proxy.Status().Address, proxy.Token(), sessionID)
}

func processScopedClientFixture(t *testing.T) (*httptest.Server, *Proxy, *exchangeSink) {
	t.Helper()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	paths := testPaths(t)
	settings := DefaultSettings()
	settings.HTTPSInspectEnabled = true
	settings.HTTPSInspectCapturePreviews = true
	seen := &exchangeSink{}
	manager := NewCertManager(paths)
	proxy := NewProxy(settings, manager, seen.add)
	proxy.paths = paths
	proxy.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	proxy.upstreamTLSConfig = &tls.Config{InsecureSkipVerify: true}
	if err := proxy.Start(); err != nil {
		upstream.Close()
		t.Fatalf("proxy start: %v", err)
	}
	return upstream, proxy, seen
}

func findExecutableForTest(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed", name)
	}
	return path
}

func writePayloadRecordForInspectTest(t *testing.T, paths Paths, name string, record PayloadRecord) string {
	t.Helper()
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal payload record: %v", err)
	}
	path := filepath.Join(paths.DataDir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile payload record: %v", err)
	}
	return path
}

func envPairs(env map[string]string) []string {
	pairs := make([]string, 0, len(env))
	for key, value := range env {
		pairs = append(pairs, key+"="+value)
	}
	return pairs
}
