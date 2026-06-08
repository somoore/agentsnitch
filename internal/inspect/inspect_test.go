package inspect

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/somoore/agentsnitch/internal/event"
)

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
	for _, key := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS", "npm_config_cafile", "YARN_CA_FILE"} {
		if env[key] != "/tmp/ca.pem" {
			t.Fatalf("%s = %q", key, env[key])
		}
	}
	if env["HTTPS_PROXY"] == "" || !strings.Contains(env["NO_PROXY"], "localhost") {
		t.Fatalf("proxy env missing: %+v", env)
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
	var seen []event.InspectedHTTPExchange
	proxy := NewProxy(settings, manager, func(exchange event.InspectedHTTPExchange) {
		seen = append(seen, exchange)
	})
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
	waitForEvents(t, &seen, 1)
	if len(seen) != 1 {
		t.Fatalf("events = %d, want 1", len(seen))
	}
	exchange := seen[0]
	if exchange.TLS.InspectionMode != "local_mitm" {
		t.Fatalf("mode = %q", exchange.TLS.InspectionMode)
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
	var seen []event.InspectedHTTPExchange
	proxy := NewProxy(settings, NewCertManager(testPaths(t)), func(exchange event.InspectedHTTPExchange) {
		seen = append(seen, exchange)
	})
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

	waitForEvents(t, &seen, 1)
	exchange := seen[0]
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

func TestProxyTrustFailureDowngradesToMetadata(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	settings := DefaultSettings()
	settings.HTTPSInspectEnabled = true
	paths := testPaths(t)
	var seen []event.InspectedHTTPExchange
	proxy := NewProxy(settings, NewCertManager(paths), func(exchange event.InspectedHTTPExchange) {
		seen = append(seen, exchange)
	})
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
	waitForEvents(t, &seen, 1)
	if len(seen) != 1 {
		t.Fatalf("events = %d, want 1", len(seen))
	}
	if seen[0].TLS.InspectionMode != "pinned_or_custom_trust" {
		t.Fatalf("mode = %q", seen[0].TLS.InspectionMode)
	}
}

func waitForEvents(t *testing.T, seen *[]event.InspectedHTTPExchange, count int) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(*seen) >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func basicProxyToken(token string) string {
	return base64.StdEncoding.EncodeToString([]byte("agentsnitch:" + token))
}
