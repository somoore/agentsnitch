package inspect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/somoore/agentsnitch/internal/event"
)

type Proxy struct {
	settings          Settings
	certs             *CertManager
	paths             Paths
	onEvent           func(event.InspectedHTTPExchange)
	scope             func(Context, string) (Context, bool)
	server            *http.Server
	listener          net.Listener
	token             string
	dial              func(context.Context, string, string) (net.Conn, error)
	upstreamTLSConfig *tls.Config
	mu                sync.Mutex
}

type ProxyStatus struct {
	Enabled   bool   `json:"enabled"`
	Listening bool   `json:"listening"`
	Address   string `json:"address,omitempty"`
}

func NewProxy(settings Settings, certs *CertManager, onEvent func(event.InspectedHTTPExchange)) *Proxy {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &Proxy{settings: settings, paths: DefaultPaths(), certs: certs, onEvent: onEvent, dial: dialer.DialContext}
}

func (p *Proxy) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener != nil {
		return nil
	}
	if !p.settings.HTTPSInspectEnabled {
		return nil
	}
	if p.certs == nil {
		p.certs = NewCertManager(DefaultPaths())
	}
	if p.token == "" {
		token, err := newProxyToken()
		if err != nil {
			return err
		}
		p.token = token
	}
	if _, err := p.certs.EnsureCA(); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	p.listener = ln
	p.server = &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := p.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("inspect proxy stopped: %v", err)
		}
	}()
	return nil
}

func (p *Proxy) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	server := p.server
	p.server = nil
	p.listener = nil
	p.mu.Unlock()
	if server == nil {
		return nil
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
	}
	return server.Shutdown(ctx)
}

func (p *Proxy) Status() ProxyStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	status := ProxyStatus{Enabled: p.settings.HTTPSInspectEnabled, Listening: p.listener != nil}
	if p.listener != nil {
		status.Address = p.listener.Addr().String()
	}
	return status
}

func (p *Proxy) Token() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.token
}

func (p *Proxy) AuthenticatedURL() string {
	status := p.Status()
	if !status.Listening || status.Address == "" {
		return ""
	}
	return AuthenticatedProxyURL(status.Address, p.Token())
}

func (p *Proxy) SetScopeFunc(scope func(Context, string) (Context, bool)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.scope = scope
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !p.localClient(req) {
		http.Error(w, "inspect proxy accepts local clients only", http.StatusForbidden)
		return
	}
	ctx := contextFromRequest(req)
	if !p.authorized(ctx) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="AgentSnitch Inspect"`)
		http.Error(w, "inspect proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if req.Method == http.MethodConnect {
		p.handleConnect(w, req, ctx)
		return
	}
	p.handlePlainHTTP(w, req, ctx)
}

func (p *Proxy) handlePlainHTTP(w http.ResponseWriter, req *http.Request, ctx Context) {
	started := time.Now()
	body, _ := io.ReadAll(req.Body)
	if req.Body != nil {
		_ = req.Body.Close()
	}
	upstream, err := CloneRequestForUpstream(req, body, "http", req.Host)
	if err != nil {
		http.Error(w, "bad proxy request", http.StatusBadRequest)
		return
	}
	resp, respBody, network, err := p.roundTrip(upstream, nil)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyResponse(w, resp, respBody)
	network.BytesOut = int64(len(body))
	network.BytesIn = int64(len(respBody))
	network.DurationMS = time.Since(started).Milliseconds()
	p.emit(ExchangeFromHTTP(ctx, Capture{
		Settings: p.settings,
		Paths:    p.paths,
		Network:  network,
	}, req, body, resp, respBody, "metadata_only", "", false))
}

func (p *Proxy) handleConnect(w http.ResponseWriter, req *http.Request, ctx Context) {
	started := time.Now()
	const maxRequestsPerTunnel = 16
	host := req.Host
	if host == "" {
		http.Error(w, "missing CONNECT host", http.StatusBadRequest)
		return
	}
	hostOnly := canonicalCertHost(host)
	if !p.settings.HTTPSInspectEnabled || !DestinationInScope(p.settings, hostOnly) {
		network, err := p.tunnelConnect(w, req)
		if err != nil {
			log.Printf("inspect proxy tunnel metadata failed for %s: %v", hostOnly, err)
		}
		p.emit(p.metadata(ctx, hostOnly, "metadata_only", network))
		return
	}
	if scopedCtx, ok := p.inspectAllowed(ctx, hostOnly); ok {
		ctx = scopedCtx
	} else {
		network, err := p.tunnelConnect(w, req)
		if err != nil {
			log.Printf("inspect proxy scoped tunnel metadata failed for %s: %v", hostOnly, err)
		}
		p.emit(p.metadata(ctx, hostOnly, "metadata_only", network))
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	leaf, err := p.certs.LeafCertificate(hostOnly)
	if err != nil {
		p.emit(p.metadata(ctx, hostOnly, "trust_failed", event.InspectedHTTPNetwork{}))
		return
	}
	tlsClient := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		p.emit(p.metadata(ctx, hostOnly, "pinned_or_custom_trust", event.InspectedHTTPNetwork{}))
		return
	}
	reader := bufio.NewReader(tlsClient)
	for requestCount := 0; requestCount < maxRequestsPerTunnel; requestCount++ {
		requestStart := time.Now()
		clientReq, err := http.ReadRequest(reader)
		if err != nil {
			if requestCount == 0 {
				p.emit(p.metadata(ctx, hostOnly, "unsupported_protocol", event.InspectedHTTPNetwork{}))
			}
			return
		}
		innerCtx := contextFromRequest(clientReq)
		if ctx.SessionID == "" {
			ctx.SessionID = innerCtx.SessionID
		}
		if ctx.SpanID == "" {
			ctx.SpanID = innerCtx.SpanID
		}
		if ctx.ToolUseID == "" {
			ctx.ToolUseID = innerCtx.ToolUseID
		}
		reqBody, err := io.ReadAll(clientReq.Body)
		if clientReq.Body != nil {
			_ = clientReq.Body.Close()
		}
		if err != nil {
			p.emit(p.metadata(ctx, hostOnly, "unsupported_protocol", event.InspectedHTTPNetwork{}))
			return
		}
		upstreamReq, err := CloneRequestForUpstream(clientReq, reqBody, "https", host)
		if err != nil {
			p.emit(p.metadata(ctx, hostOnly, "unsupported_protocol", event.InspectedHTTPNetwork{}))
			return
		}
		var tlsState *tls.ConnectionState
		resp, respBody, network, err := p.roundTrip(upstreamReq, &tlsState)
		if err != nil {
			_, _ = io.WriteString(tlsClient, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return
		}
		defer resp.Body.Close()
		if err := resp.Write(tlsClient); err != nil {
			return
		}
		upstreamVersion := ""
		if tlsState != nil {
			upstreamVersion = tlsVersionName(tlsState.Version)
		}
		info, _ := p.certs.Info()
		network.BytesOut = int64(len(reqBody))
		network.BytesIn = int64(len(respBody))
		network.DurationMS = time.Since(requestStart).Milliseconds()
		exchange := ExchangeFromHTTP(ctx, Capture{
			Settings:      p.settings,
			CAFingerprint: info.Fingerprint,
			Paths:         p.paths,
			Network:       network,
		}, clientReq, reqBody, resp, respBody, "local_mitm", upstreamVersion, true)
		p.emit(exchange)
		if clientReq.Close {
			return
		}
		_ = started
	}
	p.emit(p.metadata(ctx, hostOnly, "unsupported_protocol", event.InspectedHTTPNetwork{}))
}

func (p *Proxy) tunnelConnect(w http.ResponseWriter, req *http.Request) (event.InspectedHTTPNetwork, error) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
	defer cancel()
	upstream, err := p.dial(ctx, "tcp", req.Host)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return event.InspectedHTTPNetwork{DurationMS: time.Since(started).Milliseconds()}, err
	}
	defer upstream.Close()
	network := networkFromRemote(upstream.RemoteAddr(), started)
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return network, errors.New("hijacking unsupported")
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return network, err
	}
	defer client.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return network, err
	}
	var bytesOut atomic.Int64
	var bytesIn atomic.Int64
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(countingWriter{writer: upstream, count: &bytesOut}, client)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(countingWriter{writer: client, count: &bytesIn}, upstream)
		errc <- err
	}()
	<-errc
	_ = upstream.Close()
	_ = client.Close()
	<-errc
	network.BytesOut = bytesOut.Load()
	network.BytesIn = bytesIn.Load()
	network.DurationMS = time.Since(started).Milliseconds()
	return network, nil
}

func (p *Proxy) metadata(ctx Context, host, mode string, network event.InspectedHTTPNetwork) event.InspectedHTTPExchange {
	info, _ := p.certs.Info()
	return MetadataOnlyExchange(ctx, Capture{Settings: p.settings, CAFingerprint: info.Fingerprint, Paths: p.paths, Network: network}, host, mode)
}

func (p *Proxy) emit(exchange event.InspectedHTTPExchange) {
	event.NormalizeInspectedHTTPExchange(&exchange)
	if err := event.ValidateInspectedHTTPExchange(exchange); err != nil {
		log.Printf("INSPECT_HTTP_INVALID: %v", err)
		return
	}
	if p.onEvent != nil {
		p.onEvent(exchange)
	}
}

func (p *Proxy) inspectAllowed(ctx Context, host string) (Context, bool) {
	p.mu.Lock()
	scope := p.scope
	p.mu.Unlock()
	if scope == nil {
		return ctx, true
	}
	return scope(ctx, host)
}

func contextFromRequest(req *http.Request) Context {
	user, token := proxyCredentials(req)
	sessionID := req.Header.Get("X-AgentSnitch-Session")
	if strings.TrimSpace(sessionID) == "" {
		sessionID = sessionIDFromProxyUser(user)
	}
	return Context{
		SessionID: sessionID,
		SpanID:    req.Header.Get("X-AgentSnitch-Span"),
		ToolUseID: req.Header.Get("X-AgentSnitch-Tool-Use-ID"),
		Token:     token,
	}
}

func proxyToken(req *http.Request) string {
	_, token := proxyCredentials(req)
	return token
}

func proxyCredentials(req *http.Request) (string, string) {
	value := req.Header.Get("Proxy-Authorization")
	if strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return "", strings.TrimSpace(value[len("bearer "):])
	}
	if strings.HasPrefix(strings.ToLower(value), "basic ") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[len("basic "):]))
		if err == nil {
			user, token, ok := strings.Cut(string(raw), ":")
			if ok {
				return user, token
			}
		}
	}
	return "", ""
}

func sessionIDFromProxyUser(user string) string {
	user = strings.TrimSpace(user)
	const prefix = "agentsnitch."
	if !strings.HasPrefix(user, prefix) {
		return ""
	}
	sessionID := strings.TrimSpace(strings.TrimPrefix(user, prefix))
	if sessionID == "" {
		return ""
	}
	return sessionID
}

func (p *Proxy) authorized(ctx Context) bool {
	p.mu.Lock()
	token := p.token
	p.mu.Unlock()
	return token == "" || constantTimeStringEqual(ctx.Token, token)
}

func (p *Proxy) localClient(req *http.Request) bool {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newProxyToken() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func AuthenticatedProxyURL(address, token string) string {
	if strings.TrimSpace(address) == "" {
		return ""
	}
	u := url.URL{Scheme: "http", Host: address}
	if token != "" {
		u.User = url.UserPassword("agentsnitch", token)
	}
	return u.String()
}

func AuthenticatedProxyURLForSession(address, token, sessionID string) string {
	if strings.TrimSpace(address) == "" {
		return ""
	}
	u := url.URL{Scheme: "http", Host: address}
	if token != "" {
		user := "agentsnitch"
		if session := SafeProxySessionID(sessionID); session != "" {
			user = "agentsnitch." + session
		}
		u.User = url.UserPassword(user, token)
	}
	return u.String()
}

func SessionScopedProxyURL(proxyURL, sessionID string) string {
	session := SafeProxySessionID(sessionID)
	if strings.TrimSpace(proxyURL) == "" || session == "" {
		return proxyURL
	}
	u, err := url.Parse(proxyURL)
	if err != nil || u.Host == "" {
		return proxyURL
	}
	token := ""
	if u.User != nil {
		token, _ = u.User.Password()
	}
	if token == "" {
		return proxyURL
	}
	u.User = url.UserPassword("agentsnitch."+session, token)
	return u.String()
}

func SafeProxySessionID(sessionID string) string {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range sessionID {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
		if b.Len() >= 96 {
			break
		}
	}
	return strings.Trim(b.String(), ".-_")
}

type countingWriter struct {
	writer io.Writer
	count  *atomic.Int64
}

func (w countingWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	w.count.Add(int64(n))
	return n, err
}

func networkFromRemote(addr net.Addr, started time.Time) event.InspectedHTTPNetwork {
	network := event.InspectedHTTPNetwork{DurationMS: time.Since(started).Milliseconds()}
	if addr == nil {
		return network
	}
	network.Remote = addr.String()
	host, port, err := net.SplitHostPort(network.Remote)
	if err != nil {
		return network
	}
	network.RemoteIP = strings.Trim(host, "[]")
	if parsedPort, err := net.LookupPort("tcp", port); err == nil {
		network.RemotePort = parsedPort
	}
	return network
}

func constantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func (p *Proxy) roundTrip(req *http.Request, tlsState **tls.ConnectionState) (*http.Response, []byte, event.InspectedHTTPNetwork, error) {
	var remote net.Addr
	var remoteMu sync.Mutex
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := p.dial(ctx, network, addr)
		if err == nil && conn != nil {
			remoteMu.Lock()
			remote = conn.RemoteAddr()
			remoteMu.Unlock()
		}
		return conn, err
	}
	if p.upstreamTLSConfig != nil {
		transport.TLSClientConfig = p.upstreamTLSConfig
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, nil, event.InspectedHTTPNetwork{}, err
	}
	if tlsState != nil && resp.TLS != nil {
		state := *resp.TLS
		*tlsState = &state
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, event.InspectedHTTPNetwork{}, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	remoteMu.Lock()
	network := networkFromRemote(remote, time.Now())
	remoteMu.Unlock()
	network.DurationMS = 0
	return resp, body, network, nil
}

func copyResponse(w http.ResponseWriter, resp *http.Response, body []byte) {
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func limitReader(r io.Reader, n int64) io.Reader {
	if r == nil {
		return strings.NewReader("")
	}
	return io.LimitReader(r, n)
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("TLS 0x%x", version)
	}
}
