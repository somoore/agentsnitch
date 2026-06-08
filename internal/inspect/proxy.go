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
	body, _ := io.ReadAll(limitReader(req.Body, 16<<20))
	if req.Body != nil {
		_ = req.Body.Close()
	}
	upstream, err := CloneRequestForUpstream(req, body, "http", req.Host)
	if err != nil {
		http.Error(w, "bad proxy request", http.StatusBadRequest)
		return
	}
	resp, respBody, err := p.roundTrip(upstream, nil)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyResponse(w, resp, respBody)
	p.emit(ExchangeFromHTTP(ctx, Capture{
		Settings: p.settings,
		Paths:    p.paths,
		Network: event.InspectedHTTPNetwork{
			BytesOut:   int64(len(body)),
			BytesIn:    int64(len(respBody)),
			DurationMS: time.Since(started).Milliseconds(),
		},
	}, req, body, resp, respBody, "metadata_only", "", false))
}

func (p *Proxy) handleConnect(w http.ResponseWriter, req *http.Request, ctx Context) {
	started := time.Now()
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
	clientReq, err := http.ReadRequest(reader)
	if err != nil {
		p.emit(p.metadata(ctx, hostOnly, "unsupported_protocol", event.InspectedHTTPNetwork{}))
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
	reqBody, _ := io.ReadAll(limitReader(clientReq.Body, 16<<20))
	if clientReq.Body != nil {
		_ = clientReq.Body.Close()
	}
	upstreamReq, err := CloneRequestForUpstream(clientReq, reqBody, "https", host)
	if err != nil {
		p.emit(p.metadata(ctx, hostOnly, "unsupported_protocol", event.InspectedHTTPNetwork{}))
		return
	}
	var tlsState *tls.ConnectionState
	resp, respBody, err := p.roundTrip(upstreamReq, &tlsState)
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
	exchange := ExchangeFromHTTP(ctx, Capture{
		Settings:      p.settings,
		CAFingerprint: info.Fingerprint,
		Paths:         p.paths,
		Network: event.InspectedHTTPNetwork{
			BytesOut:   int64(len(reqBody)),
			BytesIn:    int64(len(respBody)),
			DurationMS: time.Since(started).Milliseconds(),
		},
	}, clientReq, reqBody, resp, respBody, "local_mitm", upstreamVersion, true)
	p.emit(exchange)
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

func contextFromRequest(req *http.Request) Context {
	return Context{
		SessionID: req.Header.Get("X-AgentSnitch-Session"),
		SpanID:    req.Header.Get("X-AgentSnitch-Span"),
		ToolUseID: req.Header.Get("X-AgentSnitch-Tool-Use-ID"),
		Token:     proxyToken(req),
	}
}

func proxyToken(req *http.Request) string {
	value := req.Header.Get("Proxy-Authorization")
	if strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return strings.TrimSpace(value[len("bearer "):])
	}
	if strings.HasPrefix(strings.ToLower(value), "basic ") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[len("basic "):]))
		if err == nil {
			_, token, ok := strings.Cut(string(raw), ":")
			if ok {
				return token
			}
		}
	}
	return ""
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

func (p *Proxy) roundTrip(req *http.Request, tlsState **tls.ConnectionState) (*http.Response, []byte, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = p.dial
	if p.upstreamTLSConfig != nil {
		transport.TLSClientConfig = p.upstreamTLSConfig
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, nil, err
	}
	if tlsState != nil && resp.TLS != nil {
		state := *resp.TLS
		*tlsState = &state
	}
	body, err := io.ReadAll(limitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp, body, nil
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
