package inspect

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/somoore/agentsnitch/internal/event"
)

type Context struct {
	SessionID string
	SpanID    string
	ToolUseID string
	Token     string
}

type Capture struct {
	Settings      Settings
	CAFingerprint string
	Paths         Paths
	Network       event.InspectedHTTPNetwork
}

func ExchangeFromHTTP(ctx Context, capture Capture, req *http.Request, reqBody []byte, resp *http.Response, respBody []byte, tlsMode, upstreamTLSVersion string, leafGenerated bool) event.InspectedHTTPExchange {
	settings := capture.Settings
	reqRedacted := RedactBody(reqBody, settings.HTTPSInspectPreviewBytes)
	respRedacted := RedactBody(respBody, settings.HTTPSInspectPreviewBytes)
	method := ""
	scheme := "https"
	host := ""
	path := "/"
	queryRedacted := false
	contentType := ""
	headers := []event.InspectedHTTPHeader{}
	if req != nil {
		method = req.Method
		if req.URL != nil {
			if req.URL.Scheme != "" {
				scheme = req.URL.Scheme
			}
			if req.URL.Path != "" {
				path = req.URL.EscapedPath()
			}
			if req.URL.RawQuery != "" {
				queryRedacted = true
			}
		}
		host = req.Host
		if host == "" && req.URL != nil {
			host = req.URL.Host
		}
		contentType = req.Header.Get("Content-Type")
		headers = inspectedHeaders(req.Header)
	}
	status := 0
	respContentType := ""
	if resp != nil {
		status = resp.StatusCode
		respContentType = resp.Header.Get("Content-Type")
	}
	exchange := event.InspectedHTTPExchange{
		Schema:    event.SchemaInspectedHTTPV0,
		TS:        time.Now().UTC(),
		SessionID: ctx.SessionID,
		SpanID:    ctx.SpanID,
		ToolUseID: ctx.ToolUseID,
		Request: event.InspectedHTTPRequest{
			Method:           method,
			Scheme:           scheme,
			Host:             canonicalCertHost(host),
			Path:             path,
			QueryRedacted:    queryRedacted,
			Headers:          headers,
			ContentType:      contentType,
			BodySize:         int64(len(reqBody)),
			BodySHA256:       reqRedacted.SHA256,
			Preview:          previewForSettings(settings, reqRedacted),
			PreviewTruncated: reqRedacted.PreviewTrunc,
			RedactionCount:   reqRedacted.Count,
		},
		Response: event.InspectedHTTPResponse{
			Status:           status,
			ContentType:      respContentType,
			BodySize:         int64(len(respBody)),
			BodySHA256:       respRedacted.SHA256,
			Preview:          previewForSettings(settings, respRedacted),
			PreviewTruncated: respRedacted.PreviewTrunc,
			RedactionCount:   respRedacted.Count,
		},
		TLS: event.InspectedHTTPTLS{
			InspectionMode:     tlsMode,
			CAFingerprint:      capture.CAFingerprint,
			LeafCertGenerated:  leafGenerated,
			UpstreamTLSVersion: upstreamTLSVersion,
		},
		Network: capture.Network,
		Retention: event.InspectedHTTPRetention{
			PayloadMode:       settings.PayloadMode(),
			PreviewBytes:      settings.HTTPSInspectPreviewBytes,
			FullPayloadStored: settings.HTTPSInspectCaptureFull,
			Retention:         settings.HTTPSInspectFullRetention,
		},
		Correlation: event.InspectedHTTPCorrelation{
			Basis:      correlationBasis(ctx, tlsMode),
			Confidence: correlationConfidence(ctx, tlsMode),
		},
	}
	if settings.HTTPSInspectCaptureFull {
		if err := StorePayloadRecord(payloadPaths(capture.Paths), &exchange, reqRedacted.Value, respRedacted.Value); err != nil {
			exchange.Retention.FullPayloadStored = false
		}
	}
	return exchange
}

func MetadataOnlyExchange(ctx Context, capture Capture, host string, tlsMode string) event.InspectedHTTPExchange {
	host = canonicalCertHost(host)
	return event.InspectedHTTPExchange{
		Schema:    event.SchemaInspectedHTTPV0,
		TS:        time.Now().UTC(),
		SessionID: ctx.SessionID,
		SpanID:    ctx.SpanID,
		ToolUseID: ctx.ToolUseID,
		Request: event.InspectedHTTPRequest{
			Method: "CONNECT",
			Scheme: "https",
			Host:   host,
			Path:   "/",
		},
		TLS: event.InspectedHTTPTLS{
			InspectionMode: tlsMode,
			CAFingerprint:  capture.CAFingerprint,
		},
		Retention: event.InspectedHTTPRetention{
			PayloadMode:  PayloadMetadataOnly,
			PreviewBytes: capture.Settings.HTTPSInspectPreviewBytes,
			Retention:    capture.Settings.HTTPSInspectFullRetention,
		},
		Network: capture.Network,
		Correlation: event.InspectedHTTPCorrelation{
			Basis:      correlationBasis(ctx, tlsMode),
			Confidence: correlationConfidence(ctx, tlsMode),
		},
	}
}

func inspectedHeaders(headers http.Header) []event.InspectedHTTPHeader {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]event.InspectedHTTPHeader, 0, len(names))
	for _, name := range names {
		values := headers.Values(name)
		value := strings.Join(values, ",")
		redacted := HeaderShouldRedact(name)
		item := event.InspectedHTTPHeader{
			Name:     strings.ToLower(name),
			Present:  true,
			Redacted: redacted,
		}
		if redacted {
			item.ValueSHA256 = HashString(value)
		} else if value != "" {
			item.Preview = value
		}
		out = append(out, item)
	}
	return out
}

func previewForSettings(settings Settings, redacted RedactionResult) string {
	if settings.HTTPSInspectCaptureFull || settings.HTTPSInspectCapturePreviews {
		return redacted.Preview
	}
	return ""
}

func payloadPaths(paths Paths) Paths {
	if paths.DataDir != "" {
		return paths
	}
	return DefaultPaths()
}

func correlationBasis(ctx Context, tlsMode string) []string {
	basis := []string{"managed_proxy", "exact_requested_host"}
	if ctx.SessionID != "" {
		basis = append(basis, "managed_agent_session")
	}
	if ctx.ToolUseID != "" || ctx.SpanID != "" {
		basis = append(basis, "active_tool_span")
	}
	if tlsMode == "local_mitm" {
		basis = append(basis, "tls_terminated_locally")
	}
	return basis
}

func correlationConfidence(ctx Context, tlsMode string) string {
	if tlsMode == "local_mitm" && (ctx.ToolUseID != "" || ctx.SpanID != "") {
		return "high"
	}
	if ctx.SessionID != "" {
		return "medium"
	}
	return "low"
}

func CloneRequestForUpstream(req *http.Request, body []byte, scheme, host string) (*http.Request, error) {
	rawPath := "/"
	if req.URL != nil && req.URL.RequestURI() != "" {
		rawPath = req.URL.RequestURI()
	}
	u, err := url.Parse(scheme + "://" + host + rawPath)
	if err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	clone.URL = u
	clone.RequestURI = ""
	clone.Host = host
	clone.Header.Del("Proxy-Authorization")
	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.ContentLength = int64(len(body))
	return clone, nil
}
