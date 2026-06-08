package inspect

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

var redactedHeaders = map[string]struct{}{
	"authorization":        {},
	"proxy-authorization":  {},
	"cookie":               {},
	"set-cookie":           {},
	"x-api-key":            {},
	"api-key":              {},
	"x-auth-token":         {},
	"x-amz-security-token": {},
	"x-github-token":       {},
	"x-openai-api-key":     {},
	"x-anthropic-api-key":  {},
}

type RedactionResult struct {
	Value          string         `json:"value"`
	Count          int            `json:"redaction_count"`
	Types          map[string]int `json:"redaction_types,omitempty"`
	SHA256         string         `json:"sha256"`
	Preview        string         `json:"preview,omitempty"`
	PreviewTrunc   bool           `json:"preview_truncated"`
	OriginalLength int            `json:"original_length"`
}

type patternRedactor struct {
	name string
	re   *regexp.Regexp
}

var bodyRedactors = []patternRedactor{
	{"aws_access_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{20,}`)},
	{"openai_api_key", regexp.MustCompile(`sk-[A-Za-z0-9_-]{20,}`)},
	{"anthropic_api_key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)},
	{"bearer_token", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]{12,}`)},
	{"basic_auth", regexp.MustCompile(`(?i)basic\s+[A-Za-z0-9+/=]{12,}`)},
	{"env_secret", regexp.MustCompile(`(?i)\b[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|API[_-]?KEY)[A-Z0-9_]*\s*=\s*['"]?[^'"\s]+`)},
}

func HeaderShouldRedact(name string) bool {
	_, ok := redactedHeaders[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func HashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func RedactBody(body []byte, previewBytes int) RedactionResult {
	if previewBytes <= 0 {
		previewBytes = 2048
	}
	original := string(body)
	redacted := original
	types := map[string]int{}
	for _, redactor := range bodyRedactors {
		matches := redactor.re.FindAllStringIndex(redacted, -1)
		if len(matches) == 0 {
			continue
		}
		types[redactor.name] += len(matches)
		redacted = redactor.re.ReplaceAllString(redacted, "[REDACTED:"+redactor.name+"]")
	}
	preview := redacted
	truncated := false
	if len([]byte(preview)) > previewBytes {
		preview = string([]byte(preview)[:previewBytes])
		truncated = true
	}
	return RedactionResult{
		Value:          redacted,
		Count:          redactionCount(types),
		Types:          types,
		SHA256:         HashString(original),
		Preview:        preview,
		PreviewTrunc:   truncated,
		OriginalLength: len(body),
	}
}

func redactionCount(types map[string]int) int {
	total := 0
	for _, count := range types {
		total += count
	}
	return total
}

func SortedHeaderNames(headers map[string][]string) []string {
	out := make([]string, 0, len(headers))
	for name := range headers {
		out = append(out, strings.ToLower(name))
	}
	sort.Strings(out)
	return out
}
