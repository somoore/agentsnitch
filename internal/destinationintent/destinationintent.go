package destinationintent

import (
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

var urlPattern = regexp.MustCompile(`(?i)\b(?:https?|ssh|git)://[^\s"'<>]+`)

// Extract returns host-level destinations implied by a tool call. It is
// semantic intent, not network proof; OS network observers still prove egress.
func Extract(tool, target, command string, input map[string]interface{}) []string {
	var out []string
	scan := func(value string) {
		out = appendDestination(out, value)
		for _, match := range urlPattern.FindAllString(value, -1) {
			out = appendDestination(out, match)
		}
	}

	scan(target)
	for _, value := range stringValues(input, 0) {
		scan(value)
	}
	for _, token := range shellTokens(command) {
		out = appendDestination(out, token)
	}
	for _, token := range networkCommandArgs(command) {
		out = appendDestination(out, token)
	}
	if strings.EqualFold(tool, "WebFetch") {
		out = appendDestination(out, target)
	}
	if strings.EqualFold(tool, "WebSearch") {
		out = appendSearchProviderIntents(out, target, command, input)
	}
	return out
}

func appendDestination(out []string, value string) []string {
	host := normalizeDestination(value)
	if host == "" {
		return out
	}
	for _, existing := range out {
		if existing == host {
			return out
		}
	}
	return append(out, host)
}

func appendSearchProviderIntents(out []string, target, command string, input map[string]interface{}) []string {
	values := []string{target, command}
	values = append(values, stringValues(input, 0)...)
	for _, value := range values {
		lower := strings.ToLower(value)
		for _, pair := range []struct {
			needle string
			host   string
		}{
			{"github", "github.com"},
			{"gitlab", "gitlab.com"},
			{"npm", "npmjs.com"},
			{"pypi", "pypi.org"},
		} {
			if strings.Contains(lower, pair.needle) {
				out = appendDestination(out, pair.host)
			}
		}
	}
	return out
}

func normalizeDestination(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`+"`")
	value = strings.TrimRight(value, ".,;)")
	value = strings.TrimLeft(value, "(")
	if value == "" || strings.ContainsAny(value, " \t\n\r") {
		return ""
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") {
		return ""
	}

	if parsed, err := url.Parse(value); err == nil && parsed.Scheme != "" {
		return normalizeHost(parsed.Host)
	}
	if idx := strings.IndexAny(value, "?#"); idx >= 0 {
		value = value[:idx]
	}
	if strings.Contains(value, "/") {
		value = strings.SplitN(value, "/", 2)[0]
	}
	if at := strings.LastIndex(value, "@"); at >= 0 {
		value = value[at+1:]
	}
	if colon := strings.Index(value, ":"); colon > 0 {
		// git@github.com:org/repo.git and scp-style user@host:path.
		value = value[:colon]
	}
	return normalizeHost(value)
}

func normalizeHost(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.Trim(value, "[]")
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = strings.Trim(host, "[]")
	}
	if value == "localhost" {
		return value
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.String()
	}
	if !strings.Contains(value, ".") {
		return ""
	}
	for _, part := range strings.Split(value, ".") {
		if part == "" {
			return ""
		}
	}
	return value
}

func stringValues(value interface{}, depth int) []string {
	if depth > 3 || value == nil {
		return nil
	}
	switch v := value.(type) {
	case string:
		return []string{v}
	case map[string]interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, stringValues(item, depth+1)...)
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, stringValues(item, depth+1)...)
		}
		return out
	default:
		return nil
	}
}

func shellTokens(command string) []string {
	fields := strings.FieldsFunc(command, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ';', '|', '&', '(', ')':
			return true
		default:
			return false
		}
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}

func networkCommandArgs(command string) []string {
	tokens := shellTokens(command)
	out := make([]string, 0, len(tokens))
	networkCommands := map[string]struct{}{
		"curl": {}, "wget": {}, "git": {}, "gh": {}, "npm": {}, "pnpm": {}, "yarn": {},
		"pip": {}, "pip3": {}, "go": {}, "docker": {}, "ssh": {}, "scp": {}, "rsync": {},
	}
	for i, token := range tokens {
		base := token
		if slash := strings.LastIndex(base, "/"); slash >= 0 {
			base = base[slash+1:]
		}
		if _, ok := networkCommands[strings.ToLower(strings.Trim(base, `"'`+"`"))]; !ok {
			continue
		}
		for _, arg := range tokens[i+1:] {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			out = append(out, arg)
			if len(out) >= 4 {
				return out
			}
		}
	}
	return out
}
