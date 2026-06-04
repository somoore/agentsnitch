package hookmatch

import (
	"path/filepath"
	"strings"
)

// Installed reports whether cmd is an AgentSnitch hook command for emitter and
// arg. It parses the shell words we write into Claude settings instead of doing
// substring checks, so a command that merely mentions the emitter path does not
// verify as installed.
func Installed(cmd, emitter, arg string) bool {
	argv, ok := ShellFields(cmd)
	if !ok || len(argv) < 2 {
		return false
	}
	return executableMatchesEmitter(argv[0], emitter) && strings.EqualFold(argv[1], arg)
}

// AgentSnitchCommand reports whether cmd looks like an AgentSnitch emitter hook
// and should be removed during uninstall. This is intentionally narrower than a
// text search: argv[0] must be the emitter executable.
func AgentSnitchCommand(cmd, emitter string) bool {
	argv, ok := ShellFields(cmd)
	if !ok || len(argv) == 0 {
		return false
	}
	return executableMatchesEmitter(argv[0], emitter) || looksLikeAgentSnitchEmitter(argv[0])
}

func executableMatchesEmitter(argv0, emitter string) bool {
	argv0 = filepath.Clean(strings.TrimSpace(argv0))
	emitter = filepath.Clean(strings.TrimSpace(emitter))
	if argv0 == "" || emitter == "" {
		return false
	}
	if argv0 == emitter {
		return true
	}
	// Allow the simple dev command "emitter pretooluse" when the configured
	// emitter also has that basename, but do not match "/tmp/not-emitter".
	return !strings.ContainsRune(argv0, filepath.Separator) && argv0 == filepath.Base(emitter)
}

func looksLikeAgentSnitchEmitter(argv0 string) bool {
	clean := filepath.Clean(strings.TrimSpace(argv0))
	return filepath.Base(clean) == "emitter" && strings.Contains(strings.ToLower(clean), "agentsnitch")
}

// ShellFields parses the small POSIX-shell subset emitted by hookctl:
// whitespace-separated argv with single quotes, double quotes, and backslash
// escapes. It is not a shell evaluator; it only recovers argv for identity
// checks.
func ShellFields(s string) ([]string, bool) {
	var out []string
	var b strings.Builder
	inSingle := false
	inDouble := false
	escaped := false
	inField := false

	flush := func() {
		if inField {
			out = append(out, b.String())
			b.Reset()
			inField = false
		}
	}

	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			inField = true
			escaped = false
			continue
		}
		switch {
		case r == '\\' && !inSingle:
			escaped = true
			inField = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
			inField = true
		case r == '"' && !inSingle:
			inDouble = !inDouble
			inField = true
		case (r == ' ' || r == '\t' || r == '\n' || r == '\r') && !inSingle && !inDouble:
			flush()
		default:
			b.WriteRune(r)
			inField = true
		}
	}
	if escaped || inSingle || inDouble {
		return nil, false
	}
	flush()
	return out, true
}
