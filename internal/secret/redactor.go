package secret

import (
	"regexp"
	"strings"
)

// builtinPatterns are always active.
var builtinPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password["'\s]*[:=]["'\s]*)\S+`),
	regexp.MustCompile(`(?i)(secret["'\s]*[:=]["'\s]*)\S+`),
	regexp.MustCompile(`(?i)(token["'\s]*[:=]["'\s]*)\S+`),
	regexp.MustCompile(`(?i)(api[_-]?key["'\s]*[:=]["'\s]*)\S+`),
	regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`),
}

// Redactor replaces secret patterns with [REDACTED].
type Redactor struct {
	literals []string
	patterns []*regexp.Regexp
}

// New creates a Redactor. literals are exact strings to redact (e.g., known passwords).
func New(literals []string) *Redactor {
	return &Redactor{
		literals: literals,
		patterns: builtinPatterns,
	}
}

// Redact replaces all detected secrets in s with [REDACTED].
func (r *Redactor) Redact(s string) string {
	for _, lit := range r.literals {
		if lit != "" {
			s = strings.ReplaceAll(s, lit, "[REDACTED]")
		}
	}
	for _, pat := range r.patterns {
		s = pat.ReplaceAllStringFunc(s, func(match string) string {
			// For key=value patterns keep the key part, redact value
			sub := pat.FindStringSubmatchIndex(match)
			if len(sub) >= 4 && sub[2] >= 0 {
				// Has a capture group (key part) — keep key, redact value
				return match[:sub[3]] + "[REDACTED]"
			}
			return "[REDACTED]"
		})
	}
	return s
}

// RedactMap redacts all string values in a params map.
func (r *Redactor) RedactMap(params map[string]any) map[string]any {
	if params == nil {
		return nil
	}
	out := make(map[string]any, len(params))
	for k, v := range params {
		if s, ok := v.(string); ok {
			out[k] = r.Redact(s)
		} else {
			out[k] = v
		}
	}
	return out
}
