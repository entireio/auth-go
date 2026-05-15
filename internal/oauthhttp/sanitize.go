package oauthhttp

import "strings"

// MaxErrorDescriptionRunes caps a sanitised server-supplied
// error_description by rune count. Real values are short ("user
// denied", "code expired", "audience denied"); past this the
// truncated form points at server misbehaviour rather than
// user-facing guidance, and unbounded length is a UX-DoS vector.
// Counted in runes rather than bytes so truncation lands on a valid
// UTF-8 boundary.
const MaxErrorDescriptionRunes = 512

// SanitizeDescription strips control characters (incl. ANSI escapes'
// ESC byte 0x1b, CR, LF, NUL, DEL, BEL) and caps length so a hostile
// or buggy AS can't write into the user's terminal or balloon CLI
// logs via the error_description field of an OAuth error response.
//
// Preserves printable Unicode, including non-ASCII; truncates on
// rune boundaries rather than byte offsets so a CJK / emoji /
// combining-character payload can't be cut mid-rune into invalid
// UTF-8.
func SanitizeDescription(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	runes := 0
	truncated := false
	for _, r := range s {
		switch {
		case r < 0x20: // C0 controls, including ESC (0x1b), CR/LF/TAB/NUL/BEL
			continue
		case r == 0x7f: // DEL
			continue
		}
		if runes >= MaxErrorDescriptionRunes {
			truncated = true
			break
		}
		b.WriteRune(r)
		runes++
	}
	out := strings.TrimSpace(b.String())
	if truncated {
		out += "…"
	}
	return out
}
