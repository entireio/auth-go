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

// SanitizeDescription strips control characters and caps length so
// a hostile or buggy AS can't write into the user's terminal or
// balloon CLI logs via the error_description field of an OAuth error
// response.
//
// Rejected ranges:
//
//   - C0 controls (U+0000–U+001F): ESC (0x1b) for ANSI sequences,
//     CR, LF, TAB, NUL, BEL, etc.
//   - DEL (U+007F).
//   - C1 controls (U+0080–U+009F): notably CSI (U+009B), which is
//     functionally equivalent to "ESC [" in 8-bit-aware terminals
//     and can start an ANSI escape sequence on its own.
//
// Preserves printable Unicode (including non-ASCII); truncates on
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
		case r < 0x20: // C0 controls
			continue
		case r == 0x7f: // DEL
			continue
		case r >= 0x80 && r <= 0x9f: // C1 controls (includes CSI U+009B)
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
