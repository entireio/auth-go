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

// IsDisplayUnsafeRune reports whether r must not reach a terminal or a
// log line verbatim. It is the single definition of "control character"
// for every string this library renders back to the user from
// server-supplied data.
//
// Two families qualify.
//
// Legacy control codes, which drive the terminal directly:
//
//   - C0 controls (U+0000–U+001F): ESC (0x1B) for ANSI sequences, CR,
//     LF, TAB, NUL, BEL, etc.
//   - DEL (U+007F).
//   - C1 controls (U+0080–U+009F): notably CSI (U+009B), which is
//     functionally equivalent to "ESC [" in 8-bit-aware terminals and
//     can start an ANSI escape sequence on its own.
//
// Unicode formatting characters, which change what the reader sees
// without changing the bytes they inspect — the "Trojan Source" class
// (CVE-2021-42574). Filtering only the legacy codes above leaves a
// server able to reorder or hide the very strings these helpers exist
// to make safe to display:
//
//   - Bidirectional embeddings and overrides (U+202A–U+202E) and
//     isolates (U+2066–U+2069) reorder the rendered text, so the
//     characters a user reads need not be the characters they got.
//   - The implicit marks LRM/RLM (U+200E, U+200F) and ALM (U+061C) do
//     the same for adjacent runs.
//   - Zero-width space (U+200B) and BOM/ZWNBSP (U+FEFF) are invisible,
//     so they can split a word — a hostname, a scheme — that then reads
//     as one thing and is another.
//   - LINE SEPARATOR (U+2028) and PARAGRAPH SEPARATOR (U+2029) are
//     treated as line breaks by many log viewers and JS-based
//     consumers, which is the log-injection vector the CR/LF strip
//     above already closes for ASCII.
//
// ZWNJ and ZWJ (U+200C, U+200D) are deliberately *not* rejected: they
// carry real meaning in Indic and Perso-Arabic text and in emoji
// sequences, and neither reorders nor conceals surrounding characters.
func IsDisplayUnsafeRune(r rune) bool {
	switch {
	case r < 0x20: // C0 controls
		return true
	case r == 0x7f: // DEL
		return true
	case r >= 0x80 && r <= 0x9f: // C1 controls (includes CSI U+009B)
		return true
	case r == 0x061c: // ARABIC LETTER MARK
		return true
	case r == 0x200b: // ZERO WIDTH SPACE
		return true
	case r == 0x200e || r == 0x200f: // LRM, RLM
		return true
	case r >= 0x202a && r <= 0x202e: // LRE, RLE, PDF, LRO, RLO
		return true
	case r == 0x2028 || r == 0x2029: // LINE / PARAGRAPH SEPARATOR
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI, RLI, FSI, PDI
		return true
	case r == 0xfeff: // ZERO WIDTH NO-BREAK SPACE (BOM)
		return true
	default:
		return false
	}
}

// SanitizeDescription strips display-unsafe characters and caps length
// so a hostile or buggy AS can't write into the user's terminal or
// balloon CLI logs via the error_description field of an OAuth error
// response.
//
// See IsDisplayUnsafeRune for what is removed and why.
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
		if IsDisplayUnsafeRune(r) {
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
