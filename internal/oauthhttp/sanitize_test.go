package oauthhttp

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestSanitizeDescription pins the control-char + length defenses
// against a hostile or buggy AS smuggling ANSI escapes or megabyte
// payloads into the user's terminal via error_description.
func TestSanitizeDescription(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "user denied", "user denied"},
		{"strips CR LF", "hello\r\nworld", "helloworld"},
		{"strips lone ESC byte (printable CSI bytes survive)", "\x1b[31mred", "[31mred"},
		{"strips BEL", "boom\x07", "boom"},
		{"strips NUL", "a\x00b", "ab"},
		{"strips DEL", "a\x7fb", "ab"},
		{"strips CSI (U+009B)", "a\u009b[31mb", "a[31mb"},
		{"strips C1 control U+0080", "a\u0080b", "ab"},
		{"strips C1 control U+009F", "a\u009fb", "ab"},
		{"keeps U+00A0 NBSP (printable, just exotic)", "a\u00a0b", "a\u00a0b"},
		{"keeps unicode", "ご利用ありがとう", "ご利用ありがとう"},
		{"trims whitespace after stripping", "\t hi \t", "hi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := SanitizeDescription(tc.in); got != tc.want {
				t.Fatalf("SanitizeDescription(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	long := strings.Repeat("A", 1000)
	got := SanitizeDescription(long)
	wantRunes := MaxErrorDescriptionRunes + 1 // +1 for the appended ellipsis
	if r := utf8.RuneCountInString(got); r != wantRunes {
		t.Fatalf("SanitizeDescription(<1000 A's>) rune count = %d, want %d", r, wantRunes)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("SanitizeDescription(<1000 A's>) produced invalid UTF-8: %q", got)
	}
}

// TestSanitizeDescription_TruncatesOnRuneBoundary pins the
// truncation-mid-rune defence (Cursor Bugbot finding on the v0.2.0
// PR). A payload of multi-byte runes that would straddle the byte
// cap must not be cut into invalid UTF-8 — truncation has to land on
// a rune boundary.
func TestSanitizeDescription_TruncatesOnRuneBoundary(t *testing.T) {
	t.Parallel()
	// Each "あ" is 3 bytes in UTF-8. 600 of them exceeds the rune cap
	// (and would have been chopped mid-rune by a byte-offset slice
	// once the rune cap moved past a multi-byte boundary).
	in := strings.Repeat("あ", 600)
	got := SanitizeDescription(in)
	if !utf8.ValidString(got) {
		t.Fatalf("SanitizeDescription produced invalid UTF-8 from 600-rune input")
	}
	// Sanity: the runes that survive are all the original CJK char,
	// terminated by the truncation ellipsis.
	for _, r := range got {
		if r != 'あ' && r != '…' {
			t.Fatalf("unexpected rune %U in output", r)
		}
	}
	if r := utf8.RuneCountInString(got); r != MaxErrorDescriptionRunes+1 {
		t.Fatalf("rune count = %d, want %d (cap + ellipsis)", r, MaxErrorDescriptionRunes+1)
	}
}
