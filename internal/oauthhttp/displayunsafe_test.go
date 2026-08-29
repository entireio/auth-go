package oauthhttp_test

import (
	"strings"
	"testing"

	"github.com/entireio/auth-go/internal/oauthhttp"
)

// formattingChars are the Unicode formatting characters that change what
// a reader sees without changing the bytes they inspect. A filter that
// only removes the legacy C0/C1/DEL codes lets every one of them through.
var formattingChars = map[string]rune{
	"ALM U+061C":  0x061c,
	"ZWSP U+200B": 0x200b,
	"LRM U+200E":  0x200e,
	"RLM U+200F":  0x200f,
	"LRE U+202A":  0x202a,
	"RLE U+202B":  0x202b,
	"PDF U+202C":  0x202c,
	"LRO U+202D":  0x202d,
	"RLO U+202E":  0x202e,
	"LS U+2028":   0x2028,
	"PS U+2029":   0x2029,
	"LRI U+2066":  0x2066,
	"RLI U+2067":  0x2067,
	"FSI U+2068":  0x2068,
	"PDI U+2069":  0x2069,
	"BOM U+FEFF":  0xfeff,
}

// Written as code points rather than literals so the fixtures stay
// readable in a diff. ZWNJ and ZWJ carry meaning in Indic, Perso-Arabic,
// and emoji sequences and reorder nothing, so they are deliberately kept.
var (
	esc  = string(rune(0x001b))
	del  = string(rune(0x007f))
	csi  = string(rune(0x009b))
	zwnj = string(rune(0x200c))
	zwj  = string(rune(0x200d))
)

func TestSanitizeDescription_StripsFormattingChars(t *testing.T) {
	t.Parallel()
	for name, r := range formattingChars {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			in := "access denied" + string(r) + " for this audience"
			got := oauthhttp.SanitizeDescription(in)
			if strings.ContainsRune(got, r) {
				t.Fatalf("SanitizeDescription kept %U: %q", r, got)
			}
		})
	}
}

// The legacy control codes must still go, and ordinary text must survive:
// the filter is a display guard, not a charset restriction.
func TestSanitizeDescription_KeepsLegitimateText(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, in, want string }{
		{"C0 escape stripped", "a" + esc + "[31mb", "a[31mb"},
		{"DEL stripped", "a" + del + "b", "ab"},
		{"C1 CSI stripped", "a" + csi + "31mb", "a31mb"},
		{"accented latin", "acces refuse", "acces refuse"},
		{"cjk", "拒绝访问", "拒绝访问"},
		{"zwnj kept", "a" + zwnj + "b", "a" + zwnj + "b"},
		{"zwj sequence kept", "x" + zwj + "y", "x" + zwj + "y"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := oauthhttp.SanitizeDescription(tc.in); got != tc.want {
				t.Fatalf("SanitizeDescription(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsDisplayUnsafeRune(t *testing.T) {
	t.Parallel()
	for name, r := range formattingChars {
		if !oauthhttp.IsDisplayUnsafeRune(r) {
			t.Errorf("%s (%U) reported safe", name, r)
		}
	}
	for _, r := range []rune{0x00, 0x1b, 0x1f, 0x7f, 0x80, 0x9b, 0x9f} {
		if !oauthhttp.IsDisplayUnsafeRune(r) {
			t.Errorf("legacy control %U reported safe", r)
		}
	}
	for _, r := range []rune{'a', ' ', 0x00e9, 0x200c, 0x200d, 0x4e00, 0x1f600} {
		if oauthhttp.IsDisplayUnsafeRune(r) {
			t.Errorf("printable %U reported unsafe", r)
		}
	}
}
