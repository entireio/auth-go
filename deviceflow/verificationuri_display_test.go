package deviceflow

import (
	"errors"
	"testing"
)

// The verification_uri is shown to the user and opened in their browser;
// visual inspection is the defence the doc comment asks for. A formatting
// character that reorders or hides part of the URL defeats exactly that,
// so it must be rejected the same way a CR or an ESC is.
func TestValidateVerificationURI_RejectsFormattingChars(t *testing.T) {
	t.Parallel()
	for name, r := range map[string]rune{
		"RLO U+202E":  0x202e,
		"LRO U+202D":  0x202d,
		"RLI U+2067":  0x2067,
		"PDI U+2069":  0x2069,
		"LRM U+200E":  0x200e,
		"ZWSP U+200B": 0x200b,
		"BOM U+FEFF":  0xfeff,
		"LS U+2028":   0x2028,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			uri := "https://auth.example.com/device" + string(r) + "/activate"
			if err := validateVerificationURI(uri, false); !errors.Is(err, ErrUnsafeVerificationURI) {
				t.Fatalf("accepted a URI carrying %U: err=%v", r, err)
			}
		})
	}
}

// A plain URL, and one whose path carries ordinary percent-encoding, must
// still pass: the check is a display guard, not a URL grammar.
func TestValidateVerificationURI_AcceptsOrdinaryURLs(t *testing.T) {
	t.Parallel()
	for _, uri := range []string{
		"https://auth.example.com/device",
		"https://auth.example.com/device?user_code=ABCD-EFGH",
		"https://auth.example.com/a%20b",
	} {
		if err := validateVerificationURI(uri, false); err != nil {
			t.Errorf("validateVerificationURI(%q) = %v, want nil", uri, err)
		}
	}
}
