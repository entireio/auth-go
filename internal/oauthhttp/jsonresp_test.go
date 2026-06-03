package oauthhttp

import (
	"errors"
	"strings"
	"testing"
)

func TestReadAndDecodeJSON_Success(t *testing.T) {
	t.Parallel()

	var got struct {
		A string `json:"a"`
		B int    `json:"b"`
	}
	err := ReadAndDecodeJSON(strings.NewReader(`{"a":"x","b":42}`), &got, false)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if got.A != "x" || got.B != 42 {
		t.Fatalf("got = %+v", got)
	}
}

func TestReadAndDecodeJSON_StrictRejectsUnknown(t *testing.T) {
	t.Parallel()

	var got struct {
		A string `json:"a"`
	}
	err := ReadAndDecodeJSON(strings.NewReader(`{"a":"x","extra":1}`), &got, true)
	if err == nil {
		t.Fatal("strict mode should reject unknown fields")
	}
	if errors.Is(err, ErrNonJSONResponse) {
		t.Fatal("decode failure misclassified as non-JSON")
	}
}

func TestReadAndDecodeJSON_TolerantUnknown(t *testing.T) {
	t.Parallel()

	var got struct {
		A string `json:"a"`
	}
	err := ReadAndDecodeJSON(strings.NewReader(`{"a":"x","extra":1}`), &got, false)
	if err != nil {
		t.Fatalf("non-strict should accept unknown fields, got %v", err)
	}
}

func TestReadAndDecodeJSON_DetectsHTMLBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{"plain HTML", `<html><body>Access denied</body></html>`},
		{"DOCTYPE", `<!DOCTYPE html><html></html>`},
		{"leading whitespace + HTML", "   \n\t<html></html>"},
		{"XML", `<?xml version="1.0"?><error/>`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var dest map[string]any
			err := ReadAndDecodeJSON(strings.NewReader(tt.body), &dest, false)
			if !errors.Is(err, ErrNonJSONResponse) {
				t.Fatalf("error = %v, want ErrNonJSONResponse", err)
			}
		})
	}
}

func TestReadAndDecodeJSON_SurfacesGenuineDecodeErrors(t *testing.T) {
	t.Parallel()

	var dest map[string]any
	err := ReadAndDecodeJSON(strings.NewReader(`{"a": not json}`), &dest, false)
	if err == nil {
		t.Fatal("malformed JSON should error")
	}
	if errors.Is(err, ErrNonJSONResponse) {
		t.Fatal("malformed-but-not-HTML should not be flagged as non-JSON response")
	}
	if !strings.Contains(err.Error(), "decode JSON response") {
		t.Fatalf("error = %v, want wrapped decode error", err)
	}
}

func TestReadAndDecodeJSON_EmptyBody(t *testing.T) {
	t.Parallel()

	var dest map[string]any
	err := ReadAndDecodeJSON(strings.NewReader(""), &dest, false)
	if err == nil {
		t.Fatal("empty body should error")
	}
	if errors.Is(err, ErrNonJSONResponse) {
		t.Fatal("empty body shouldn't be flagged as HTML")
	}
}

func TestReadAndDecodeJSON_RejectsOversizedBody(t *testing.T) {
	t.Parallel()

	var dest map[string]any
	err := ReadAndDecodeJSON(strings.NewReader(strings.Repeat(" ", MaxResponseBytes+1)), &dest, false)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v, want ErrResponseTooLarge", err)
	}
}

func TestReadAndDecodeJSON_RejectsTrailingData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{"trailing JSON value", `{"a":1} {"b":2}`},
		{"trailing garbage", `{"a":1} not json`},
		{"trailing single byte", `{"a":1}x`},
		{"trailing whitespace then garbage", "{\"a\":1}\n\tx"},
	}
	// In strict mode we route through *json.Decoder and emit our own
	// "trailing data after JSON value" message; in non-strict mode
	// json.Unmarshal's "after top-level value" surfaces. Either is
	// acceptable — both name the trailing condition explicitly. The
	// test pins the rejection rather than the exact wording.
	wantSubstrs := []string{"trailing data", "after top-level value"}
	containsAny := func(s string, subs []string) bool {
		for _, sub := range subs {
			if strings.Contains(s, sub) {
				return true
			}
		}
		return false
	}
	for _, tc := range tests {
		for _, strict := range []bool{false, true} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				var dest map[string]any
				err := ReadAndDecodeJSON(strings.NewReader(tc.body), &dest, strict)
				if err == nil || !containsAny(err.Error(), wantSubstrs) {
					t.Fatalf("strict=%v error = %v, want trailing-data marker", strict, err)
				}
			})
		}
	}
}

// TestReadAndDecodeJSON_AcceptsTrailingWhitespace pins the JSON-spec
// whitespace set (RFC 8259 §2: space, tab, LF, CR) as the only bytes
// allowed after the top-level value.
func TestReadAndDecodeJSON_AcceptsTrailingWhitespace(t *testing.T) {
	t.Parallel()

	bodies := []string{
		`{"a":1}`,
		`{"a":1} `,
		"{\"a\":1}\n",
		"{\"a\":1}\r\n",
		"{\"a\":1}\t \n  ",
	}
	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			var dest map[string]any
			if err := ReadAndDecodeJSON(strings.NewReader(body), &dest, false); err != nil {
				t.Fatalf("body=%q err=%v", body, err)
			}
		})
	}
}

func TestErrNonJSONResponse_MessageIsActionable(t *testing.T) {
	t.Parallel()

	msg := ErrNonJSONResponse.Error()
	for _, want := range []string{"non-JSON", "VPN", "proxy", "firewall"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q: %s", want, msg)
		}
	}
}
