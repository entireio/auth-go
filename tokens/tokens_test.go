package tokens

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestTokenSet_Expired(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		set  TokenSet
		want bool
	}{
		{"zero expiry never expires", TokenSet{}, false},
		{"future expiry", TokenSet{ExpiresAt: now.Add(time.Hour)}, false},
		{"past expiry", TokenSet{ExpiresAt: now.Add(-time.Second)}, true},
		{"exact moment is expired", TokenSet{ExpiresAt: now}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.set.Expired(now); got != tt.want {
				t.Fatalf("Expired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenSet_ShouldRefresh(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	skew := 30 * time.Second

	tests := []struct {
		name string
		set  TokenSet
		want bool
	}{
		{"zero expiry never refreshes", TokenSet{}, false},
		{"comfortably future", TokenSet{ExpiresAt: now.Add(time.Hour)}, false},
		{"within skew window", TokenSet{ExpiresAt: now.Add(15 * time.Second)}, true},
		{"already expired", TokenSet{ExpiresAt: now.Add(-time.Second)}, true},
		{"exactly at skew boundary", TokenSet{ExpiresAt: now.Add(skew)}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.set.ShouldRefresh(now, skew); got != tt.want {
				t.Fatalf("ShouldRefresh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenSet_HasRefresh(t *testing.T) {
	t.Parallel()
	if (TokenSet{}).HasRefresh() {
		t.Fatal("empty TokenSet should not have a refresh token")
	}
	if !(TokenSet{RefreshToken: "x"}).HasRefresh() {
		t.Fatal("TokenSet with refresh token should report true")
	}
}

// makeJWT builds a well-formed JWT with a non-none alg header — the
// default for production-shape claims tests. ParseClaims rejects
// alg:none, so any test that needs the unsigned shape must use
// makeJWTWithHeader explicitly.
func makeJWT(t *testing.T, payload any) string {
	t.Helper()
	return makeJWTWithHeader(t, `{"alg":"EdDSA","typ":"JWT"}`, payload)
}

// makeJWTWithHeader builds a well-formed JWT with the given header
// JSON and claim payload. Signature is a placeholder ("sig") since
// ParseClaims is unverified-by-design; tests that need a real
// signature should reach for a JOSE library.
func makeJWTWithHeader(t *testing.T, header string, payload any) string {
	t.Helper()
	encHeader := base64.RawURLEncoding.EncodeToString([]byte(header))
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return encHeader + "." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
}

func TestParseClaims_BasicFields(t *testing.T) {
	t.Parallel()

	jwt := makeJWT(t, map[string]any{
		"iss":    "https://entire.io",
		"sub":    "01HX...",
		"aud":    "entire-cli",
		"exp":    1800000000,
		"iat":    1799999000,
		"handle": "alex",
	})

	got, err := ParseClaims(jwt)
	if err != nil {
		t.Fatalf("ParseClaims() error = %v", err)
	}

	if got.Issuer != "https://entire.io" {
		t.Errorf("Issuer = %q", got.Issuer)
	}
	if got.Subject != "01HX..." {
		t.Errorf("Subject = %q", got.Subject)
	}
	if got.Handle != "alex" {
		t.Errorf("Handle = %q", got.Handle)
	}
	if !got.ExpiresAt.Equal(time.Unix(1800000000, 0).UTC()) {
		t.Errorf("ExpiresAt = %v", got.ExpiresAt)
	}
	if len(got.Audience) != 1 || got.Audience[0] != "entire-cli" {
		t.Errorf("Audience = %v", got.Audience)
	}
}

func TestParseClaims_AudienceArray(t *testing.T) {
	t.Parallel()

	jwt := makeJWT(t, map[string]any{
		"aud": []string{"entire-cli", "entire-server"},
	})

	got, err := ParseClaims(jwt)
	if err != nil {
		t.Fatalf("ParseClaims() error = %v", err)
	}
	if len(got.Audience) != 2 || got.Audience[0] != "entire-cli" || got.Audience[1] != "entire-server" {
		t.Fatalf("Audience = %v", got.Audience)
	}
}

func TestParseClaims_MissingFieldsAreZero(t *testing.T) {
	t.Parallel()

	jwt := makeJWT(t, map[string]any{})
	got, err := ParseClaims(jwt)
	if err != nil {
		t.Fatalf("ParseClaims() error = %v", err)
	}

	if got.Issuer != "" || got.Subject != "" || got.Handle != "" {
		t.Errorf("expected zero strings, got %+v", got)
	}
	if !got.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt should be zero, got %v", got.ExpiresAt)
	}
	if len(got.Audience) != 0 {
		t.Errorf("Audience should be empty, got %v", got.Audience)
	}
}

func TestParseClaims_MalformedJWT(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"two segments", "header.payload"},
		{"four segments", "a.b.c.d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseClaims(tt.input)
			if !errors.Is(err, ErrMalformedJWT) {
				t.Fatalf("ParseClaims(%q) error = %v, want ErrMalformedJWT", tt.input, err)
			}
		})
	}
}

func TestParseClaims_BadBase64(t *testing.T) {
	t.Parallel()

	_, err := ParseClaims("header.!!!.sig")
	if err == nil {
		t.Fatal("ParseClaims() with bad base64 should fail")
	}
}

func TestParseClaims_BadJSON(t *testing.T) {
	t.Parallel()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`not json`))
	_, err := ParseClaims(header + "." + payload + ".sig")
	if err == nil {
		t.Fatal("ParseClaims() with bad JSON should fail")
	}
}

// TestParseClaims_RejectsUnsignedJWT pins the alg:none defense.
// An attacker who can present a JWT to the CLI must not be able to
// craft one with arbitrary claims that pass shape checks. Even though
// ParseClaims is documented as unverified and is used only for routing
// decisions, future callers might be tempted to rely on the values —
// rejecting alg:none at the source keeps that door closed.
func TestParseClaims_RejectsUnsignedJWT(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		header string
	}{
		{"none lowercase", `{"alg":"none","typ":"JWT"}`},
		{"None capitalised", `{"alg":"None","typ":"JWT"}`},
		{"NONE uppercase", `{"alg":"NONE","typ":"JWT"}`},
		{"none with whitespace", `{"alg":"  none  ","typ":"JWT"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			jwt := makeJWTWithHeader(t, tc.header, map[string]any{
				"iss": "https://attacker.example.com",
				"sub": "account:not-real",
				"aud": "entire-api",
			})
			_, err := ParseClaims(jwt)
			if !errors.Is(err, ErrUnsignedJWT) {
				t.Fatalf("ParseClaims(alg:%q) error = %v, want ErrUnsignedJWT", tc.header, err)
			}
		})
	}
}

// TestParseClaims_AcceptsSignedAlgs sanity check: any alg other than
// none parses successfully (signature itself is not verified). Pins
// the contract that the alg-rejection logic is narrowly scoped to the
// known-bad value.
func TestParseClaims_AcceptsSignedAlgs(t *testing.T) {
	t.Parallel()

	algs := []string{"HS256", "RS256", "ES256", "EdDSA", "PS512"}
	for _, alg := range algs {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()
			jwt := makeJWTWithHeader(t,
				`{"alg":"`+alg+`","typ":"JWT"}`,
				map[string]any{"iss": "https://example.com", "sub": "x"})
			c, err := ParseClaims(jwt)
			if err != nil {
				t.Fatalf("ParseClaims(alg:%q) error = %v", alg, err)
			}
			if c.Issuer != "https://example.com" {
				t.Fatalf("alg:%q claims not parsed: %+v", alg, c)
			}
		})
	}
}
