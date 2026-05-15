// Package tokens defines the post-protocol token shape and helpers for
// reading unverified claims out of JWT access tokens.
//
// The wire-shape responses from RFC 8628 / RFC 8693 endpoints are
// translated into a single TokenSet with absolute expiry. Clients that
// only ever see access tokens as opaque bearer strings need not import
// this package directly.
package tokens

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TokenSet is an OAuth token bundle returned from a device-flow or
// token-exchange endpoint, normalised to absolute expiry.
//
// RefreshToken is empty when the issuer didn't return one. ExpiresAt is
// zero for tokens that don't carry a wire-side expires_in.
type TokenSet struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time
	Scope        string
}

// HasRefresh reports whether the set carries a refresh token.
func (t TokenSet) HasRefresh() bool { return t.RefreshToken != "" }

// String redacts the AccessToken and RefreshToken so accidental
// log/print-debug exposure (e.g. `fmt.Printf("%+v", ts)`) doesn't
// leak the bearer to the user's terminal, log aggregator, or crash
// report. Length of the elided value is preserved so callers can
// still tell "had a token / didn't" at a glance.
//
// To get the raw values, read the struct fields directly. Note that
// fmt and log packages reach for Stringer first, so the redacted
// form is what shows up by default.
func (t TokenSet) String() string {
	return fmt.Sprintf(
		"TokenSet{AccessToken:%s RefreshToken:%s TokenType:%q ExpiresAt:%s Scope:%q}",
		ElideSecret(t.AccessToken),
		ElideSecret(t.RefreshToken),
		t.TokenType,
		t.ExpiresAt.Format(time.RFC3339),
		t.Scope,
	)
}

// GoString delegates to String so %#v in fmt also redacts the secret
// fields. Without this, `fmt.Sprintf("%#v", ts)` would dump the raw
// struct and reveal the AccessToken.
func (t TokenSet) GoString() string { return t.String() }

// ElideSecret returns a `<elided:N bytes>` placeholder when s is
// non-empty, `""` otherwise. Length is preserved so callers can see
// "this had a token of length N" without seeing the token itself.
// Exported because deviceflow.DeviceCode and sts.ExchangeRequest
// both have their own Stringer methods that need to redact secrets
// in the same way — duplicating this two-line helper across three
// packages would invite the same fix-one-miss-the-other hazard as
// the sanitize duplication v0.2.0 consolidated.
func ElideSecret(s string) string {
	if s == "" {
		return `""`
	}
	return fmt.Sprintf("<elided:%d bytes>", len(s))
}

// Expired reports whether the access token's advertised lifetime has
// elapsed at now. Returns false for tokens with a zero ExpiresAt.
func (t TokenSet) Expired(now time.Time) bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(t.ExpiresAt)
}

// ShouldRefresh reports whether the access token is within skew of
// expiring (or has already expired). Tokens without an advertised
// expiry never need refreshing.
func (t TokenSet) ShouldRefresh(now time.Time, skew time.Duration) bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return !now.Add(skew).Before(t.ExpiresAt)
}

// UnverifiedClaims holds the fields parsed from a JWT access token's
// payload. The name carries a deliberate warning: the signature is
// not verified by this library, so the fields are attacker-controlled
// if an unsigned JWT slips through.
//
// Signature verification is the issuing server's responsibility; this
// package never validates signatures. Clients read claims for routing
// (which issuer, which audience) and UX (display the principal
// handle) — never as a security boundary.
type UnverifiedClaims struct {
	Issuer    string
	Subject   string
	Audience  []string
	Handle    string
	ExpiresAt time.Time
	IssuedAt  time.Time
	NotBefore time.Time
}

// ErrMalformedJWT is returned by ParseClaims when the input is not a
// well-formed JWT (three base64url-encoded segments separated by dots).
var ErrMalformedJWT = errors.New("malformed JWT")

// ErrUnsignedJWT is returned by ParseClaims when the JWT header
// declares `alg: none`. The unsigned-JWT shape was deprecated by
// RFC 7518 §3.6 and is a known attack vector (an attacker can craft
// arbitrary claims that pass shape checks). Defense in depth: even
// though this package never trusts claims for authorization
// decisions, we refuse to parse them so a future caller can't be
// tricked into routing on attacker-controlled values.
var ErrUnsignedJWT = errors.New("refusing to parse unsigned JWT (alg:none)")

// ParseClaims decodes the payload segment of jwt without verifying the
// signature. Audience is normalised to a slice even when the wire form
// is a single string.
//
// Rejects JWTs whose header declares `alg: none` — see ErrUnsignedJWT
// for the rationale. The signature payload itself is still not
// verified; that remains the issuing server's responsibility.
func ParseClaims(jwt string) (*UnverifiedClaims, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 segments, got %d", ErrMalformedJWT, len(parts))
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: decode header: %w", ErrMalformedJWT, err)
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(header, &hdr); err != nil {
		return nil, fmt.Errorf("%w: parse header: %w", ErrMalformedJWT, err)
	}
	// JWS algorithm identifiers (RFC 7515 §4.1.1, IANA "JSON Web
	// Signature and Encryption Algorithms" registry) are ASCII
	// alphanumeric only — "HS256", "RS512", "EdDSA", "none", …
	//
	// Anything else is malformed. Rejecting non-alphanumeric runes
	// here closes a class of bypasses against the alg:none check:
	// `strings.TrimSpace` only handles unicode.IsSpace, missing
	// U+200B (zero-width space), U+FEFF (BOM), and other invisible
	// chars that a hostile AS could pad around "none" to slip past
	// a case-fold comparison.
	for _, r := range hdr.Alg {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			continue
		}
		return nil, fmt.Errorf("%w: alg contains non-alphanumeric character", ErrMalformedJWT)
	}
	// Case-insensitive because RFC 7515 §4.1.1 doesn't strictly
	// canonicalise case, and "None" / "NONE" have been observed in
	// the wild.
	if strings.EqualFold(hdr.Alg, "none") {
		return nil, ErrUnsignedJWT
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: decode payload: %w", ErrMalformedJWT, err)
	}

	var raw struct {
		Iss    string          `json:"iss"`
		Sub    string          `json:"sub"`
		Aud    json.RawMessage `json:"aud"`
		Exp    int64           `json:"exp"`
		Iat    int64           `json:"iat"`
		Nbf    int64           `json:"nbf"`
		Handle string          `json:"handle"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("%w: parse payload: %w", ErrMalformedJWT, err)
	}

	c := &UnverifiedClaims{
		Issuer:  raw.Iss,
		Subject: raw.Sub,
		Handle:  raw.Handle,
	}

	if raw.Exp != 0 {
		c.ExpiresAt = time.Unix(raw.Exp, 0).UTC()
	}
	if raw.Iat != 0 {
		c.IssuedAt = time.Unix(raw.Iat, 0).UTC()
	}
	if raw.Nbf != 0 {
		c.NotBefore = time.Unix(raw.Nbf, 0).UTC()
	}

	c.Audience, err = decodeAudience(raw.Aud)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// decodeAudience handles both string and string-array forms of the JWT
// `aud` claim.
func decodeAudience(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == "" {
			return nil, nil
		}
		return []string{single}, nil
	}

	var multi []string
	if err := json.Unmarshal(raw, &multi); err == nil {
		return multi, nil
	}

	return nil, fmt.Errorf("%w: aud claim is neither a string nor a string array", ErrMalformedJWT)
}
