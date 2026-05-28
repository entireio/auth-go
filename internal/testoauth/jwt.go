// Package testoauth is a mock OAuth authorization server for end-to-end
// tests of the auth-go Manager and friends. The package is internal
// (test-only) and not part of the public API.
package testoauth

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// Claims are the inputs to MintUnsignedJWT. All time fields are optional
// (zero = omit). Extra carries additional custom claims merged into the
// payload — useful for fields tokens.ParseClaims also reads, e.g. "handle".
type Claims struct {
	Issuer    string
	Subject   string
	Audience  []string
	FamilyID  string
	IssuedAt  time.Time
	NotBefore time.Time
	ExpiresAt time.Time
	Extra     map[string]any
}

// MintUnsignedJWT returns a three-segment JWT (header.payload.junk-sig)
// matching the shape tokens.ParseClaims accepts. The signature segment is
// intentionally invalid — tokens.ParseClaims is unverified-by-design.
//
// alg is "EdDSA" (matching production format and the existing test fixtures
// in tokenmanager_test.go); the helper deliberately avoids "none" because
// ParseClaims rejects unsigned JWTs per RFC 7518 §3.6.
func MintUnsignedJWT(c Claims) string {
	header := map[string]any{"alg": "EdDSA", "typ": "JWT"}
	headerSeg := encodeSegment(header)

	payload := map[string]any{}
	if c.Issuer != "" {
		payload["iss"] = c.Issuer
	}
	if c.Subject != "" {
		payload["sub"] = c.Subject
	}
	if len(c.Audience) > 0 {
		payload["aud"] = c.Audience
	}
	if c.FamilyID != "" {
		payload["fid"] = c.FamilyID
	}
	if !c.IssuedAt.IsZero() {
		payload["iat"] = c.IssuedAt.Unix()
	}
	if !c.NotBefore.IsZero() {
		payload["nbf"] = c.NotBefore.Unix()
	}
	if !c.ExpiresAt.IsZero() {
		payload["exp"] = c.ExpiresAt.Unix()
	}
	for k, v := range c.Extra {
		payload[k] = v
	}
	payloadSeg := encodeSegment(payload)

	sig := base64.RawURLEncoding.EncodeToString([]byte("test-signature-intentionally-invalid"))

	return headerSeg + "." + payloadSeg + "." + sig
}

func encodeSegment(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Marshal of a map[string]any of basic types cannot fail in
		// practice; panic is acceptable for a test-only helper.
		panic("testoauth: encode segment: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
