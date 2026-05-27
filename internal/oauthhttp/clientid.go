package oauthhttp

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ValidateClientID enforces the byte-level constraints RFC 6749 §2.3.1
// and RFC 7617 §2 place on a client_id traveling via HTTP Basic Auth:
// VSCHAR (printable ASCII, 0x20–0x7E) and no ':' (the Basic Auth field
// separator). Without this guard, url.QueryEscape at the call site would
// percent-encode forbidden bytes, slip them past the wire validator, and
// surface as opaque server-side rejections after a QueryUnescape round-trip.
//
// An empty client_id is permitted: public clients that don't authenticate
// at the token endpoint omit the credential entirely.
func ValidateClientID(id string) error {
	if strings.ContainsRune(id, ':') {
		return errors.New("ClientID must not contain ':' (RFC 7617 §2)")
	}
	for _, r := range id {
		if r < 0x20 || r > 0x7E {
			return fmt.Errorf("ClientID contains non-printable or non-ASCII byte %U (RFC 6749 §2.3.1 requires VSCHAR)", r)
		}
	}
	return nil
}

// ValidateClientIDConsistency rejects requests that set client_id on both
// the typed field and Extra to different values, or that put more than one
// client_id in Extra. The two surfaces are populated independently — typed
// field becomes Basic Auth, Extra becomes form body — and a server reading
// one but not the other would silently accept the wrong identity.
// Same-value duplication is the documented belt-and-braces pattern.
//
// Multiple client_id entries in Extra are always rejected, even when id
// is unset: servers that read via r.PostFormValue see only the first;
// servers that read via r.PostForm["client_id"] see all, so a slice like
// ["a","b"] succeeds against one and fails against the other in ways the
// caller can't predict.
func ValidateClientIDConsistency(id string, extra url.Values) error {
	if extra == nil {
		return nil
	}
	extras := extra["client_id"]
	if len(extras) > 1 {
		return fmt.Errorf("extra %q must hold at most one value, got %d", "client_id", len(extras))
	}
	if id == "" || len(extras) == 0 {
		return nil
	}
	if extras[0] != id {
		return fmt.Errorf("ClientID (%q) and Extra[%q] (%q) disagree", id, "client_id", extras[0])
	}
	return nil
}
