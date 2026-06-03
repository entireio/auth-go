// Package oauthhttp holds shared HTTP-response helpers used by the
// auth subpackages. Internal: only auth/* may import.
package oauthhttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxResponseBytes caps how much of an OAuth response body we read.
// Both device-flow and token-exchange endpoints return small JSON
// documents; larger bodies indicate a misconfigured proxy or an
// attempt to exhaust client memory.
const MaxResponseBytes = 1 << 20

// ErrNonJSONResponse is returned by ReadAndDecodeJSON when a 200 OK
// from the authorization server's body looks like HTML rather than
// JSON — typically a captive portal, corporate proxy, or VPN firewall
// (Cloudflare WARP, etc.) intercepting the request and returning an
// error page.
//
// Callers can match with errors.Is and surface a UX message; the
// default Error() string is already user-readable.
var ErrNonJSONResponse = errors.New(
	"could not reach authentication server: server returned non-JSON " +
		"response (check VPN, proxy, or firewall — e.g. Cloudflare WARP)",
)

// ErrResponseTooLarge is returned when an OAuth endpoint returns a
// response body larger than MaxResponseBytes. The helpers read one byte
// past the cap so callers get an explicit error instead of silently
// parsing a truncated response.
var ErrResponseTooLarge = errors.New("OAuth response body exceeds maximum size")

// ReadAndDecodeJSON reads up to MaxResponseBytes from r and decodes
// the body as JSON into dest. When strict is true, unknown fields are
// rejected.
//
// Returns ErrNonJSONResponse when the body is HTML — the captive-
// portal / proxy-interceptor case. Other read or decode failures are
// wrapped with context.
func ReadAndDecodeJSON(r io.Reader, dest any, strict bool) error {
	body, err := readLimitedBody(r)
	if err != nil {
		return fmt.Errorf("read JSON response: %w", err)
	}
	if looksLikeHTML(body) {
		return ErrNonJSONResponse
	}

	// Strict path: DisallowUnknownFields is decoder-only, so we keep
	// *json.Decoder here. Reject trailing data with a single-pass scan
	// of the unconsumed bytes (see hasTrailingNonWhitespace) rather
	// than a second Decode — avoids an `any` allocation and parser
	// error text derived from attacker-controlled bytes.
	if strict {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(dest); err != nil {
			return fmt.Errorf("decode JSON response: %w", err)
		}
		if hasTrailingNonWhitespace(body[dec.InputOffset():]) {
			return errors.New("decode JSON response: trailing data after JSON value")
		}
		return nil
	}

	// Non-strict (hot) path: json.Unmarshal bypasses *json.Decoder and
	// *bytes.Reader, validates the whole body in one byte scan via
	// stdlib's checkValid, and short-circuits on the first non-whitespace
	// trailing byte — so a hostile body can't trick us into parsing a
	// second JSON document. Net: −2 allocs per token response vs the
	// decoder path. The trade-off is the trailing-data error message:
	// stdlib emits "json: invalid character 'X' after top-level value"
	// rather than our "trailing data after JSON value" — one byte of
	// attacker-controlled input ends up in the error text. Acceptable
	// for token endpoints (the byte is %q-escaped and the error never
	// gets surfaced to a terminal without going through
	// SanitizeDescription first).
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("decode JSON response: %w", err)
	}
	return nil
}

// hasTrailingNonWhitespace reports whether b contains any byte that
// encoding/json would not treat as inter-token whitespace. Mirrors the
// JSON spec's whitespace set (RFC 8259 §2): space, tab, LF, CR.
func hasTrailingNonWhitespace(b []byte) bool {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		}
		return true
	}
	return false
}

// looksLikeHTML reports whether body's first non-whitespace byte is
// '<'. That covers HTML, XHTML, XML, and most captive-portal error
// pages without trying to fully sniff the document.
func looksLikeHTML(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 0 && trimmed[0] == '<'
}
