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

// ReadAndDecodeJSON reads up to MaxResponseBytes from r and decodes
// the body as JSON into dest. When strict is true, unknown fields are
// rejected.
//
// Returns ErrNonJSONResponse when the body is HTML — the captive-
// portal / proxy-interceptor case. Other read or decode failures are
// wrapped with context.
func ReadAndDecodeJSON(r io.Reader, dest any, strict bool) error {
	body, err := io.ReadAll(io.LimitReader(r, MaxResponseBytes))
	if err != nil {
		return fmt.Errorf("read JSON response: %w", err)
	}
	if looksLikeHTML(body) {
		return ErrNonJSONResponse
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(dest); err != nil {
		return fmt.Errorf("decode JSON response: %w", err)
	}
	return nil
}

// looksLikeHTML reports whether body's first non-whitespace byte is
// '<'. That covers HTML, XHTML, XML, and most captive-portal error
// pages without trying to fully sniff the document.
func looksLikeHTML(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 0 && trimmed[0] == '<'
}
