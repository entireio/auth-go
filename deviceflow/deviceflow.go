// Package deviceflow is an RFC 8628 OAuth 2.0 Device Authorization
// Grant client.
//
// Construct a Client with the issuer's BaseURL plus the paths and
// client_id it expects, then call StartDeviceAuth followed by repeated
// PollDeviceAuth calls until either a TokenSet comes back or a
// terminal error is returned. Caller drives the polling loop and
// adjusts the interval on ErrSlowDown per RFC 8628 §3.5.
//
// The client is provider-agnostic: every server-specific value
// (endpoint paths, client_id, optional scope) is configured at
// construction time. There is no provider detection.
package deviceflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/entireio/auth-go/internal/oauthhttp"
	"github.com/entireio/auth-go/tokens"
)

// nowFunc is the package's clock. Tests override it; production uses
// time.Now.
var nowFunc = time.Now

// deviceCodeGrantType is the RFC 8628 token-endpoint grant_type for
// polling device-flow authorization.
const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// DeviceCode is the response from the device authorization endpoint
// (RFC 8628 §3.2). Pass DeviceCode through to subsequent PollDeviceAuth
// calls and show UserCode + VerificationURI to the user.
type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// DefaultRequestTimeout caps a single device-flow HTTP round-trip
// (StartDeviceAuth or one PollDeviceAuth call). Set conservatively:
// healthy device-flow endpoints respond in sub-seconds, so the cap
// mainly defends against slow-loris responses dripping bytes within
// MaxResponseBytes — see Client.RequestTimeout for the per-Client
// override. The polling-loop interval is the caller's concern; this
// timeout governs only the individual HTTP request.
const DefaultRequestTimeout = 30 * time.Second

// Client polls an RFC 8628 device authorization grant.
//
// All configuration is explicit; the package has no global state and
// no implicit URLs. Provide BaseURL, ClientID, and the two endpoint
// paths; the rest is RFC 8628 mechanics.
type Client struct {
	// Transport supplies the http.RoundTripper used for all calls.
	// nil → http.DefaultTransport. The library builds its own
	// *http.Client around this transport so callers can't trivially
	// pass a *http.Client with a misconfigured TLS bypass (the prior
	// HTTP *http.Client field made that a one-liner). Custom
	// RoundTrippers that wrap or replace TLS verification remain the
	// caller's responsibility; this hook is for observability
	// (request/response logging) and per-environment proxies, not
	// security bypass.
	Transport http.RoundTripper

	BaseURL        string
	ClientID       string
	Scope          string
	UserAgent      string
	DeviceCodePath string
	TokenPath      string

	// RequestTimeout is the per-request deadline applied via
	// context.WithTimeout on top of the caller's context. Zero falls
	// back to DefaultRequestTimeout. Negative disables the cap (useful
	// for tests that want to drive timing via the caller's ctx alone).
	RequestTimeout time.Duration

	// AllowInsecureHTTP permits http:// BaseURLs. Default (false) is
	// reject — the device-flow token endpoint returns the user's
	// freshly-minted access token in the response body and must be
	// TLS-protected end to end. Production callers MUST leave this
	// false; only tests and local development pinned to loopback
	// should flip it.
	AllowInsecureHTTP bool
}

// httpClient builds the *http.Client used for one request. The
// transport is c.Transport when non-nil; otherwise http.DefaultTransport.
// We always construct a fresh *http.Client (rather than caching one)
// because the per-request timeout is driven by ctx.WithTimeout in the
// caller, not by *http.Client.Timeout — keeping construction local
// avoids accidentally sharing state across Clients.
func (c *Client) httpClient() *http.Client {
	if c.Transport == nil {
		return http.DefaultClient
	}
	return &http.Client{Transport: c.Transport}
}

// requestTimeout resolves the effective per-request timeout: the
// configured RequestTimeout if positive, the package default if zero,
// or zero (no cap) if negative.
func (c *Client) requestTimeout() time.Duration {
	switch {
	case c.RequestTimeout < 0:
		return 0
	case c.RequestTimeout == 0:
		return DefaultRequestTimeout
	default:
		return c.RequestTimeout
	}
}

// Sentinel errors returned by PollDeviceAuth when the token endpoint
// responds with a recognised RFC 8628 §3.5 error code. Callers branch
// on these with errors.Is and adjust their polling loop accordingly.
var (
	// ErrAuthorizationPending — user has not yet approved or denied.
	// Caller polls again at the existing interval.
	ErrAuthorizationPending = errors.New("authorization_pending")

	// ErrSlowDown — caller is polling too fast. Caller bumps the
	// interval (per RFC 8628 §3.5, by at least 5 seconds) and tries
	// again.
	ErrSlowDown = errors.New("slow_down")

	// ErrAccessDenied — user denied the request. Terminal.
	ErrAccessDenied = errors.New("access_denied")

	// ErrExpiredToken — device code expired before the user approved.
	// Terminal; restart with a fresh StartDeviceAuth.
	ErrExpiredToken = errors.New("expired_token")

	// ErrInvalidGrant — device code already redeemed, malformed, or
	// otherwise rejected. Terminal.
	ErrInvalidGrant = errors.New("invalid_grant")
)

// errCodeToSentinel maps an RFC 8628 §3.5 error code string to the
// matching sentinel. Unknown codes fall through to a generic error.
func errCodeToSentinel(code string) error {
	switch code {
	case "authorization_pending":
		return ErrAuthorizationPending
	case "slow_down":
		return ErrSlowDown
	case "access_denied":
		return ErrAccessDenied
	case "expired_token":
		return ErrExpiredToken
	case "invalid_grant":
		return ErrInvalidGrant
	default:
		return fmt.Errorf("oauth error: %s", code)
	}
}

// StartDeviceAuth requests a fresh device code from the authorization
// server. The returned DeviceCode is opaque to the client; pass it
// back unmodified on every PollDeviceAuth.
func (c *Client) StartDeviceAuth(ctx context.Context) (*DeviceCode, error) {
	if timeout := c.requestTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	body := url.Values{}
	body.Set("client_id", c.ClientID)
	if c.Scope != "" {
		body.Set("scope", c.Scope)
	}

	resp, err := c.postForm(ctx, c.DeviceCodePath, body)
	if err != nil {
		return nil, fmt.Errorf("start device auth: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(resp, "start device auth")
	}

	var result DeviceCode
	if err := oauthhttp.ReadAndDecodeJSON(resp.Body, &result, true); err != nil {
		return nil, fmt.Errorf("start device auth: %w", err)
	}
	if err := validateVerificationURI(result.VerificationURI, c.AllowInsecureHTTP); err != nil {
		return nil, fmt.Errorf("start device auth: verification_uri: %w", err)
	}
	if result.VerificationURIComplete != "" {
		if err := validateVerificationURI(result.VerificationURIComplete, c.AllowInsecureHTTP); err != nil {
			return nil, fmt.Errorf("start device auth: verification_uri_complete: %w", err)
		}
	}
	return &result, nil
}

// ErrUnsafeVerificationURI is returned when the authorization server
// returns a verification_uri that fails minimum-trust checks. Defense
// against a compromised or misconfigured AS pointing users at a
// phishing page: the URL we'd otherwise echo to the user and open in
// their browser carries the user code, so a wrong destination is a
// direct credential-harvesting vector.
var ErrUnsafeVerificationURI = errors.New("unsafe verification_uri")

// validateVerificationURI rejects URIs that obviously look like
// phishing or shell-injection attempts:
//
//   - Must parse as an absolute URL.
//   - Scheme must be https (or http only when allowInsecureHTTP is
//     set AND the host is loopback — production never qualifies).
//   - Must not embed userinfo (user:password@host tricks the eye).
//   - Must not contain control characters (CR/LF/etc.) that could
//     break terminal output or sneak past glance-checks.
//
// This is the bottom-floor check; the embedding CLI is still expected
// to show the URL to the user for visual inspection, and the user is
// expected to read it before opening.
func validateVerificationURI(raw string, allowInsecureHTTP bool) error {
	if raw == "" {
		return fmt.Errorf("%w: missing", ErrUnsafeVerificationURI)
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: contains control character", ErrUnsafeVerificationURI)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: parse: %w", ErrUnsafeVerificationURI, err)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: missing host", ErrUnsafeVerificationURI)
	}
	if u.User != nil {
		return fmt.Errorf("%w: embedded userinfo not permitted", ErrUnsafeVerificationURI)
	}
	switch u.Scheme {
	case "https":
		// fine
	case "http":
		if !allowInsecureHTTP {
			return fmt.Errorf("%w: scheme must be https", ErrUnsafeVerificationURI)
		}
		host := u.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return fmt.Errorf("%w: http only permitted on loopback hosts", ErrUnsafeVerificationURI)
		}
	default:
		return fmt.Errorf("%w: scheme %q (must be https)", ErrUnsafeVerificationURI, u.Scheme)
	}
	return nil
}

// PollDeviceAuth exchanges deviceCode for a TokenSet at the token
// endpoint.
//
// On success, returns a TokenSet with absolute expiry derived from
// the server's expires_in. On any RFC 8628 §3.5 error code, returns
// the matching sentinel error from this package. Other failures
// (network, malformed responses) are wrapped with context.
//
// Most callers want PollUntil instead — it drives the poll loop,
// honours the interval, applies the RFC 8628 §3.5 +5s slow_down bump,
// and stops at the device-code's ExpiresIn ceiling. Use PollDeviceAuth
// directly only when you need to render the per-tick state yourself
// (e.g. animating a TUI spinner).
func (c *Client) PollDeviceAuth(ctx context.Context, deviceCode string) (*tokens.TokenSet, error) {
	if timeout := c.requestTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	body := url.Values{}
	body.Set("grant_type", deviceCodeGrantType)
	body.Set("client_id", c.ClientID)
	body.Set("device_code", deviceCode)

	resp, err := c.postForm(ctx, c.TokenPath, body)
	if err != nil {
		return nil, fmt.Errorf("poll device auth: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(resp, "poll device auth")
	}

	var raw struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if err := oauthhttp.ReadAndDecodeJSON(resp.Body, &raw, false); err != nil {
		return nil, fmt.Errorf("poll device auth: %w", err)
	}

	if raw.AccessToken == "" {
		return nil, errors.New("poll device auth: server returned 200 with no access token")
	}

	t := &tokens.TokenSet{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		TokenType:    raw.TokenType,
		Scope:        raw.Scope,
	}
	if raw.ExpiresIn > 0 {
		t.ExpiresAt = nowFunc().Add(time.Duration(raw.ExpiresIn) * time.Second)
	}
	return t, nil
}

// postForm POSTs body as application/x-www-form-urlencoded to a path
// resolved against the client's BaseURL. The caller is responsible
// for applying any per-request timeout via context.WithTimeout — the
// timeout must cover the body-read that happens after postForm
// returns, so cancel-on-return here would interrupt that read.
func (c *Client) postForm(ctx context.Context, path string, body url.Values) (*http.Response, error) {
	endpoint, err := resolveURL(c.BaseURL, path, c.AllowInsecureHTTP)
	if err != nil {
		return nil, fmt.Errorf("resolve URL %s: %w", path, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", path, err)
	}
	return resp, nil
}

// ErrInsecureBaseURL is returned when device-flow requests are made
// against an http:// BaseURL without AllowInsecureHTTP set. The token
// endpoint returns the user's access token in the response body — over
// plain HTTP that's a credential in the clear.
var ErrInsecureBaseURL = errors.New("refusing to run device-flow over plain HTTP (set Client.AllowInsecureHTTP only for local dev / test)")

// ErrAbsolutePath is returned when DeviceCodePath or TokenPath is an
// absolute URL rather than a path relative to BaseURL. Go's
// url.ResolveReference *replaces* the base when handed an absolute
// reference, so accepting an absolute path would let any caller who can
// influence the configuration (env var, config file, server-discovery
// doc) redirect the device-code or token request to an attacker — and
// in the token-endpoint case, capture the user's access token.
var ErrAbsolutePath = errors.New("path must be a relative URL, not absolute")

func resolveURL(baseURL, path string, allowInsecureHTTP bool) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base URL: %w", err)
	}
	switch base.Scheme {
	case "https":
		// fine
	case "http":
		if !allowInsecureHTTP {
			return "", ErrInsecureBaseURL
		}
	default:
		return "", fmt.Errorf("unsupported base URL scheme %q (must be http or https)", base.Scheme)
	}
	rel, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("parse path: %w", err)
	}
	// Reject both scheme-relative (e.g. "//host/path") and absolute
	// references — both override BaseURL's host via url.ResolveReference.
	if rel.IsAbs() || rel.Host != "" {
		return "", fmt.Errorf("%w: got %q", ErrAbsolutePath, path)
	}
	return base.ResolveReference(rel).String(), nil
}

type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func readAPIErrorResponse(resp *http.Response) (*errorResponse, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, oauthhttp.MaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var apiErr errorResponse
	if err := json.Unmarshal(body, &apiErr); err == nil && strings.TrimSpace(apiErr.Error) != "" {
		return &apiErr, nil
	}

	text := strings.TrimSpace(string(body))
	if text != "" {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, text)
	}
	return nil, fmt.Errorf("status %d", resp.StatusCode)
}

// readAPIError surfaces an error-shaped response. It routes the AS's
// `error` code through errCodeToSentinel so callers can errors.Is
// regardless of which endpoint produced the failure, and appends a
// sanitised error_description when one was supplied — capping length
// and stripping control characters that would otherwise let a hostile
// AS write ANSI escapes / overflow into the user's terminal.
func readAPIError(resp *http.Response, action string) error {
	apiErr, parseErr := readAPIErrorResponse(resp)
	if parseErr != nil {
		return fmt.Errorf("%s: %w", action, parseErr)
	}
	err := errCodeToSentinel(apiErr.Error)
	if desc := sanitizeDescription(apiErr.ErrorDescription); desc != "" {
		return fmt.Errorf("%s: %w: %s", action, err, desc)
	}
	return fmt.Errorf("%s: %w", action, err)
}

// maxErrorDescriptionRunes caps the sanitised error_description by
// rune count. Real values are short ("user denied", "code expired");
// past this the truncated form points at server misbehaviour rather
// than user-facing guidance, and unbounded length is a UX-DoS vector.
// Counted in runes rather than bytes so truncation lands on a valid
// UTF-8 boundary (preserving the comment's "preserves printable
// Unicode" invariant).
const maxErrorDescriptionRunes = 512

// sanitizeDescription strips control characters (incl. ANSI escapes'
// ESC byte 0x1b, CR, LF, NUL, DEL, BEL) and caps length so a hostile
// or buggy AS can't write into the user's terminal or balloon CLI
// logs. Preserves printable Unicode, including non-ASCII; truncates
// on rune boundaries rather than byte offsets so a CJK / emoji /
// combining-character payload can't be cut mid-rune into invalid
// UTF-8.
func sanitizeDescription(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	runes := 0
	truncated := false
	for _, r := range s {
		switch {
		case r < 0x20: // C0 controls, including ESC (0x1b), CR/LF/TAB/NUL/BEL
			continue
		case r == 0x7f: // DEL
			continue
		}
		if runes >= maxErrorDescriptionRunes {
			truncated = true
			break
		}
		b.WriteRune(r)
		runes++
	}
	out := strings.TrimSpace(b.String())
	if truncated {
		out += "…"
	}
	return out
}

// slowDownBump is the per-RFC 8628 §3.5 mandated interval increase
// applied each time the AS responds with `slow_down`. RFC says "at
// least 5 seconds"; we go with exactly 5. Declared as a var rather
// than const so PollUntil tests can shrink it without burning real
// wall-clock seconds. Production callers should never mutate this.
var slowDownBump = 5 * time.Second

// pollInterval picks the effective poll interval for a device-code
// response. RFC 8628 §3.5 lets the AS omit `interval`, in which case
// the client SHOULD use 5 seconds. We clamp to 1s minimum to defend
// against a hostile or buggy AS responding with `"interval":0`, which
// would otherwise produce a tight loop against the token endpoint.
func pollInterval(dc *DeviceCode) time.Duration {
	const defaultInterval = 5 * time.Second
	const minInterval = 1 * time.Second
	switch {
	case dc.Interval <= 0:
		return defaultInterval
	case time.Duration(dc.Interval)*time.Second < minInterval:
		return minInterval
	default:
		return time.Duration(dc.Interval) * time.Second
	}
}

// PollUntil drives the device-flow poll loop end-to-end. Most embedders
// want this helper rather than calling PollDeviceAuth manually — it
// owns the loop discipline that RFC 8628 §5.5 calls out as the
// difference between a polite client and a DoS source.
//
// Behaviour:
//
//   - Waits dc.Interval (defaulting to 5s, clamped to 1s minimum)
//     between successive poll calls.
//   - On ErrSlowDown, bumps the interval by 5s permanently per RFC
//     8628 §3.5. Subsequent slow_down responses bump again.
//   - Stops with the most-recent error when dc.ExpiresIn elapses since
//     PollUntil was called.
//   - Returns the TokenSet on success.
//   - Returns ctx.Err() (wrapped) when the caller cancels.
//   - Returns terminal sentinels (ErrAccessDenied, ErrExpiredToken,
//     ErrInvalidGrant) unwrapped, plus any unknown OAuth error verbatim,
//     so callers can errors.Is.
func (c *Client) PollUntil(ctx context.Context, dc *DeviceCode) (*tokens.TokenSet, error) {
	if dc == nil {
		return nil, errors.New("PollUntil: DeviceCode is nil")
	}
	if dc.DeviceCode == "" {
		return nil, errors.New("PollUntil: DeviceCode.DeviceCode is empty")
	}

	interval := pollInterval(dc)

	deadline := time.Time{}
	if dc.ExpiresIn > 0 {
		deadline = nowFunc().Add(time.Duration(dc.ExpiresIn) * time.Second)
	}

	for {
		ts, err := c.PollDeviceAuth(ctx, dc.DeviceCode)
		switch {
		case err == nil:
			return ts, nil
		case errors.Is(err, ErrAuthorizationPending):
			// keep polling
		case errors.Is(err, ErrSlowDown):
			interval += slowDownBump
		default:
			// All other errors (terminal sentinels, unknown OAuth
			// codes, network/decode failures) are propagated. The
			// caller decides whether to retry.
			return nil, err
		}

		if !deadline.IsZero() && !nowFunc().Before(deadline) {
			return nil, fmt.Errorf("PollUntil: device code expired after %ds", dc.ExpiresIn)
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("PollUntil: %w", ctx.Err())
		case <-time.After(interval):
		}
	}
}
