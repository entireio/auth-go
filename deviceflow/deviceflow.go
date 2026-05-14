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

	"github.com/entireio/cli/auth/internal/oauthhttp"
	"github.com/entireio/cli/auth/tokens"
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
	HTTP           *http.Client
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
		apiErr, parseErr := readAPIErrorResponse(resp)
		if parseErr != nil {
			return nil, fmt.Errorf("poll device auth: %w", parseErr)
		}
		err := errCodeToSentinel(apiErr.Error)
		if apiErr.ErrorDescription != "" {
			// Wrap so callers using errors.Is(err, ErrInvalidGrant) keep
			// working while the description is still surfaced via
			// err.Error(). Format: "<code>: <description>".
			err = fmt.Errorf("%w: %s", err, apiErr.ErrorDescription)
		}
		return nil, err
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

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	resp, err := httpClient.Do(req)
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

func readAPIError(resp *http.Response, action string) error {
	apiErr, err := readAPIErrorResponse(resp)
	if err == nil {
		return fmt.Errorf("%s: %s", action, apiErr.Error)
	}
	return fmt.Errorf("%s: %w", action, err)
}
