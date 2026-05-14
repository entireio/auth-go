// Package sts is an RFC 8693 OAuth 2.0 Token Exchange client.
//
// Construct a Client with the issuer's BaseURL and the token endpoint
// path, then call Exchange with a populated ExchangeRequest. The
// package is provider-agnostic: every server-specific value (endpoint
// path, requested-token-type URIs, custom form fields) is supplied at
// call time. There is no provider detection.
package sts

import (
	"bytes"
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

// nowFunc is the package's clock. Override in tests.
var nowFunc = time.Now

// RFC 8693 grant_type and standard subject-token type URIs. Caller
// supplies RequestedTokenType (which is always implementation-specific
// outside of these RFC 8693 standard values).
const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // RFC 8693 grant_type URI, not a credential

	SubjectTokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"          //nolint:gosec // RFC 8693 token-type URI, not a credential
	SubjectTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token" //nolint:gosec // RFC 8693 token-type URI, not a credential
)

// ExchangeRequest is the input to a token exchange.
//
// SubjectToken, SubjectTokenType, and RequestedTokenType are required.
// Audience, Resource, and Scope map to RFC 8693 §2.1 parameters and
// are sent only when non-empty. Extra carries implementation-specific
// form fields (e.g. server-defined parameters not in RFC 8693) that
// the caller's server expects; the standard fields above always win
// if Extra also sets them.
type ExchangeRequest struct {
	SubjectToken       string
	SubjectTokenType   string
	RequestedTokenType string

	Audience string
	Resource string
	Scope    string

	Extra url.Values
}

func (r ExchangeRequest) validate() error {
	switch {
	case r.SubjectToken == "":
		return errors.New("SubjectToken is required")
	case r.SubjectTokenType == "":
		return errors.New("SubjectTokenType is required")
	case r.RequestedTokenType == "":
		return errors.New("RequestedTokenType is required")
	}
	return nil
}

// DefaultRequestTimeout caps a single token-exchange round-trip. Set
// conservatively: even with a slow auth host plus TLS handshake, a
// healthy exchange completes in sub-seconds. The cap mainly defends
// against slow-loris responses dripping bytes within MaxResponseBytes
// — see Client.RequestTimeout for the per-Client override.
const DefaultRequestTimeout = 30 * time.Second

// Client exchanges subject tokens for tokens of a different type at an
// RFC 8693 token endpoint.
//
// All configuration is explicit; the package has no global state and
// no implicit URLs. Provide BaseURL and Path; the rest is RFC 8693.
type Client struct {
	HTTP      *http.Client
	BaseURL   string
	Path      string
	UserAgent string

	// RequestTimeout is the per-Exchange deadline applied via
	// context.WithTimeout on top of the caller's context. Zero falls
	// back to DefaultRequestTimeout. Negative disables the cap (useful
	// for tests that want to drive timing via the caller's ctx alone).
	RequestTimeout time.Duration

	// AllowInsecureHTTP permits http:// BaseURLs. Default (false) is
	// reject — token exchanges carry the subject token (a bearer) on
	// the wire and must be TLS-protected end to end. Production callers
	// MUST leave this false; only tests and local development that pin
	// the issuer to loopback should flip it.
	AllowInsecureHTTP bool
}

// Exchange performs one RFC 8693 token exchange.
//
// Returns a TokenSet with absolute ExpiresAt derived from the server's
// expires_in. Returns an error wrapping the response body when the
// server responds with a non-2xx status; callers can match on the
// returned error message for known OAuth error codes.
func (c *Client) Exchange(ctx context.Context, req ExchangeRequest) (*tokens.TokenSet, error) {
	if err := req.validate(); err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	form := buildForm(req)

	endpoint, err := resolveURL(c.BaseURL, c.Path, c.AllowInsecureHTTP)
	if err != nil {
		return nil, fmt.Errorf("token exchange: resolve URL: %w", err)
	}

	if timeout := c.requestTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("token exchange: create request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.UserAgent != "" {
		httpReq.Header.Set("User-Agent", c.UserAgent)
	}

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(resp)
	}

	var raw struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		ExpiresIn       int    `json:"expires_in"`
		RefreshToken    string `json:"refresh_token"`
		Scope           string `json:"scope"`
	}
	if err := oauthhttp.ReadAndDecodeJSON(resp.Body, &raw, false); err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, errors.New("token exchange: response missing access_token")
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

// buildForm renders an ExchangeRequest into the wire form, layering
// the standard RFC 8693 fields on top of req.Extra so caller-supplied
// duplicates of standard fields are overwritten by the typed values.
func buildForm(req ExchangeRequest) url.Values {
	form := url.Values{}
	for k, v := range req.Extra {
		form[k] = append(form[k], v...)
	}

	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token", req.SubjectToken)
	form.Set("subject_token_type", req.SubjectTokenType)
	form.Set("requested_token_type", req.RequestedTokenType)

	if req.Audience != "" {
		form.Set("audience", req.Audience)
	}
	if req.Resource != "" {
		form.Set("resource", req.Resource)
	}
	if req.Scope != "" {
		form.Set("scope", req.Scope)
	}
	return form
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

// ErrInsecureBaseURL is returned when Exchange is called against an
// http:// BaseURL without AllowInsecureHTTP set. Token exchange ships
// a subject_token (typically the user's core bearer) in the request
// body — over plain HTTP that's a credential in the clear.
var ErrInsecureBaseURL = errors.New("refusing to perform token exchange over plain HTTP (set Client.AllowInsecureHTTP only for local dev / test)")

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

func readAPIError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, oauthhttp.MaxResponseBytes)) //nolint:errcheck // best-effort body read for error message
	var apiErr errorResponse
	if err := json.Unmarshal(bytes.TrimSpace(body), &apiErr); err == nil && apiErr.Error != "" {
		if apiErr.ErrorDescription != "" {
			return fmt.Errorf("token exchange: status %d: %s: %s", resp.StatusCode, apiErr.Error, apiErr.ErrorDescription)
		}
		return fmt.Errorf("token exchange: status %d: %s", resp.StatusCode, apiErr.Error)
	}
	text := strings.TrimSpace(string(body))
	if text != "" {
		return fmt.Errorf("token exchange: status %d: %s", resp.StatusCode, text)
	}
	return fmt.Errorf("token exchange: status %d", resp.StatusCode)
}
