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
	"sync/atomic"
	"time"

	"github.com/entireio/auth-go/internal/oauthhttp"
	"github.com/entireio/auth-go/tokens"
)

// Client.now reads c.nowOverride (set only via SetNowForTest) and
// falls back to time.Now. The override lives on the Client rather
// than as a package global so tests using independent Clients can
// freeze their own clocks without racing each other — the v0.2.0
// review flagged the previous package-global `nowFunc` as a latent
// t.Parallel hazard.

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

// String redacts SubjectToken (the user's core bearer) so accidental
// log/print-debug exposure doesn't leak it. Other fields are
// configuration metadata and shown verbatim.
func (r ExchangeRequest) String() string {
	return fmt.Sprintf(
		"ExchangeRequest{SubjectToken:%s SubjectTokenType:%q RequestedTokenType:%q Audience:%q Resource:%q Scope:%q Extra:%v}",
		tokens.ElideSecret(r.SubjectToken),
		r.SubjectTokenType,
		r.RequestedTokenType,
		r.Audience,
		r.Resource,
		r.Scope,
		r.Extra,
	)
}

// GoString delegates to String so %#v in fmt also redacts.
func (r ExchangeRequest) GoString() string { return r.String() }

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
	// Transport supplies the http.RoundTripper used for all calls.
	// nil → http.DefaultTransport. The library builds its own
	// *http.Client around this transport so callers can't trivially
	// pass a *http.Client with TLS verification disabled. See the
	// deviceflow.Client.Transport doc for the security rationale.
	Transport http.RoundTripper

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

	// nowOverride is the per-Client clock. Set only via
	// SetNowForTest. Held behind atomic.Pointer so hot-path reads in
	// Exchange don't race against test setup.
	nowOverride atomic.Pointer[nowFuncType]
}

// nowFuncType is named so we can hold it behind an atomic.Pointer.
type nowFuncType func() time.Time

// now returns the Client's effective clock. Tests can replace it via
// SetNowForTest; production callers always get time.Now.
func (c *Client) now() time.Time {
	if p := c.nowOverride.Load(); p != nil {
		return (*p)()
	}
	return time.Now()
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

	resp, err := c.httpClient().Do(httpReq)
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

	// Exchanged tokens are short-lived per RFC 8693 §2.2.1's spirit
	// (the whole point of exchange is to issue narrowly-scoped,
	// short-lived bearers). A missing or non-positive expires_in is
	// either misconfiguration or a hostile AS — either way, we refuse
	// to cache a token of unknown lifetime and force a fresh exchange.
	if raw.ExpiresIn <= 0 {
		return nil, fmt.Errorf("token exchange: non-positive expires_in (%d)", raw.ExpiresIn)
	}

	return &tokens.TokenSet{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		TokenType:    raw.TokenType,
		Scope:        raw.Scope,
		ExpiresAt:    c.now().Add(time.Duration(raw.ExpiresIn) * time.Second),
	}, nil
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

// httpClient builds the *http.Client used for one Exchange call. See
// oauthhttp.HTTPClient for the construction policy.
func (c *Client) httpClient() *http.Client {
	return oauthhttp.HTTPClient(c.Transport)
}

// New validates a Client's required fields at construction time
// rather than at the first Exchange call. Returns an error if
// BaseURL or Path is empty — these would otherwise surface as a
// confusing "POST to :///token: ..." error from the caller at the
// worst moment.
//
// Takes a *Client (rather than a Client value) because the struct
// embeds an atomic.Pointer for the test-clock seam, which can't be
// copied per the noCopy convention. Returns the same pointer on
// success.
//
// Field-bag construction (`&sts.Client{...}`) is still supported for
// callers who want to set optional fields piecemeal, but `New` is
// the recommended path — it makes misconfiguration a startup error
// rather than a runtime one.
func New(c *Client) (*Client, error) {
	if c == nil {
		return nil, errors.New("sts.New: nil Client")
	}
	switch {
	case c.BaseURL == "":
		return nil, errors.New("sts.New: BaseURL is required")
	case c.Path == "":
		return nil, errors.New("sts.New: Path is required")
	}
	return c, nil
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
// body — over plain HTTP that's a credential in the clear. Re-exported
// from internal/oauthhttp so callers can errors.Is uniformly across
// deviceflow and sts.
var ErrInsecureBaseURL = oauthhttp.ErrInsecureBaseURL

// ErrAbsolutePath is returned when Path is an absolute or
// scheme-relative URL rather than a path relative to BaseURL. See
// oauthhttp.ErrAbsolutePath for the rationale; re-exported here so
// callers can errors.Is on either package's sentinel.
var ErrAbsolutePath = oauthhttp.ErrAbsolutePath

func resolveURL(baseURL, path string, allowInsecureHTTP bool) (string, error) {
	return oauthhttp.ResolveURL(baseURL, path, allowInsecureHTTP) //nolint:wrapcheck // pass through with sentinel-preserving semantics
}

type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// sanitizeDescription is a thin alias kept for in-package readability.
// The implementation lives in internal/oauthhttp.
func sanitizeDescription(s string) string { return oauthhttp.SanitizeDescription(s) }

func readAPIError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, oauthhttp.MaxResponseBytes)) //nolint:errcheck // best-effort body read for error message
	var apiErr errorResponse
	if err := json.Unmarshal(bytes.TrimSpace(body), &apiErr); err == nil && apiErr.Error != "" {
		if desc := sanitizeDescription(apiErr.ErrorDescription); desc != "" {
			return fmt.Errorf("token exchange: status %d: %s: %s", resp.StatusCode, apiErr.Error, desc)
		}
		return fmt.Errorf("token exchange: status %d: %s", resp.StatusCode, apiErr.Error)
	}
	text := strings.TrimSpace(string(body))
	if text != "" {
		return fmt.Errorf("token exchange: status %d: %s", resp.StatusCode, text)
	}
	return fmt.Errorf("token exchange: status %d", resp.StatusCode)
}
