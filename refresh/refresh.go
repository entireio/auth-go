// Package refresh is an RFC 6749 §6 OAuth 2.0 refresh_token grant client.
//
// Construct a Client with the issuer's BaseURL and the token endpoint
// path, then call Refresh with a populated Request to re-mint an access
// token (in auth-go's three-tier model, the login JWT) from a stored
// refresh token. The package is provider-agnostic: endpoint path and
// client_id are supplied at call time. There is no provider detection.
package refresh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/entireio/auth-go/internal/oauthhttp"
	"github.com/entireio/auth-go/tokens"
)

// grantTypeRefreshToken is the RFC 6749 §6 token-endpoint grant_type.
// Unlike the device-code and token-exchange grants it is a bare keyword,
// not a URN.
const grantTypeRefreshToken = "refresh_token"

// ErrInvalidGrant is returned when the server rejects the refresh token
// with the RFC 6749 §5.2 invalid_grant code — the token is expired,
// revoked, or (under rotating-refresh reuse detection) already consumed.
// Callers branch on this to distinguish a recoverable rotation race from
// a transport failure.
var ErrInvalidGrant = errors.New("invalid_grant")

// ErrInsecureBaseURL / ErrAbsolutePath are re-exported from oauthhttp so
// callers can errors.Is uniformly across deviceflow / sts / refresh.
var (
	ErrInsecureBaseURL = oauthhttp.ErrInsecureBaseURL
	ErrAbsolutePath    = oauthhttp.ErrAbsolutePath
)

// DefaultRequestTimeout caps a single refresh round-trip. Set
// conservatively; a healthy refresh completes in sub-seconds. See
// Client.RequestTimeout for the per-Client override.
const DefaultRequestTimeout = 30 * time.Second

// Client runs the refresh_token grant against an RFC 6749 token endpoint.
//
// All configuration is explicit; the package has no global state and no
// implicit URLs. Mirrors sts.Client's construction and security posture.
type Client struct {
	// Transport supplies the http.RoundTripper used for all calls. nil →
	// http.DefaultTransport. The library builds its own *http.Client so
	// callers can't trivially pass one with TLS verification disabled —
	// see sts.Client.Transport for the rationale.
	Transport http.RoundTripper

	BaseURL   string
	Path      string
	UserAgent string

	// RequestTimeout is the per-Refresh deadline applied via
	// context.WithTimeout on top of the caller's context. Zero → default;
	// negative disables the cap.
	RequestTimeout time.Duration

	// AllowInsecureHTTP permits http:// BaseURLs. Default (false) rejects:
	// the refresh request ships the refresh token (a bearer) in the body
	// and must be TLS-protected. Only flip for loopback dev/tests.
	AllowInsecureHTTP bool

	// nowOverride is the per-Client clock. Set only via
	// SetNowForTest. Held behind atomic.Pointer so hot-path reads in
	// Refresh don't race against test setup.
	nowOverride atomic.Pointer[nowFuncType]
}

// nowFuncType is named so we can hold it behind an atomic.Pointer.
type nowFuncType func() time.Time

func (c *Client) now() time.Time {
	if p := c.nowOverride.Load(); p != nil {
		return (*p)()
	}
	return time.Now()
}

func (c *Client) httpClient() *http.Client { return oauthhttp.HTTPClient(c.Transport) }

// New validates a Client's required fields at construction time rather than
// at the first Refresh call. Returns an error if BaseURL or Path is empty —
// these would otherwise surface as a confusing URL error from the caller at
// the worst moment.
//
// Takes a *Client (rather than a Client value) because the struct embeds an
// atomic.Pointer for the test-clock seam, which can't be copied per the
// noCopy convention. Returns the same pointer on success.
//
// Field-bag construction (`&refresh.Client{...}`) is still supported for
// callers who want to set optional fields piecemeal, but New is the
// recommended path — it makes misconfiguration a startup error rather than
// a runtime one.
func New(c *Client) (*Client, error) {
	if c == nil {
		return nil, errors.New("refresh.New: nil Client")
	}
	switch {
	case c.BaseURL == "":
		return nil, errors.New("refresh.New: BaseURL is required")
	case c.Path == "":
		return nil, errors.New("refresh.New: Path is required")
	}
	return c, nil
}

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

// Request is the input to a refresh. RefreshToken is required. ClientID,
// when non-empty, is sent as the Basic-auth username (RFC 6749 §2.3.1) —
// entire-core/zitadel reads client credentials from the Basic header on
// the token grants. Callers also typically mirror it into
// Extra["client_id"] for servers that read the form body. Scope is
// optional (RFC 6749 §6 allows narrowing; omitted when empty). Extra
// carries additional form fields; standard fields win over Extra.
//
// Extra values are NOT redacted by String()/GoString() — only RefreshToken
// is. Do not place bearer-equivalent credentials (client secrets, assertion
// JWTs) in Extra; this package targets public-client flows where no such
// field is expected.
type Request struct {
	RefreshToken string
	ClientID     string
	Scope        string
	Extra        url.Values
}

// String redacts RefreshToken so an accidental log/print doesn't leak the
// bearer. ClientID is an identifier, shown verbatim.
func (r Request) String() string {
	return fmt.Sprintf(
		"refresh.Request{RefreshToken:%s ClientID:%q Scope:%q Extra:%v}",
		tokens.ElideSecret(r.RefreshToken), r.ClientID, r.Scope, r.Extra,
	)
}

// GoString delegates to String so %#v also redacts.
func (r Request) GoString() string { return r.String() }

func (r Request) validate() error {
	if r.RefreshToken == "" {
		return errors.New("RefreshToken is required")
	}
	if err := oauthhttp.ValidateClientID(r.ClientID); err != nil {
		return err
	}
	return oauthhttp.ValidateClientIDConsistency(r.ClientID, r.Extra)
}

// Refresh performs one refresh_token grant. Returns a TokenSet whose
// AccessToken is the freshly minted token and RefreshToken is the rotated
// successor (empty if the server doesn't rotate). ExpiresAt is derived
// from expires_in when positive, else left zero — unlike sts.Exchange we
// tolerate a missing expires_in because the minted login JWT carries its
// own exp claim.
func (c *Client) Refresh(ctx context.Context, req Request) (*tokens.TokenSet, error) {
	if err := req.validate(); err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}

	form := buildForm(req)

	endpoint, err := resolveURL(c.BaseURL, c.Path, c.AllowInsecureHTTP)
	if err != nil {
		return nil, fmt.Errorf("refresh token: resolve URL: %w", err)
	}

	if timeout := c.requestTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("refresh token: create request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.UserAgent != "" {
		httpReq.Header.Set("User-Agent", c.UserAgent)
	}
	if req.ClientID != "" {
		// QueryEscape per RFC 6749 §2.3.1 — client credentials are
		// form-urlencoded before being placed in the Basic header; spec-
		// compliant servers QueryUnescape on the way in. validate()'s
		// byte-level guards mean QueryEscape only ever sees safe input.
		httpReq.SetBasicAuth(url.QueryEscape(req.ClientID), "")
	}

	resp, err := c.httpClient().Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(resp)
	}

	var raw struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if err := oauthhttp.ReadAndDecodeJSON(resp.Body, &raw, false); err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, errors.New("refresh token: response missing access_token")
	}

	ts := &tokens.TokenSet{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		TokenType:    raw.TokenType,
		Scope:        raw.Scope,
	}
	if raw.ExpiresIn > 0 {
		ts.ExpiresAt = c.now().Add(expiresInDuration(raw.ExpiresIn))
	}
	return ts, nil
}

// maxExpiresInSeconds caps a server-provided expires_in before it is
// multiplied into a time.Duration. Without a ceiling, a hostile or buggy
// AS returning a value above ~9.2e9 overflows time.Duration's int64
// nanosecond range, wrapping ExpiresAt into the past so a freshly-minted
// token looks already-expired. 100 years is far beyond any real token
// lifetime and safely below the overflow threshold. Mirrors the
// defensive clamp deviceflow applies to its interval field.
const maxExpiresInSeconds = 100 * 365 * 24 * 60 * 60

// expiresInDuration converts a server-provided expires_in (seconds) to a
// time.Duration, clamping at maxExpiresInSeconds to avoid int64 overflow.
func expiresInDuration(secs int) time.Duration {
	if secs > maxExpiresInSeconds {
		secs = maxExpiresInSeconds
	}
	return time.Duration(secs) * time.Second
}

// buildForm renders a Request into the wire form, layering the standard
// fields on top of Extra so caller-supplied duplicates of standard fields
// are overwritten by the typed values. client_id rides in Extra (form
// body) the same way sts does; the typed ClientID field drives Basic auth.
func buildForm(req Request) url.Values {
	form := url.Values{}
	for k, v := range req.Extra {
		form[k] = append(form[k], v...)
	}
	form.Set("grant_type", grantTypeRefreshToken)
	form.Set("refresh_token", req.RefreshToken)
	if req.Scope != "" {
		form.Set("scope", req.Scope)
	}
	return form
}

func resolveURL(baseURL, path string, allowInsecureHTTP bool) (string, error) {
	return oauthhttp.ResolveURL(baseURL, path, allowInsecureHTTP) //nolint:wrapcheck // pass through with sentinel-preserving semantics
}

func readAPIError(resp *http.Response) error {
	apiErr, parseErr := oauthhttp.ReadOAuthError(resp)
	if parseErr != nil {
		return fmt.Errorf("refresh token: %w", parseErr)
	}
	code := oauthhttp.SanitizeDescription(apiErr.Error)
	desc := oauthhttp.SanitizeDescription(apiErr.ErrorDescription)

	var base error
	if apiErr.Error == "invalid_grant" {
		base = ErrInvalidGrant
	}

	switch {
	case base != nil && desc != "":
		return fmt.Errorf("refresh token: %w: %s", base, desc)
	case base != nil:
		return fmt.Errorf("refresh token: %w", base)
	case desc != "":
		return fmt.Errorf("refresh token: status %d: %s: %s", resp.StatusCode, code, desc)
	default:
		return fmt.Errorf("refresh token: status %d: %s", resp.StatusCode, code)
	}
}
