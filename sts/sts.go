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
//
// Extra values are NOT redacted by the Stringer — only SubjectToken
// is. Do not stuff bearer-equivalent credentials (client secrets,
// assertion JWTs, refresh tokens) into Extra; the package is targeted
// at public-client device flow where no such field is expected. If a
// caller's server demands a secret-bearing form field via Extra, log
// hygiene becomes that caller's responsibility.
type ExchangeRequest struct {
	SubjectToken       string
	SubjectTokenType   string
	RequestedTokenType string

	Audience string
	Resource string
	Scope    string

	// ClientID, when non-empty, is sent as the username component of an
	// HTTP Basic Authorization header (RFC 6749 §2.3.1). ClientSecret
	// is the password component; leave empty for public clients
	// (Exchange will emit Basic base64("id:"), which §2.3.1 permits).
	//
	// Why both surfaces. Some authorization servers accept client
	// credentials for the token-exchange grant only via Basic Auth and
	// ignore form-body client_id — zitadel-based servers as of
	// 2026-05 are a known example (pkg/op/token_exchange.go reads only
	// from r.BasicAuth()). Callers are also free to set
	// Extra["client_id"] for servers that read from the form body;
	// both surfaces can be populated simultaneously and validate()
	// rejects a divergence between them.
	//
	// Wire encoding. Both values are url.QueryEscape'd before being
	// placed in the header — RFC 6749 §2.3.1 mandates that client
	// credentials are form-urlencoded before going into Basic Auth, so
	// spec-compliant servers decode via QueryUnescape on the way in.
	// Without the escape, credentials containing reserved characters
	// (':', '@', '%', non-ASCII) would not round-trip correctly even
	// against compliant servers. validate() further rejects ClientID
	// values that ':' or non-VSCHAR bytes can't reach via this path
	// (RFC 7617 §2 + RFC 6749 §2.3.1).
	ClientID     string
	ClientSecret string

	Extra url.Values
}

// String redacts SubjectToken (the user's core bearer) and
// ClientSecret (bearer-equivalent for confidential clients) so
// accidental log/print-debug exposure doesn't leak them. ClientID is
// shown verbatim — it's an identifier, not a credential. Other fields
// are configuration metadata and shown verbatim.
//
// Redaction here is a log-hygiene defense, not a memory-safety or
// security boundary. The struct fields remain exported and readable
// via direct access or reflection; callers handling long-lived
// credentials are responsible for their own zeroization. When adding
// new fields to ExchangeRequest, update this method if the field
// carries bearer-equivalent data.
func (r ExchangeRequest) String() string {
	return fmt.Sprintf(
		"ExchangeRequest{SubjectToken:%s SubjectTokenType:%q RequestedTokenType:%q Audience:%q Resource:%q Scope:%q ClientID:%q ClientSecret:%s Extra:%v}",
		tokens.ElideSecret(r.SubjectToken),
		r.SubjectTokenType,
		r.RequestedTokenType,
		r.Audience,
		r.Resource,
		r.Scope,
		r.ClientID,
		tokens.ElideSecret(r.ClientSecret),
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
	case r.ClientSecret != "" && r.ClientID == "":
		// Without this guard the Basic Auth branch in Exchange is
		// skipped (gated on ClientID != "") and the secret is
		// silently dropped — a confidential-client misconfiguration
		// that would otherwise reach the server as anonymous and
		// either 401 opaquely or, worse, succeed under a permissive
		// policy. Fail fast at the caller.
		return errors.New("ClientSecret set without ClientID: credentials would not be sent")
	}
	if err := validateClientID(r.ClientID); err != nil {
		return err
	}
	if err := validateClientIDConsistency(r.ClientID, r.Extra); err != nil {
		return err
	}
	return nil
}

// validateClientID enforces the byte-level constraints RFC 6749 §2.3.1
// and RFC 7617 §2 place on a client_id traveling via HTTP Basic Auth:
// VSCHAR (printable ASCII, 0x20–0x7E) and no ':' (the Basic Auth field
// separator). Without this guard, url.QueryEscape in Exchange would
// percent-encode forbidden bytes, slip them past the wire validator,
// and surface as opaque server-side rejections after a QueryUnescape
// round-trip.
func validateClientID(id string) error {
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

// validateClientIDConsistency rejects requests that set client_id on
// both the typed field and Extra to different values. The two surfaces
// are populated independently — typed field becomes Basic Auth, Extra
// becomes form body — and a server reading one but not the other would
// silently accept the wrong identity. Same-value duplication is the
// documented belt-and-braces pattern and is allowed.
func validateClientIDConsistency(id string, extra url.Values) error {
	if id == "" || extra == nil {
		return nil
	}
	for _, extraID := range extra["client_id"] {
		if extraID != id {
			return fmt.Errorf("ClientID (%q) and Extra[\"client_id\"] (%q) disagree", id, extraID)
		}
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
	if req.ClientID != "" {
		// QueryEscape on the way out per RFC 6749 §2.3.1: client
		// credentials are form-urlencoded before being placed in the
		// Basic Authorization header. Spec-compliant servers
		// (zitadel-based servers among them) decode via QueryUnescape
		// on the way in; without the escape, credentials containing
		// reserved characters would not round-trip correctly. The
		// validate() byte-level guards above mean we only ever hand
		// QueryEscape values it can safely percent-encode.
		httpReq.SetBasicAuth(url.QueryEscape(req.ClientID), url.QueryEscape(req.ClientSecret))
	}
	// Intentional fall-through when ClientID is empty: omit the
	// Authorization header entirely rather than send Basic Og==
	// (the encoded ":"). Sending an explicit empty-credential header
	// flips servers that branch on header presence into credential-
	// evaluation mode and yields invalid_client; public clients that
	// don't authenticate at this endpoint expect an absent header.

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
	text := sanitizeDescription(string(body))
	if text != "" {
		return fmt.Errorf("token exchange: status %d: %s", resp.StatusCode, text)
	}
	return fmt.Errorf("token exchange: status %d", resp.StatusCode)
}
