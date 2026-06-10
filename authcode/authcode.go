// Package authcode is an RFC 8252 OAuth 2.0 Authorization Code Grant
// client for native apps: it uses PKCE (RFC 7636, S256) and a loopback
// redirect so a CLI can authenticate a user through their browser
// without the user copying a code by hand.
//
// Usage is three steps, driven by the embedding CLI:
//
//  1. Start binds a loopback listener and computes the PKCE verifier +
//     state. It returns a Flow carrying AuthorizationURL — the URL the
//     caller opens in the user's browser.
//  2. Wait blocks until the browser is redirected back to the loopback
//     listener, returning the authorization code.
//  3. Exchange redeems that code (with the PKCE verifier) at the token
//     endpoint for a TokenSet.
//
// Opening the browser is deliberately the caller's job — this package
// performs no I/O beyond the loopback listener and the two HTTP calls to
// the authorization server, mirroring deviceflow (which likewise leaves
// browser-opening to the embedder).
//
// The client is provider-agnostic: every server-specific value (endpoint
// paths, client_id, optional scope) is configured at construction time.
// There is no provider detection.
package authcode

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/entireio/auth-go/internal/oauthhttp"
	"github.com/entireio/auth-go/tokens"
)

// authCodeGrantType is the RFC 6749 §4.1.3 token-endpoint grant_type for
// redeeming an authorization code.
const authCodeGrantType = "authorization_code"

// pkceMethodS256 is the only PKCE transform this client offers (RFC 7636
// §4.3). The "plain" method is intentionally not supported — S256 is
// universally available and "plain" leaks the verifier to anyone who can
// observe the authorization request.
const pkceMethodS256 = "S256"

// callbackPath is the path the loopback listener serves and the redirect
// the authorization server is told to send the browser back to.
const callbackPath = "/callback"

// loopbackHost is the address the callback listener binds. RFC 8252 §7.3
// permits the server to accept any port on the loopback interface, so we
// bind 127.0.0.1:0 (OS-assigned ephemeral port) rather than registering a
// fixed one. IPv4 only: 127.0.0.1 is accepted by every loopback-redirect
// registration in practice, and dual-stacking ::1 adds a fallback path
// that's rarely needed and easy to get subtly wrong.
const loopbackHost = "127.0.0.1"

// verifierBytes / stateBytes size the random inputs. 48 verifier bytes →
// 64 base64url chars, comfortably inside RFC 7636's 43–128 range. 24
// state bytes → 32 chars, ample CSRF entropy.
const (
	verifierBytes = 48
	stateBytes    = 24
)

// DefaultRequestTimeout caps the token-exchange HTTP round-trip. Set
// conservatively: healthy token endpoints respond in sub-seconds, so the
// cap mainly defends against a slow-loris response dribbling bytes.
const DefaultRequestTimeout = 30 * time.Second

// DefaultCallbackTimeout bounds how long Wait blocks for the browser
// redirect before giving up. Long enough for a user to complete an SSO
// hop (including MFA), short enough that an abandoned login doesn't park
// the listener forever.
const DefaultCallbackTimeout = 5 * time.Minute

// Sentinel errors returned by the flow. Callers branch on these with
// errors.Is to distinguish user action from transport failure.
var (
	// ErrAccessDenied — the user declined consent (the authorization
	// server redirected back with error=access_denied), or the token
	// endpoint rejected the exchange with the same code. Terminal.
	ErrAccessDenied = errors.New("access_denied")

	// ErrInvalidGrant — the token endpoint rejected the authorization
	// code (already redeemed, expired, or PKCE verifier mismatch).
	// Terminal.
	ErrInvalidGrant = errors.New("invalid_grant")

	// ErrMissingCode — the authorization server redirected to the
	// callback with neither a code nor an error parameter. Terminal.
	ErrMissingCode = errors.New("authorization callback returned no code")

	// ErrListenerClosed — the loopback listener stopped before any
	// callback arrived (e.g. Close was called concurrently). Terminal.
	ErrListenerClosed = errors.New("loopback listener closed before callback arrived")

	// ErrAuthorizeQuery — AuthorizePath carries query parameters. The client
	// owns the authorization request's query string (response_type, client_id,
	// redirect_uri, the PKCE challenge, state, scope) and sets it wholesale, so
	// a query on the configured path would be silently discarded. Rather than
	// drop it — and issue a request missing whatever the caller intended
	// (audience, resource, access_type, a tenant hint) — Start fails loud.
	ErrAuthorizeQuery = errors.New("AuthorizePath must not carry query parameters")
)

// ErrInsecureBaseURL is re-exported from internal/oauthhttp so callers
// can errors.Is(err, authcode.ErrInsecureBaseURL) regardless of which
// package raised it. The token endpoint returns the user's freshly-minted
// access token in the response body and must be TLS-protected end to end.
var ErrInsecureBaseURL = oauthhttp.ErrInsecureBaseURL

// ErrAbsolutePath is re-exported from internal/oauthhttp. See deviceflow's
// identically-named sentinel: an absolute AuthorizePath/TokenPath would let
// configuration redirect the user's bearer to an attacker.
var ErrAbsolutePath = oauthhttp.ErrAbsolutePath

// Client performs the RFC 8252 loopback authorization-code flow.
//
// All configuration is explicit; the package has no global state and no
// implicit URLs. Provide BaseURL, ClientID, and the two endpoint paths;
// the rest is RFC 8252 / RFC 7636 mechanics.
type Client struct {
	// Transport supplies the http.RoundTripper used for the token-exchange
	// call. nil → http.DefaultTransport. As in deviceflow, this hook is for
	// observability and per-environment proxies, not TLS-verification
	// bypass; the library builds its own *http.Client around it.
	Transport http.RoundTripper

	BaseURL       string
	ClientID      string
	Scope         string
	UserAgent     string
	AuthorizePath string
	TokenPath     string

	// RequestTimeout is the per-request deadline for the token exchange,
	// applied via context.WithTimeout on top of the caller's context. Zero
	// falls back to DefaultRequestTimeout; negative disables the cap.
	RequestTimeout time.Duration

	// CallbackTimeout bounds how long Wait blocks for the browser redirect.
	// Zero falls back to DefaultCallbackTimeout; negative disables the cap
	// (Wait then relies solely on the caller's context).
	CallbackTimeout time.Duration

	// AllowInsecureHTTP permits http:// BaseURLs, restricted to loopback
	// hosts. Production callers MUST leave this false; only tests and local
	// development pinned to loopback should flip it. Note this governs the
	// authorization-server BaseURL, not the loopback redirect — the
	// redirect is always http://127.0.0.1, which RFC 8252 §8.3 permits
	// precisely because loopback traffic never leaves the machine.
	AllowInsecureHTTP bool

	// nowOverride is the per-Client clock. Set only via SetNowForTest.
	// Held behind atomic.Pointer so the expiry computation in Exchange
	// doesn't race against test setup.
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

// httpClient builds the *http.Client used for the token-exchange request.
// See oauthhttp.HTTPClient for the construction policy.
func (c *Client) httpClient() *http.Client {
	return oauthhttp.HTTPClient(c.Transport)
}

// New validates a Client's required fields at construction time rather
// than at Start/Exchange. Returns an error if BaseURL, ClientID,
// AuthorizePath, or TokenPath is empty.
//
// Takes a *Client (rather than a value) because the struct embeds an
// atomic.Pointer for the test-clock seam, which can't be copied. Returns
// the same pointer on success. Field-bag construction is still supported,
// but New makes misconfiguration a startup error rather than a runtime one.
func New(c *Client) (*Client, error) {
	if c == nil {
		return nil, errors.New("authcode.New: nil Client")
	}
	switch {
	case c.BaseURL == "":
		return nil, errors.New("authcode.New: BaseURL is required")
	case c.ClientID == "":
		return nil, errors.New("authcode.New: ClientID is required")
	case c.AuthorizePath == "":
		return nil, errors.New("authcode.New: AuthorizePath is required")
	case c.TokenPath == "":
		return nil, errors.New("authcode.New: TokenPath is required")
	}
	return c, nil
}

// requestTimeout resolves the effective per-request timeout for the token
// exchange: the configured RequestTimeout if positive, the package default
// if zero, or zero (no cap) if negative.
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

// callbackTimeout resolves the effective Wait timeout the same way
// requestTimeout does, against CallbackTimeout / DefaultCallbackTimeout.
func (c *Client) callbackTimeout() time.Duration {
	switch {
	case c.CallbackTimeout < 0:
		return 0
	case c.CallbackTimeout == 0:
		return DefaultCallbackTimeout
	default:
		return c.CallbackTimeout
	}
}

// Flow is one in-progress authorization-code login. Start returns it with
// AuthorizationURL populated; the caller opens that URL, then calls Wait
// followed by Exchange. The Flow owns a live loopback listener until Wait
// returns or Close is called — callers MUST call one of the two to avoid
// leaking the listener.
type Flow struct {
	// AuthorizationURL is the URL the caller opens in the user's browser
	// to begin consent.
	AuthorizationURL string

	// RedirectURI is the loopback callback the authorization server
	// redirects to. Exposed mainly for diagnostics/logging; the value is
	// also re-sent on the token exchange (RFC 6749 §4.1.3 requires it to
	// match the authorize request).
	RedirectURI string

	client    *Client
	verifier  string
	state     string
	srv       *http.Server
	resultCh  chan callbackResult
	srvErrCh  chan error
	closeOnce sync.Once
	closeErr  error
}

// String redacts the PKCE verifier and CSRF state. Both are live secrets
// during the auth window: the verifier redeems the authorization code, and
// state is the only gate on which callback this Flow accepts. Without this,
// a stray fmt.Printf("%+v", flow) in caller code would dump them to logs —
// the same hazard tokens.TokenSet, deviceflow.DeviceCode, and
// sts.ExchangeRequest guard against. AuthorizationURL carries the same state
// in its query by construction, so it's shown with that one parameter
// scrubbed (see redactedAuthorizationURL); otherwise fmt would be a second,
// silent path to the bare secret. RedirectURI holds no secret and is shown
// verbatim.
func (f *Flow) String() string {
	if f == nil {
		return "<nil>"
	}
	return fmt.Sprintf(
		"Flow{AuthorizationURL:%q RedirectURI:%q verifier:%s state:%s}",
		f.redactedAuthorizationURL(),
		f.RedirectURI,
		tokens.ElideSecret(f.verifier),
		tokens.ElideSecret(f.state),
	)
}

// redactedAuthorizationURL returns AuthorizationURL with the state query
// parameter's value masked, for safe inclusion in String. The raw field
// stays untouched — only this diagnostic rendering is scrubbed. On a parse
// failure we return a marker rather than risk emitting the unredacted URL.
func (f *Flow) redactedAuthorizationURL() string {
	if f.AuthorizationURL == "" {
		return ""
	}
	u, err := url.Parse(f.AuthorizationURL)
	if err != nil {
		return "<unparseable authorization URL>"
	}
	if q := u.Query(); q.Has("state") {
		q.Set("state", "<redacted>")
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// GoString delegates to String so %#v in fmt also redacts.
func (f *Flow) GoString() string { return f.String() }

// callbackResult is the outcome the callback handler hands to Wait over
// resultCh: either an authorization code or a terminal error.
type callbackResult struct {
	code string
	err  error
}

// Start computes PKCE + state, binds a loopback listener, starts serving
// the callback, and builds the authorization URL. The returned Flow's
// AuthorizationURL should be opened in the user's browser.
//
// The provided context governs only the listener bind; the listener and
// callback server outlive ctx and are torn down by Wait or Close. Pass the
// browser-wait deadline to Wait, not here.
func (c *Client) Start(ctx context.Context) (*Flow, error) {
	verifier, challenge, err := newPKCE()
	if err != nil {
		return nil, fmt.Errorf("start authorization: %w", err)
	}
	state, err := randomB64URL(stateBytes)
	if err != nil {
		return nil, fmt.Errorf("start authorization: generate state: %w", err)
	}

	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", loopbackHost+":0")
	if err != nil {
		return nil, fmt.Errorf("start authorization: open loopback listener: %w", err)
	}
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("start authorization: loopback listener returned non-TCP address: %T", listener.Addr())
	}
	redirectURI := fmt.Sprintf("http://%s:%d%s", loopbackHost, tcpAddr.Port, callbackPath)

	authURL, err := c.authorizationURL(redirectURI, challenge, state)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("start authorization: %w", err)
	}

	f := &Flow{
		AuthorizationURL: authURL,
		RedirectURI:      redirectURI,
		client:           c,
		verifier:         verifier,
		state:            state,
		resultCh:         make(chan callbackResult, 1),
		srvErrCh:         make(chan error, 1),
	}

	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, f.handleCallback)
	f.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		// Bound the response write and any keep-alive idle so a stalled
		// browser connection can't pin a handler goroutine open for the whole
		// callback window. The page is a few hundred bytes over loopback, so
		// these never bite a real client.
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  10 * time.Second,
	}
	go func() { f.srvErrCh <- f.srv.Serve(listener) }()

	return f, nil
}

// authorizationURL builds the RFC 6749 §4.1.1 authorization request URL
// with the PKCE challenge. resolveURL applies the BaseURL scheme + loopback
// + absolute-path guards before we attach the query.
func (c *Client) authorizationURL(redirectURI, challenge, state string) (string, error) {
	endpoint, err := resolveURL(c.BaseURL, c.AuthorizePath, c.AllowInsecureHTTP)
	if err != nil {
		return "", fmt.Errorf("resolve authorize URL: %w", err)
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse authorize URL: %w", err)
	}
	// We overwrite u.RawQuery below, so any query already on the resolved
	// endpoint (i.e. configured on AuthorizePath) would vanish without trace.
	// Reject it instead of silently dropping caller-intended parameters.
	if u.RawQuery != "" {
		return "", fmt.Errorf("%w: got %q", ErrAuthorizeQuery, c.AuthorizePath)
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", pkceMethodS256)
	q.Set("state", state)
	if c.Scope != "" {
		q.Set("scope", c.Scope)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// handleCallback is the loopback redirect handler. It validates state,
// surfaces an OAuth error parameter, extracts the authorization code, and
// signals Wait over the buffered resultCh.
//
// The outcome is recorded (f.signal) BEFORE the response is written. The
// browser-page write can block — a slow or stalled client connection — and
// if Wait's deadline or the caller's context fires during that write, Wait
// re-checks the buffer (tryResult) and must find the result already there.
// Signalling after the write would let a redirect that genuinely succeeded
// surface as a false timeout while the browser shows "Signed in".
func (f *Flow) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// State mismatch: reject the request but do NOT signal — a stray or
	// forged request must not abort a login that's still waiting for the
	// genuine redirect. The wait deadline bounds the worst case.
	if q.Get("state") != f.state {
		http.Error(w, "state mismatch — refusing to redeem authorization code", http.StatusBadRequest)
		return
	}

	if oerr := q.Get("error"); oerr != "" {
		desc := oauthhttp.SanitizeDescription(q.Get("error_description"))
		f.signal(callbackResult{err: callbackError(oerr, desc)})
		writeBrowserPage(w, http.StatusBadRequest, "Sign-in failed", "You can close this tab and return to your terminal.")
		return
	}

	code := q.Get("code")
	if code == "" {
		f.signal(callbackResult{err: ErrMissingCode})
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	f.signal(callbackResult{code: code})
	writeBrowserPage(w, http.StatusOK, "Signed in", "You're signed in. You can close this tab and return to your terminal.")
}

// signal delivers res to Wait over the capacity-1 resultCh. The first
// matching-state callback wins and is terminal: once a result is buffered,
// later callbacks — duplicates (double-submit, retry) or a stray/forged
// follow-up that guessed state — are dropped, never overwriting it.
//
// Immutability is the security property. state leaks via the browser-open
// command line, so a local observer could revisit the live authorization
// request and complete it against their own account. If a later success
// could displace an earlier result, that observer's code would overwrite
// the genuine user's access_denied and sign the CLI into the attacker's
// account. A sunk login (forged error winning the race) is recoverable and
// obvious; silently signing into the wrong account is not — so first-wins.
//
// The buffered-channel send-or-drop is itself atomic, so no mutex is needed
// to serialise concurrent handler goroutines: exactly one send fills the
// slot, the rest hit the default and drop.
func (f *Flow) signal(res callbackResult) {
	select {
	case f.resultCh <- res:
	default:
	}
}

// tryResult non-blockingly reads a buffered callback result, if any. Wait
// uses it to let a successful callback win over a concurrently-ready failure
// or deadline signal (a select with multiple ready cases chooses at random).
func (f *Flow) tryResult() (callbackResult, bool) {
	select {
	case res := <-f.resultCh:
		return res, true
	default:
		return callbackResult{}, false
	}
}

// callbackError maps an authorization-server error code (RFC 6749 §4.1.2.1)
// to a sentinel where one exists, attaching the sanitised description.
func callbackError(code, desc string) error {
	var base error
	if code == "access_denied" {
		base = ErrAccessDenied
	} else {
		base = fmt.Errorf("oauth error: %s", oauthhttp.SanitizeDescription(code))
	}
	if desc != "" {
		return fmt.Errorf("authorization callback: %w: %s", base, desc)
	}
	return fmt.Errorf("authorization callback: %w", base)
}

// Wait blocks until the browser is redirected to the loopback callback,
// the callback timeout elapses, or ctx is cancelled. It returns the
// authorization code on success. The loopback listener is shut down before
// Wait returns, so the Flow is single-use.
func (f *Flow) Wait(ctx context.Context) (code string, err error) {
	defer func() { _ = f.Close() }()

	if timeout := f.client.callbackTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	select {
	case res := <-f.resultCh:
		return res.code, res.err
	case serr := <-f.srvErrCh:
		// A genuine callback may have raced the failure signal; select offers
		// no priority, so prefer an already-buffered result over the error.
		if res, ok := f.tryResult(); ok {
			return res.code, res.err
		}
		if errors.Is(serr, http.ErrServerClosed) {
			return "", ErrListenerClosed
		}
		return "", fmt.Errorf("loopback listener: %w", serr)
	case <-ctx.Done():
		if res, ok := f.tryResult(); ok {
			return res.code, res.err
		}
		return "", fmt.Errorf("wait for browser sign-in: %w", ctx.Err())
	}
}

// Close shuts down the loopback listener. Safe to call multiple times and
// safe to call without Wait (e.g. when the caller aborts after Start).
// Wait calls Close on return, so most callers never invoke it directly.
func (f *Flow) Close() error {
	f.closeOnce.Do(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.srv.Shutdown(shutCtx); err != nil {
			// Graceful shutdown timed out — Shutdown leaves any still-active
			// connection (e.g. a callback response writing to a stalled
			// client) running rather than interrupting it. Force it closed so
			// the listener and its handler goroutines are gone when we return;
			// otherwise the timeout would be a silent connection/goroutine leak.
			f.closeErr = f.srv.Close()
		}
	})
	return f.closeErr
}

// Exchange redeems code at the token endpoint using the PKCE verifier and
// redirect URI captured in this Flow (RFC 6749 §4.1.3 + RFC 7636 §4.5).
//
// On success it returns a TokenSet with absolute expiry derived from the
// server's expires_in. On a recognised OAuth error it returns the matching
// sentinel (ErrAccessDenied, ErrInvalidGrant); other failures (network,
// malformed responses) are wrapped with context.
func (f *Flow) Exchange(ctx context.Context, code string) (*tokens.TokenSet, error) {
	c := f.client
	if timeout := c.requestTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	body := url.Values{}
	body.Set("grant_type", authCodeGrantType)
	body.Set("code", code)
	body.Set("redirect_uri", f.RedirectURI)
	body.Set("code_verifier", f.verifier)
	body.Set("client_id", c.ClientID)

	resp, err := c.postForm(ctx, c.TokenPath, body)
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(resp, "exchange authorization code")
	}

	var raw struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if err := oauthhttp.ReadAndDecodeJSON(resp.Body, &raw, false); err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, errors.New("exchange authorization code: server returned 200 with no access token")
	}

	t := &tokens.TokenSet{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		TokenType:    raw.TokenType,
		Scope:        raw.Scope,
	}
	if raw.ExpiresIn > 0 {
		t.ExpiresAt = c.now().Add(oauthhttp.ExpiresInDuration(raw.ExpiresIn))
	}
	return t, nil
}

// postForm POSTs body as application/x-www-form-urlencoded to a path
// resolved against the client's BaseURL. The caller applies any per-request
// timeout via context.WithTimeout — the timeout must cover the body-read
// that happens after postForm returns.
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

func resolveURL(baseURL, path string, allowInsecureHTTP bool) (string, error) {
	return oauthhttp.ResolveURL(baseURL, path, allowInsecureHTTP) //nolint:wrapcheck // pass through with sentinel-preserving semantics
}

// readAPIError surfaces an error-shaped token-endpoint response, routing
// the AS's `error` code to a sentinel where one exists and appending a
// sanitised error_description.
func readAPIError(resp *http.Response, action string) error {
	apiErr, parseErr := oauthhttp.ReadOAuthError(resp)
	if parseErr != nil {
		return fmt.Errorf("%s: %w", action, parseErr)
	}
	err := errCodeToSentinel(apiErr.Error)
	if desc := oauthhttp.SanitizeDescription(apiErr.ErrorDescription); desc != "" {
		return fmt.Errorf("%s: %w: %s", action, err, desc)
	}
	return fmt.Errorf("%s: %w", action, err)
}

// errCodeToSentinel maps a token-endpoint error code to the matching
// sentinel. Unknown codes fall through to a generic error with the
// AS-supplied code sanitised before interpolation.
func errCodeToSentinel(code string) error {
	switch code {
	case "access_denied":
		return ErrAccessDenied
	case "invalid_grant":
		return ErrInvalidGrant
	default:
		return fmt.Errorf("oauth error: %s", oauthhttp.SanitizeDescription(code))
	}
}

// newPKCE returns a fresh PKCE verifier and its S256 challenge (RFC 7636
// §4.1–4.2).
func newPKCE() (verifier, challenge string, err error) {
	verifier, err = randomB64URL(verifierBytes)
	if err != nil {
		return "", "", fmt.Errorf("generate PKCE verifier: %w", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// randomB64URL returns nbytes of crypto-random data, base64url-encoded
// without padding (RFC 7636 §4.1 unreserved-character alphabet).
func randomB64URL(nbytes int) (string, error) {
	buf := make([]byte, nbytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// browserPageHTML is the page shown to the user who just completed (or
// failed) consent in their browser. Styled to match entire-core's CLI
// login pages (Marvin logo, card layout, light/dark via a
// prefers-color-scheme media query) so the whole login reads as one flow,
// but still self-contained: no scripts, no external resources — the real
// UX is back in the terminal.
const browserPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{title}} — Entire CLI</title>
<style>
  :root {
    --surface-base: #fafafa;
    --surface-raised: #ffffff;
    --text-default: #161616;
    --text-muted: #5d5d5d;
    --border-card: rgb(10 10 10 / 0.06);
    --font-headline: ui-sans-serif, system-ui, sans-serif;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --surface-base: #0c0c0c;
      --surface-raised: #181818;
      --text-default: #ebebeb;
      --text-muted: #aeaeae;
      --border-card: rgb(250 250 250 / 0.05);
    }
  }

  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1.5rem;
    background: var(--surface-base);
    color: var(--text-default);
    font-family: var(--font-headline);
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }
  .card {
    width: 100%;
    max-width: 28rem;
    border: 1px solid var(--border-card);
    background: var(--surface-raised);
    padding: 2.5rem 2rem;
    text-align: center;
  }
  .marvin { display: block; margin: 0 auto 1.25rem; color: var(--text-default); }
  h1 { margin: 0 0 0.5rem; font-size: 1.5rem; font-weight: 600; line-height: 1.25; }
  .note { margin: 0; color: var(--text-muted); font-size: 0.95rem; line-height: 1.5; }
</style>
</head>
<body>
<div class="card">
  <svg class="marvin" width="44" height="44" viewBox="0 0 32 32" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <path d="M17.6.22c1.61-.43,3.33-.21,4.77.61l7.47,4.25c.31.18.25.64-.09.73l-16.75,4.49c-1.69.45-2.69,2.19-2.24,3.88l.82,3.06c.45,1.69,2.19,2.69,3.88,2.24l9.57-2.5,4.61,4.74c.89.89,1.39,2.1,1.39,3.36v2.54c0,1.65-1.27,3.03-2.92,3.16l-15.61,1.2c-1.85.14-3.67-.53-4.98-1.85l-5.11-5.14c-.88-.89-1.38-2.09-1.38-3.35v-2.55c0-1.65,1.5-3.08,3-3.08h2l-3.85-3.04c-.6-.43-1.04-1.05-1.23-1.76l-.81-3.03c-.45-1.69.55-3.43,2.24-3.88L17.6.22Z" />
    <g transform="rotate(-18.8 17.52 13.94)">
      <ellipse cx="17.52" cy="13.94" rx="2.5" ry="2.5">
        <animate attributeName="ry" values="2.5;2.5;0.1;0.1;2.5" keyTimes="0;0.9231;0.9538;0.9615;1" calcMode="spline" keySplines="0 0 1 1;0.4 0 0.2 1;0 0 1 1;0 0.5 0.4 1" dur="3.25s" repeatCount="indefinite" />
      </ellipse>
    </g>
    <g transform="rotate(-18.8 25.52 11.94)">
      <ellipse cx="25.52" cy="11.94" rx="2.5" ry="2.5">
        <animate attributeName="ry" values="2.5;2.5;0.1;0.1;2.5" keyTimes="0;0.9231;0.9538;0.9615;1" calcMode="spline" keySplines="0 0 1 1;0.4 0 0.2 1;0 0 1 1;0 0.5 0.4 1" dur="3.25s" repeatCount="indefinite" />
      </ellipse>
    </g>
  </svg>
  <h1>{{title}}</h1>
  <p class="note">{{message}}</p>
</div>
</body>
</html>
`

// writeBrowserPage renders browserPageHTML with the given title and
// message. Both are HTML-escaped even though current callers only pass
// constants — the escaping is what keeps that a local invariant rather
// than a load-bearing one.
func writeBrowserPage(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	page := strings.NewReplacer(
		"{{title}}", html.EscapeString(title),
		"{{message}}", html.EscapeString(message),
	).Replace(browserPageHTML)
	_, _ = io.WriteString(w, page)
}
