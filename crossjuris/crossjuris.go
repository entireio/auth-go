// Package crossjuris is an http.RoundTripper that follows entire-core's
// cross-jurisdiction 421 redirects.
//
// A multi-region deployment answers a request for a resource whose home
// is another region with 421 Misdirected Request and a JSON body naming
// the home core:
//
//	{"error":"...","home_core_url":"https://core.eu.example"}
//
// Transport rewrites the request at that origin and retries it once,
// replaying the buffered body. Before it follows, the target must pass a
// trust gate: its host has to appear in the responding core's federation
// manifest, fetched lazily from GET /.well-known/entire-federation on the
// origin that emitted the 421. The manifest is cached per origin for the
// life of the Transport, negative results included.
//
// With Config.ClientID set the Transport also runs the RFC 8693 exchange a
// home core may still demand for a foreign-region login JWT (see
// exchange.go). That branch is scheduled for removal once every region
// accepts sibling-region login JWTs directly; follow-only consumers leave
// ClientID empty and never enter it.
//
// The package reads no environment variables. Trace output goes through
// Config.Logf, which consumers typically gate on their own debug flag.
package crossjuris

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
	"sync"
	"time"

	"github.com/entireio/auth-go/internal/oauthhttp"
)

// WellKnownPath is the federation-trust manifest entire-core serves on
// every origin. Public and unauthenticated: the peer list names siblings
// any user can already enumerate via login.
const WellKnownPath = "/.well-known/entire-federation"

// TokenPath is entire-core's RFC 8693 token-exchange endpoint, always
// same-origin with the core that emitted the 401 or 421.
const TokenPath = "/oauth/token" //nolint:gosec // G101: a URL path, not a credential

// federationLookupTimeout caps the lazy manifest fetch on the critical
// path of a 421 follow. The endpoint is local to the responding core and
// the response is small; a slow fetch must not stall the redirect.
const federationLookupTimeout = 3 * time.Second

// Body caps. Control-plane envelopes are small; these bound what a
// misbehaving server can make the client buffer.
const (
	maxMisdirectedBody  = 64 * 1024
	maxUnauthorizedBody = 8 * 1024
	maxFederationBody   = 16 * 1024
)

// Config configures a Transport. Zero values are usable: a Transport
// with an empty Config follows 421s over http.DefaultTransport and
// never exchanges.
type Config struct {
	// Base puts requests on the wire. nil selects http.DefaultTransport.
	//
	// Requests the Transport builds itself (the manifest fetch and the
	// exchange) go straight to Base, so anything that must stamp every
	// request — a User-Agent wrapper, say — belongs in Base, not around
	// the Transport.
	Base http.RoundTripper

	// ClientID is the public OAuth client_id presented on the RFC 8693
	// exchange at a home core. Empty disables the exchange branch: 421s
	// are still followed, every 401 passes through unchanged.
	ClientID string

	// AllowInsecureHTTP permits http:// server-supplied URLs (home_core_url,
	// token_exchange_url) when the host is loopback, so httptest fixtures
	// work. Production callers leave it false: the user's login JWT is
	// re-targeted at these URLs and must travel over TLS.
	AllowInsecureHTTP bool

	// Logf receives one line per recovery decision the Transport makes
	// (a followed or refused 421, a refused exchange URL, a failed
	// exchange). nil is silent. The hops are otherwise invisible, so a
	// misconfigured federation is hard to diagnose without it; consumers
	// usually wire this to a debug-flag-gated stderr printer.
	Logf func(format string, args ...any)
}

// Transport is the http.RoundTripper. Construct with New; the zero
// value is not usable.
type Transport struct {
	base          http.RoundTripper
	clientID      string
	allowInsecure bool
	logf          func(format string, args ...any)

	federation sync.Map // origin (scheme://host) → cachedFederation
	tokens     sync.Map // origin (scheme://host) → cachedExchangedToken
}

// New builds a Transport from cfg. It fails only on a ClientID that
// could not be sent as HTTP Basic credentials (RFC 6749 §2.3.1), so a
// misconfiguration surfaces at startup rather than on the first 401.
func New(cfg Config) (*Transport, error) {
	if err := oauthhttp.ValidateClientID(cfg.ClientID); err != nil {
		return nil, fmt.Errorf("crossjuris.New: %w", err)
	}
	base := cfg.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return &Transport{
		base:          base,
		clientID:      cfg.ClientID,
		allowInsecure: cfg.AllowInsecureHTTP,
		logf:          cfg.Logf,
	}, nil
}

func (t *Transport) debugf(format string, args ...any) {
	if t.logf != nil {
		t.logf(format, args...)
	}
}

// hop tracks one request's recovery budget across retries.
//
// Redirects share a single budget for the whole call. Exchanges are
// bounded per origin so a 421-then-401 chain does not starve the home
// core of its one attempt. afterRedirect records that the current hop
// was reached by following a 421 — the trigger for the bare-401
// exchange, see exchange.go.
type hop struct {
	redirects     int
	triedExchange map[string]bool
	afterRedirect bool
}

// RoundTrip implements http.RoundTripper.
//
// The caller's request is cloned, its body buffered once for replay, and
// its Authorization header snapshotted: that original bearer is what
// every retry presents (unless a cached exchanged token exists for the
// hop's origin) and what every exchange uses as subject_token.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := bufferBody(req)
	if err != nil {
		return nil, fmt.Errorf("crossjuris: buffer body: %w", err)
	}
	req = req.Clone(req.Context())
	originalAuth := req.Header.Get("Authorization")
	return t.send(req, body, originalAuth, hop{redirects: 1, triedExchange: map[string]bool{}})
}

func (t *Transport) send(req *http.Request, body []byte, originalAuth string, budget hop) (*http.Response, error) {
	// Choose this hop's Authorization explicitly rather than inheriting
	// whatever a previous hop stamped: an exchanged token is scoped to
	// one origin and must not leak to another.
	origin := requestOrigin(req)
	switch cached, ok := t.lookupToken(origin); {
	case ok:
		req.Header.Set("Authorization", "Bearer "+cached)
	case originalAuth != "":
		req.Header.Set("Authorization", originalAuth)
	}
	resetBody(req, body)

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		// Returned verbatim: http.Client wraps every RoundTripper failure
		// in a *url.Error that already names the method and URL.
		return nil, err //nolint:wrapcheck // see above
	}

	switch resp.StatusCode {
	case http.StatusMisdirectedRequest:
		if budget.redirects <= 0 {
			return resp, nil
		}
		next, err := t.followMisdirected(req, resp, origin)
		if err != nil {
			// Surface the original response so the caller sees the
			// server's body.
			t.debugf("421 from %s not followed: %v", origin, err)
			return resp, nil
		}
		t.debugf("421 from %s: retrying at %s", origin, requestOrigin(next))
		_ = resp.Body.Close()
		budget.redirects--
		budget.afterRedirect = true
		return t.send(next, body, originalAuth, budget)
	case http.StatusUnauthorized:
		if t.clientID == "" {
			return resp, nil
		}
		return t.recoverUnauthorized(req, resp, body, originalAuth, origin, budget)
	}
	return resp, nil
}

// misdirectedBody is entire-core's 421 envelope.
type misdirectedBody struct {
	HomeCoreURL string `json:"home_core_url"`
}

// followMisdirected reads the 421 envelope and builds a fresh request
// at the home core with the original method, headers, path, and query.
// The body is attached by send. On any failure the response body has
// been restored so the caller can hand resp back unchanged.
//
// Trust gate: home_core_url must be a safe origin (see isSafeOrigin)
// and its host must appear in the federation manifest of responseOrigin,
// the core that emitted the 421 and one the caller already chose to
// talk to.
func (t *Transport) followMisdirected(orig *http.Request, resp *http.Response, responseOrigin string) (*http.Request, error) {
	raw, err := drainAndRestoreBody(resp, maxMisdirectedBody)
	if err != nil {
		return nil, fmt.Errorf("read 421 body: %w", err)
	}
	var env misdirectedBody
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("parse 421 body: %w", err)
	}
	if env.HomeCoreURL == "" {
		return nil, errors.New("421 body missing home_core_url")
	}
	home, err := url.Parse(strings.TrimRight(env.HomeCoreURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse home_core_url: %w", err)
	}
	if !t.isSafeOrigin(home) {
		return nil, fmt.Errorf("home_core_url %q is not https (or permitted http loopback)", env.HomeCoreURL)
	}
	peers := t.federationHostsFor(orig.Context(), responseOrigin)
	if _, ok := peers[home.Host]; !ok {
		return nil, fmt.Errorf("home_core_url host %q is not in the responding core's federation manifest", home.Host)
	}
	target := *home
	target.Path = orig.URL.Path
	target.RawPath = orig.URL.RawPath
	target.RawQuery = orig.URL.RawQuery
	next, err := http.NewRequestWithContext(orig.Context(), orig.Method, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build redirected request: %w", err)
	}
	next.Header = orig.Header.Clone()
	return next, nil
}

// isSafeOrigin reports whether u may receive the user's login JWT:
// https always, http only for loopback and only when the Transport was
// configured to allow it.
func (t *Transport) isSafeOrigin(u *url.URL) bool {
	switch u.Scheme {
	case "https":
		return u.Host != ""
	case "http":
		return t.allowInsecure && oauthhttp.IsLoopbackHost(u.Hostname())
	default:
		return false
	}
}

// federationBody is the GET /.well-known/entire-federation response.
// Empty or missing peer_auth_hosts means no peers are trusted.
type federationBody struct {
	PeerAuthHosts []string `json:"peer_auth_hosts"`
}

// cachedFederation is one manifest lookup's result. A failed fetch is
// cached as nil hosts like any other answer: an attacker cannot bypass
// the gate by 421-spamming for a stale negative, because nil still
// rejects every host.
type cachedFederation struct {
	hosts map[string]struct{}
}

// federationHostsFor returns the hosts origin publishes as federation
// peers, fetching the manifest on first use and caching the answer for
// the life of the Transport. nil means no 421 from origin is followed.
func (t *Transport) federationHostsFor(ctx context.Context, origin string) map[string]struct{} {
	if origin == "" {
		return nil
	}
	if v, ok := t.federation.Load(origin); ok {
		cached, _ := v.(cachedFederation) //nolint:errcheck // type assertion, not error
		return cached.hosts
	}
	hosts := t.fetchFederationHosts(ctx, origin)
	t.federation.Store(origin, cachedFederation{hosts: hosts})
	return hosts
}

// fetchFederationHosts performs the one-shot manifest GET. Any failure
// (transport error, non-200, parse error, empty list) yields nil.
func (t *Transport) fetchFederationHosts(ctx context.Context, origin string) map[string]struct{} {
	ctx, cancel := context.WithTimeout(ctx, federationLookupTimeout)
	defer cancel()
	// origin is a core the caller already dials and the path is fixed,
	// so this is not an attacker-steerable fetch.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+WellKnownPath, nil)
	if err != nil {
		t.debugf("build federation request: %v", err)
		return nil
	}
	req.Header.Set("Accept", "application/json")
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		t.debugf("federation fetch from %s: %v", origin, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.debugf("federation fetch from %s returned HTTP %d", origin, resp.StatusCode)
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFederationBody))
	if err != nil {
		t.debugf("read federation body: %v", err)
		return nil
	}
	var env federationBody
	if err := json.Unmarshal(raw, &env); err != nil {
		t.debugf("parse federation body: %v", err)
		return nil
	}
	if len(env.PeerAuthHosts) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(env.PeerAuthHosts))
	for _, peer := range env.PeerAuthHosts {
		u, err := url.Parse(peer)
		if err != nil || u.Host == "" {
			continue
		}
		out[u.Host] = struct{}{}
	}
	return out
}

// drainAndRestoreBody reads up to maxBytes of resp.Body and replaces it
// with an in-memory reader over those bytes, so the caller can still
// hand resp back with a readable body.
func drainAndRestoreBody(resp *http.Response, maxBytes int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(raw)) // restore even on error
	if err != nil {
		return nil, fmt.Errorf("drain response body: %w", err)
	}
	return raw, nil
}

// bufferBody reads req.Body once so each retry can replay it. Returns
// nil when there is no body.
func bufferBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	buf, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	return buf, nil
}

// resetBody attaches a fresh reader over buf (and matching
// ContentLength and GetBody) to req. Safe when buf is nil.
func resetBody(req *http.Request, buf []byte) {
	if buf == nil {
		req.Body = http.NoBody
		req.ContentLength = 0
		req.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(buf))
	req.ContentLength = int64(len(buf))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf)), nil
	}
}

// requestOrigin returns scheme://host of req, or "" when req.URL is
// not absolute.
func requestOrigin(req *http.Request) string {
	if req.URL == nil || req.URL.Scheme == "" || req.URL.Host == "" {
		return ""
	}
	return req.URL.Scheme + "://" + req.URL.Host
}
