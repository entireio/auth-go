// Package tokenmanager orchestrates core-token storage and RFC 8693
// token exchanges for an OAuth 2.0 device-flow client.
//
// One Manager per CLI process. Construct it once from the embedding
// CLI's identity (Issuer, ClientID, STSPath, Store) and call
// TokenForResource / Token from data-API call sites.
//
// The package is provider-agnostic: every endpoint, identifier, and
// default value comes from Config. It has no env-var reads, no
// implicit URLs, and no embedded provider tables. Tests inject
// behaviour via SetExchangeForTest / SetNowForTest (see testseams.go)
// rather than via the public Config — keeping the STS call out of the
// caller-controllable surface.
package tokenmanager

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/entireio/auth-go/internal/oauthhttp"
	"github.com/entireio/auth-go/sts"
	"github.com/entireio/auth-go/tokens"
	"github.com/entireio/auth-go/tokenstore"
)

// DefaultRequestedTokenType is the RFC 8693 §3 URI used when neither
// Config.RequestedTokenType nor TokenRequest.RequestedTokenType is set.
// :access_token is the canonical "give me an OAuth access token" URI;
// the wire format is the server's choice.
//
//nolint:gosec // RFC 8693 token-type URI, not a credential
const DefaultRequestedTokenType = "urn:ietf:params:oauth:token-type:access_token"

// exchangeSkew is the safety margin applied when deciding whether a
// cached exchanged token is still usable. Set conservatively because
// the worst case (re-exchange one extra time per command) is cheap.
const exchangeSkew = 30 * time.Second

// ErrNotLoggedIn is returned by Token / TokenForResource when no core
// token is present in the store. Callers can match on it to render a
// "run <login>" message.
var ErrNotLoggedIn = errors.New("not logged in")

// ErrNoSTSPath is returned when an exchange is needed but Config.STSPath
// is empty. Single-host deployments hit the same-host shortcut and never
// reach this; split-host deployments must configure STSPath.
var ErrNoSTSPath = errors.New("token exchange required but Config.STSPath is empty")

// Config configures a Manager.
type Config struct {
	// Issuer is the auth host base URL where the device-flow login
	// happened and STS exchanges are POSTed. Required. Doubles as the
	// Store profile key, so a user can be logged into multiple issuers
	// (e.g. regions / staging) without conflict.
	Issuer string

	// ClientID identifies the public client per RFC 6749 §2.3.1 / §3.2.1.
	// Sent on STS exchanges via the client_id form field. Required.
	ClientID string

	// STSPath is the path on Issuer where token-exchange requests are
	// POSTed. Optional: single-host deployments never trigger an
	// exchange (the same-host shortcut wins) so they can leave it
	// empty. When empty and an exchange is attempted, runExchange
	// returns ErrNoSTSPath rather than POSTing to a bogus URL.
	STSPath string

	// Store persists the core token. Required. Use any tokenstore.Store
	// implementation; a per-CLI service name keeps credentials isolated
	// from other CLIs sharing this library.
	Store tokenstore.Store

	// RequestedTokenType is the default RFC 8693 requested_token_type
	// URI. Empty → DefaultRequestedTokenType.
	RequestedTokenType string

	// SubjectTokenType is the RFC 8693 subject_token_type sent on
	// exchanges. Empty → sts.SubjectTokenTypeAccessToken, because the
	// stored core token is an OAuth access token even when its wire format
	// happens to be JWT.
	SubjectTokenType string

	// Scope is the default scope sent on exchanges. Empty → omitted.
	Scope string

	// UserAgent for HTTP requests. Empty → none.
	UserAgent string

	// AllowInsecureHTTP permits exchanges against http:// issuers. Off
	// by default — STS calls ship the user's core token in the request
	// body and must be TLS-protected. Only flip this for local/dev
	// deployments pinned to loopback.
	AllowInsecureHTTP bool

	// Transport overrides the http.RoundTripper used for STS calls.
	// Useful for installing a debug logger or proxy. nil →
	// http.DefaultTransport. Replaces the previous HTTPClient field —
	// see sts.Client.Transport for the security rationale.
	Transport http.RoundTripper
}

func (c Config) validate() error {
	switch {
	case strings.TrimSpace(c.Issuer) == "":
		return errors.New("Config.Issuer is required")
	case strings.TrimSpace(c.ClientID) == "":
		return errors.New("Config.ClientID is required")
	case c.Store == nil:
		return errors.New("Config.Store is required")
	}
	return nil
}

// exchangeFunc / nowFuncType are named so we can hold them in
// atomic.Pointer values. Storing the override behind an
// atomic.Pointer rather than a plain field plus mu lets the hot read
// paths (runExchange, m.now) avoid taking the lock — they were
// previously racing with SetExchangeForTest / SetNowForTest.
type exchangeFunc func(ctx context.Context, req sts.ExchangeRequest) (*tokens.TokenSet, error)
type nowFuncType func() time.Time

// Manager orchestrates core-token storage and STS exchanges. Safe for
// concurrent use.
type Manager struct {
	cfg Config

	mu    sync.Mutex
	cache map[cacheKey]cachedToken

	// Test seams. Set only via SetExchangeForTest / SetNowForTest,
	// both of which require a testing.TB to discourage production
	// callers from synthesising a fake TB to bypass STS. Held behind
	// atomic.Pointer so hot-path reads (runExchange, now) don't race
	// against test setup/teardown.
	exchangeOverride atomic.Pointer[exchangeFunc]
	nowOverride      atomic.Pointer[nowFuncType]
}

// now returns the manager's effective clock. Tests can replace it via
// SetNowForTest; production callers always get time.Now.
func (m *Manager) now() time.Time {
	if p := m.nowOverride.Load(); p != nil {
		return (*p)()
	}
	return time.Now()
}

// New builds a Manager from cfg. Returns an error when required
// fields are missing or Issuer is not an absolute URL.
//
// Issuer is normalized via RFC 3986 §6.2.2 (lowercase scheme/host,
// default-port stripped, no trailing slash) before being used as the
// Store profile key and as the same-host shortcut comparison. Without
// this, two Managers configured with cosmetically-different issuers
// (`https://auth.example.com/` vs `https://auth.example.com`) would
// write to different keyring entries but compare equal for the
// shortcut — one Manager handing out the other's tokens.
func New(cfg Config) (*Manager, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(cfg.Issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("Config.Issuer must be an absolute URL with scheme and host, got %q", cfg.Issuer)
	}
	cfg.Issuer = oauthhttp.NormalizeOriginURL(cfg.Issuer)
	if cfg.RequestedTokenType == "" {
		cfg.RequestedTokenType = DefaultRequestedTokenType
	}
	if cfg.SubjectTokenType == "" {
		cfg.SubjectTokenType = sts.SubjectTokenTypeAccessToken
	}
	return &Manager{cfg: cfg, cache: map[cacheKey]cachedToken{}}, nil
}

// Issuer returns the configured issuer URL.
func (m *Manager) Issuer() string { return m.cfg.Issuer }

// SaveCoreToken persists the full device-flow token bundle under the
// configured Issuer. Takes the entire tokens.TokenSet (rather than
// just the access token) so RefreshToken, absolute ExpiresAt, and
// Scope survive the round-trip through the keyring — earlier versions
// dropped these fields silently, blocking refresh-token support and
// losing the wire-side expiry hint for opaque tokens.
//
// AccessToken is required (rejected here rather than letting it
// surface as a confusing "Bearer <empty>" later). The tokens.TokenSet
// is otherwise stored verbatim; consumers can read the persisted
// fields back via Store.LoadTokens.
//
// On successful save the in-memory exchange cache is cleared so a
// re-login under a different identity can't return the previous user's
// exchanged tokens. The cacheKey already binds entries to the core
// token's SHA-256 hash, so this is defence-in-depth — see
// TestSaveCoreToken_ClearsExchangeCache.
func (m *Manager) SaveCoreToken(t tokens.TokenSet) error {
	if t.AccessToken == "" {
		return errors.New("save core token: AccessToken is empty")
	}
	if err := m.cfg.Store.SaveTokens(m.cfg.Issuer, t); err != nil {
		return fmt.Errorf("save core token: %w", err)
	}
	m.mu.Lock()
	m.cache = map[cacheKey]cachedToken{}
	m.mu.Unlock()
	return nil
}

// LookupCoreToken returns the stored core token, or "" if none is
// stored. A nil-return-no-error mirrors how callers expect
// "not-logged-in" to look.
func (m *Manager) LookupCoreToken() (string, error) {
	t, err := m.cfg.Store.LoadTokens(m.cfg.Issuer)
	if errors.Is(err, tokenstore.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("load core token: %w", err)
	}
	return t.AccessToken, nil
}

// DeleteCoreToken removes the stored core token and any cached
// exchanges derived from it.
//
// Order matters: the keyring delete runs first, then the in-memory
// cache is cleared. If the keyring delete fails the cache is left
// alone — clearing it pre-emptively would create a window where the
// CLI thinks it's logged out (no cache entries) but the keyring
// still hands out the core token to the next process.
func (m *Manager) DeleteCoreToken() error {
	if err := m.cfg.Store.DeleteTokens(m.cfg.Issuer); err != nil {
		return fmt.Errorf("delete core token: %w", err)
	}
	m.mu.Lock()
	m.cache = map[cacheKey]cachedToken{}
	m.mu.Unlock()
	return nil
}

// TokenRequest customises one Token call. Empty fields fall back to
// Config defaults.
type TokenRequest struct {
	// Resource is the origin where the bearer will be presented.
	// Required. Used for the same-host shortcut, the JWT-aud shortcut,
	// and as part of the cache key.
	Resource string

	// Audience is the wire-level RFC 8693 audience parameter. Empty →
	// omitted (the AS picks). Independent of Resource — most callers
	// leave Audience empty.
	Audience string

	// RequestedTokenType overrides Config.RequestedTokenType for this
	// call. Empty → Config default.
	RequestedTokenType string

	// Scope overrides Config.Scope for this call. Empty → Config default.
	Scope string
}

// TokenForResource is a convenience for Token using only Resource.
func (m *Manager) TokenForResource(ctx context.Context, resourceBaseURL string) (string, error) {
	return m.Token(ctx, TokenRequest{Resource: resourceBaseURL})
}

// Token resolves a bearer token for use against req.Resource,
// performing an RFC 8693 exchange when needed.
//
// Resolution rules:
//
//  1. No core token in the store → ErrNotLoggedIn.
//  2. m.Issuer() == req.Resource (and req.Audience is empty) → use
//     the core token directly. Single-host deployments hit this path.
//  3. Core token's `aud` claim already includes req.Resource → use
//     the core token directly. Multi-audience tokens skip exchange.
//  4. Otherwise → RFC 8693 token exchange.
//
// Successful exchanges are cached in-memory keyed by (core token,
// resource, audience, requested-token-type, scope) until expiry.
func (m *Manager) Token(ctx context.Context, req TokenRequest) (string, error) {
	if strings.TrimSpace(req.Resource) == "" {
		return "", errors.New("TokenRequest.Resource is required")
	}
	normResource, err := oauthhttp.ValidateOriginURL(req.Resource, m.cfg.AllowInsecureHTTP, "TokenRequest.Resource")
	if err != nil {
		return "", err
	}

	core, err := m.LookupCoreToken()
	if err != nil {
		return "", err
	}
	if core == "" {
		return "", ErrNotLoggedIn
	}
	// Preflight expiry: a long-stored core token would otherwise hit the
	// resource (or STS) and surface as a confusing "invalid_grant" /
	// "401". Parse-failure is intentionally not treated as expired —
	// opaque (non-JWT) access tokens have no client-visible expiry, so
	// we let them flow and trust the server to reject if necessary.
	if coreTokenExpired(core, m.now()) {
		return "", ErrNotLoggedIn
	}

	// m.cfg.Issuer was normalized at New() time, so no re-normalize here.
	if req.Audience == "" && m.cfg.Issuer == normResource {
		return core, nil
	}
	if req.Audience == "" && coreTokenAudienceIncludes(core, normResource) {
		return core, nil
	}

	resolved := m.resolve(req)
	resolved.Resource = normResource
	key := makeCacheKey(core, resolved, normResource)
	if hit, ok := m.cacheLookup(key); ok {
		return hit, nil
	}

	exchanged, err := m.runExchange(ctx, core, resolved)
	if err != nil {
		return "", err
	}
	m.cacheStore(key, exchanged)
	return exchanged.AccessToken, nil
}

// resolve fills empty TokenRequest fields with Config defaults.
func (m *Manager) resolve(req TokenRequest) TokenRequest {
	if req.RequestedTokenType == "" {
		req.RequestedTokenType = m.cfg.RequestedTokenType
	}
	if req.Scope == "" {
		req.Scope = m.cfg.Scope
	}
	return req
}

// coreTokenExpired reports whether the core token is not currently
// usable: either its `exp` claim is in the past (or within
// exchangeSkew of now) or its `nbf` claim is in the future. JWT
// parse failures (and tokens without an `exp` claim) are reported as
// not-expired so opaque access tokens flow through the rest of the
// resolution rules unchanged.
//
// Applying exchangeSkew here closes a race: a token expiring at
// now+1ms is technically "live", but if we present it to the resource
// (or STS), the request body's TLS handshake + DNS + queue can easily
// push the AS-side validation past the wire-side exp — landing a
// confusing invalid_grant / 401 that triggers a re-login at the worst
// moment. The cost is one fresh login slightly earlier than strictly
// necessary; the cache's exchangeSkew uses the same window so the
// two stay in sync.
//
// Enforcing `nbf` is defence in depth — a token that's not-yet-valid
// shouldn't be presented either. RFC 7519 §4.1.5 requires the
// processor to reject a JWT with `nbf` in the future.
func coreTokenExpired(coreJWT string, now time.Time) bool {
	claims, err := tokens.ParseClaims(coreJWT)
	if err != nil {
		return false
	}
	if !claims.NotBefore.IsZero() && now.Before(claims.NotBefore) {
		return true
	}
	if claims.ExpiresAt.IsZero() {
		return false
	}
	return !now.Add(exchangeSkew).Before(claims.ExpiresAt)
}

// coreTokenAudienceIncludes reports whether the core JWT's `aud` claim
// covers target. target is expected to already be in normalised form;
// aud entries are normalised here so a trailing-slash / case difference
// between the AS and the caller doesn't force a needless STS exchange.
func coreTokenAudienceIncludes(coreJWT, target string) bool {
	claims, err := tokens.ParseClaims(coreJWT)
	if err != nil {
		return false
	}
	for _, aud := range claims.Audience {
		if oauthhttp.NormalizeOriginURL(aud) == target {
			return true
		}
	}
	return false
}

// maxCachedTokenLifetime bounds entries with an unknown wire-side
// expiry. Today this can't happen on the exchange path (sts.Exchange
// rejects non-positive expires_in), but it would still apply if a
// future code path stored a TokenSet without ExpiresAt — capping at 1h
// prevents an indefinitely-cached stale token in that case.
const maxCachedTokenLifetime = time.Hour

// cachedToken is one entry in the per-process exchange cache.
type cachedToken struct {
	accessToken string
	expiresAt   time.Time
	cachedAt    time.Time
}

func (c cachedToken) usable(now time.Time) bool {
	if c.accessToken == "" {
		return false
	}
	if c.expiresAt.IsZero() {
		return now.Sub(c.cachedAt) < maxCachedTokenLifetime
	}
	return now.Add(exchangeSkew).Before(c.expiresAt)
}

// cacheKey is a structurally-keyed exchange-cache key. Using a struct
// rather than a delimiter-joined string sidesteps any chance of two
// distinct (core token, resource, audience, requested-token-type,
// scope) tuples hashing to the same map slot via embedded delimiters
// in any field.
//
// CoreTokenHash is a SHA-256 of the core token rather than the token
// itself: a long-running embedder (daemon, server agent) accumulates
// one cache entry per (Resource, Audience, RequestedTokenType, Scope)
// tuple, so embedding the full token replicates the bearer N times
// across the per-process exchange cache. Memory dumps, crash reports,
// and profile heap snapshots then leak N copies. The hash is a stable
// identifier (collision-resistant for this purpose) that still
// distinguishes between cores from different logins.
type cacheKey struct {
	CoreTokenHash      [sha256.Size]byte
	Resource           string
	Audience           string
	RequestedTokenType string
	Scope              string
}

// makeCacheKey builds a cacheKey from the (resolved) request. Includes
// every wire-affecting field so different combinations don't shadow
// each other. normalizedResource is the caller-supplied Resource after
// normalisation, so https://api.example.com and
// https://api.example.com/ share a single cache entry.
func makeCacheKey(coreToken string, req TokenRequest, normalizedResource string) cacheKey {
	return cacheKey{
		CoreTokenHash:      sha256.Sum256([]byte(coreToken)),
		Resource:           normalizedResource,
		Audience:           req.Audience,
		RequestedTokenType: req.RequestedTokenType,
		Scope:              req.Scope,
	}
}

func (m *Manager) cacheLookup(key cacheKey) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.cache[key]
	if !ok {
		return "", false
	}
	if !entry.usable(m.now()) {
		delete(m.cache, key)
		return "", false
	}
	return entry.accessToken, true
}

func (m *Manager) cacheStore(key cacheKey, t *tokens.TokenSet) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache[key] = cachedToken{
		accessToken: t.AccessToken,
		expiresAt:   t.ExpiresAt,
		cachedAt:    m.now(),
	}
}

// runExchange dispatches to either Config.Exchange (test override) or
// a freshly built sts.Client pointing at m.cfg.Issuer + m.cfg.STSPath.
func (m *Manager) runExchange(ctx context.Context, coreToken string, req TokenRequest) (*tokens.TokenSet, error) {
	stsReq := sts.ExchangeRequest{
		SubjectToken:       coreToken,
		SubjectTokenType:   m.cfg.SubjectTokenType,
		RequestedTokenType: req.RequestedTokenType,
		Audience:           req.Audience,
		Resource:           req.Resource,
		Scope:              req.Scope,
		// Public-client identification per RFC 6749 §2.3.1 / §3.2.1.
		// Carried via Extra because the sts package is provider-agnostic.
		Extra: url.Values{"client_id": {m.cfg.ClientID}},
	}

	if p := m.exchangeOverride.Load(); p != nil {
		return (*p)(ctx, stsReq)
	}

	if strings.TrimSpace(m.cfg.STSPath) == "" {
		return nil, ErrNoSTSPath
	}

	stsClient := &sts.Client{
		Transport:         m.cfg.Transport,
		BaseURL:           m.cfg.Issuer,
		Path:              m.cfg.STSPath,
		UserAgent:         m.cfg.UserAgent,
		AllowInsecureHTTP: m.cfg.AllowInsecureHTTP,
	}
	return stsClient.Exchange(ctx, stsReq) //nolint:wrapcheck // sts.Exchange already prefixes "token exchange:"
}
