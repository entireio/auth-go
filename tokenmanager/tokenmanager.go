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
// behaviour via SetExchangeForTest / SetNowForTest / SetRefreshForTest /
// SetProcessLockForTest (see testseams.go) rather than via the public
// Config — keeping the STS call out of the caller-controllable surface.
package tokenmanager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/entireio/auth-go/internal/oauthhttp"
	"github.com/entireio/auth-go/internal/proclock"
	"github.com/entireio/auth-go/refresh"
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

// ErrNotLoggedIn is returned by Token / TokenForResource when no core token
// is present in the store, or when a stored token is expired and carries no
// refresh token (the session cannot be silently renewed). Callers can match
// on it to render a "run <login>" message.
var ErrNotLoggedIn = errors.New("not logged in")

// ErrNoSTSPath is returned when an exchange is needed but Config.STSPath
// is empty. Single-host deployments hit the same-host shortcut and never
// reach this; split-host deployments must configure STSPath.
var ErrNoSTSPath = errors.New("token exchange required but Config.STSPath is empty")

// ErrReauthRequired is returned by Token / Refresh when the stored refresh
// token is genuinely revoked or expired (server returned invalid_grant and
// a store re-read confirmed the refresh token was not concurrently
// rotated). Distinct from ErrNotLoggedIn — there was a credential, the
// session simply needs a fresh interactive login. Callers can match on it
// to render "your session expired, log in again".
var ErrReauthRequired = errors.New("reauthentication required")

// ErrNoRefreshPath is returned when a refresh is needed but
// Config.RefreshPath is empty. Mirrors ErrNoSTSPath.
var ErrNoRefreshPath = errors.New("refresh required but Config.RefreshPath is empty")

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

	// RefreshPath is the token-endpoint path where grant_type=refresh_token
	// is POSTed to re-mint the login JWT. Optional: when empty and a
	// refresh is needed, runRefresh returns ErrNoRefreshPath. Often equal
	// to STSPath or the device-flow token path, since servers typically
	// multiplex grants at one /oauth/token.
	RefreshPath string

	// LockDir is the directory holding the cross-process advisory lock
	// file. Empty → os.UserCacheDir()/auth-go (falling back to the system
	// temp dir if the user cache dir is unavailable). The lock file holds
	// no credentials.
	LockDir string

	// Store persists the core token. Required. Use any tokenstore.Store
	// implementation; a per-CLI service name keeps credentials isolated
	// from other CLIs sharing this library.
	Store tokenstore.Store

	// RequestedTokenType is the default RFC 8693 requested_token_type
	// URI. Empty → DefaultRequestedTokenType.
	RequestedTokenType string

	// SubjectTokenType is the RFC 8693 subject_token_type sent on
	// exchanges. Empty → sts.SubjectTokenTypeAccessToken.
	//
	// :access_token is the RFC 8693 §3 URI for "OAuth 2.0 access token
	// issued by the given authorization server" — exactly what the
	// device-code grant returns into Store. The distinction from :jwt
	// matters at the server: zitadel-oidc's STS validator (pkg/op/
	// token_exchange.go's GetTokenIDAndSubjectFromToken) only switches on
	// :access_token / :refresh_token / :id_token; :jwt passes the
	// IsSupported() check upstream but silently falls through to the
	// not-handled branch and surfaces as the (uninformative)
	// "subject_token is invalid" error_description. Other servers
	// generally treat :jwt and :access_token interchangeably for OAuth
	// access tokens, so :access_token is the safer default. A caller who
	// genuinely needs :jwt semantics (RFC 7519 JWT-as-credential rather
	// than OAuth-issued bearer) can set this field explicitly, or bypass
	// tokenmanager and call sts.Client.Exchange directly.
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

// ProcessLock serialises credential mutations (refresh, save, delete)
// across processes. Acquire blocks until the lock is held or ctx is done,
// returning an idempotent release func. On error the returned release func
// is nil and must not be called. The default implementation is a file lock
// (internal/proclock); SetProcessLockForTest swaps a fake.
type ProcessLock interface {
	Acquire(ctx context.Context) (release func(), err error)
}

type refreshFunc func(ctx context.Context, req refresh.Request) (*tokens.TokenSet, error)

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

	// refreshMu is the in-process single-flight gate for re-mints. Held
	// across the cross-process lock + grant so concurrent goroutines
	// coalesce onto one re-mint (the second waiter re-reads a fresh token).
	refreshMu sync.Mutex

	// Refresh + process-lock test seams; see SetRefreshForTest /
	// SetProcessLockForTest. Same atomic.Pointer rationale as above.
	refreshOverride atomic.Pointer[refreshFunc]
	lockOverride    atomic.Pointer[ProcessLock]

	lockOnce    sync.Once
	defaultLock ProcessLock
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
	// Hold Issuer to the same origin-URL contract as TokenRequest.Resource:
	// userinfo, path, query, fragment all forbidden. The same-host shortcut
	// (Token) byte-compares the normalised Resource against cfg.Issuer; an
	// Issuer that still carries userinfo or a path silently fails that
	// equality even when the caller's Resource is the "same" origin.
	normIssuer, err := oauthhttp.ValidateOriginURL(cfg.Issuer, cfg.AllowInsecureHTTP, "Config.Issuer")
	if err != nil {
		return nil, err //nolint:wrapcheck // pass through with field-named message
	}
	cfg.Issuer = normIssuer
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
//
// SaveCoreToken is serialised against in-flight refreshes by acquiring
// refreshMu and the cross-process lock before mutating the store. Without
// this, a refresh whose grant is mid-flight could land its persist after
// a concurrent SaveCoreToken (re-login) and overwrite the new identity
// with the old account's refreshed credentials. Lock ordering matches
// refreshLocked: refreshMu first, then processLock. Can block up to
// ~30s under contention and may return a wrapped lock error. The
// empty-AccessToken check fires before lock acquisition so an obviously
// bad call doesn't touch the filesystem.
func (m *Manager) SaveCoreToken(t tokens.TokenSet) error {
	if t.AccessToken == "" {
		return errors.New("save core token: AccessToken is empty")
	}
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	release, err := m.processLock().Acquire(context.Background())
	if err != nil {
		return fmt.Errorf("save core token: acquire lock: %w", err)
	}
	defer release()
	return m.saveCoreTokenLocked(t)
}

// saveCoreTokenLocked is the lock-free persist path. Caller MUST hold
// refreshMu and the process lock. Used by SaveCoreToken (which acquires
// them) and by persistRefreshed (which runs inside refreshLocked where
// both are already held — a recursive lock attempt here would
// self-deadlock).
//
// The empty-AccessToken check is duplicated here as defence in depth
// because the locked variant is also reachable from persistRefreshed.
func (m *Manager) saveCoreTokenLocked(t tokens.TokenSet) error {
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

// Refresh ensures a fresh login JWT, re-minting it from the stored refresh
// token when the current one is expired or near expiry, and returns it.
// It is idempotent when the token is already fresh (a cheap store read, no
// grant). Returns ErrNotLoggedIn when no credential is stored (or an
// expired one carries no refresh token), and ErrReauthRequired when the
// refresh token is revoked/expired.
//
// Callers can use this to warm the session at startup and surface a
// re-login prompt before the first data call rather than mid-request.
//
// Expiry is judged from the login JWT's exp claim. Opaque (non-JWT)
// stored tokens have no client-visible expiry, so they are treated as
// live and never trigger a re-mint — the refresh tier assumes a JWT login
// token (as in the three-tier session model).
func (m *Manager) Refresh(ctx context.Context) (string, error) {
	return m.ensureFreshLogin(ctx)
}

// DeleteCoreToken removes the stored core token and any cached exchanges
// derived from it.
//
// Order matters within the locked region: the keyring delete runs first,
// then the in-memory cache is cleared. If the keyring delete fails the
// cache is left alone — clearing it pre-emptively would create a window
// where the CLI thinks it's logged out (no cache entries) but the keyring
// still hands out the core token to the next process.
//
// DeleteCoreToken is serialised against in-flight refreshes by acquiring
// refreshMu and the cross-process lock before mutating the store. Without
// this, a refresh whose grant is mid-flight could land its persist after
// a concurrent logout and resurrect the deleted session. Lock ordering
// matches refreshLocked: refreshMu first, then processLock. Can block up
// to ~30s under contention and may return a wrapped lock error.
func (m *Manager) DeleteCoreToken() error {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	release, err := m.processLock().Acquire(context.Background())
	if err != nil {
		return fmt.Errorf("delete core token: acquire lock: %w", err)
	}
	defer release()
	return m.deleteCoreTokenLocked()
}

// deleteCoreTokenLocked is the lock-free delete path. Caller MUST hold
// refreshMu and the process lock.
func (m *Manager) deleteCoreTokenLocked() error {
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
//  2. Core (login JWT) expired or near expiry → transparently re-mint it
//     from the stored refresh token (see Refresh). No refresh token →
//     ErrNotLoggedIn; refresh token revoked/expired → ErrReauthRequired;
//     Config.RefreshPath unset → ErrNoRefreshPath.
//  3. m.Issuer() == req.Resource (and req.Audience is empty) → use
//     the core token directly. Single-host deployments hit this path.
//  4. Core token's `aud` claim already includes req.Resource → use
//     the core token directly. Multi-audience tokens skip exchange.
//  5. Otherwise → RFC 8693 token exchange.
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

	core, err := m.ensureFreshLogin(ctx)
	if err != nil {
		return "", err
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
	// Default Audience to the normalized resource URI. RFC 8693 §2.1
	// treats audience and resource as overlapping ways to identify the
	// target service, but some AS implementations (notably zitadel-OIDC-
	// backed servers — entire-core as of 2026-05) require audience to
	// be populated and reject the request with
	// "invalid_target: audience is required" when only resource is
	// present. Applying the default here, AFTER the same-host and
	// JWT-aud shortcuts above, means single-host deployments still
	// return the core token unchanged without setting audience — only
	// requests that actually go to the STS endpoint get the populated
	// audience. Callers that explicitly set Audience to something
	// different are preserved verbatim.
	if resolved.Audience == "" {
		resolved.Audience = normResource
	}
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

// fileLockPath adapts a derived lock path to ProcessLock via
// internal/proclock. The path field lets tests assert the per-identity
// derivation without importing proclock.
type fileLockPath struct {
	path string
	lock *proclock.FileLock
}

func (f *fileLockPath) Acquire(ctx context.Context) (func(), error) {
	return f.lock.Acquire(ctx) //nolint:wrapcheck // proclock already prefixes "proclock:"
}

// processLock returns the test override if set, else the lazily-built
// default file lock. The lock path is keyed on (ClientID, Issuer) — the
// identity that scopes the stored credential — so unrelated CLIs sharing
// an issuer don't serialise against each other.
func (m *Manager) processLock() ProcessLock {
	if p := m.lockOverride.Load(); p != nil {
		return *p
	}
	m.lockOnce.Do(func() {
		dir := m.cfg.LockDir
		if dir == "" {
			if cache, err := os.UserCacheDir(); err == nil {
				dir = filepath.Join(cache, "auth-go")
			} else {
				dir = filepath.Join(os.TempDir(), "auth-go")
			}
		}
		sum := sha256.Sum256([]byte(m.cfg.ClientID + "\x00" + m.cfg.Issuer))
		path := filepath.Join(dir, hex.EncodeToString(sum[:])+".lock")
		m.defaultLock = &fileLockPath{path: path, lock: proclock.New(path)}
	})
	return m.defaultLock
}

// runRefresh dispatches to the test override (if set) else a freshly built
// refresh.Client pointing at Issuer + RefreshPath. client_id is sent on
// both surfaces (Basic auth via the typed field, form body via Extra),
// matching runExchange — see sts.ExchangeRequest.ClientID for the why.
func (m *Manager) runRefresh(ctx context.Context, refreshToken string) (*tokens.TokenSet, error) {
	req := refresh.Request{
		RefreshToken: refreshToken,
		ClientID:     m.cfg.ClientID,
		Extra:        url.Values{"client_id": {m.cfg.ClientID}},
	}
	if p := m.refreshOverride.Load(); p != nil {
		return (*p)(ctx, req)
	}
	if strings.TrimSpace(m.cfg.RefreshPath) == "" {
		return nil, ErrNoRefreshPath
	}
	client := &refresh.Client{
		Transport:         m.cfg.Transport,
		BaseURL:           m.cfg.Issuer,
		Path:              m.cfg.RefreshPath,
		UserAgent:         m.cfg.UserAgent,
		AllowInsecureHTTP: m.cfg.AllowInsecureHTTP,
	}
	return client.Refresh(ctx, req) //nolint:wrapcheck // refresh.Refresh already prefixes "refresh token:"
}

// loadTokenSet reads the full stored TokenSet for the configured issuer.
// ok=false (with nil error) means no credential is stored; a non-nil error
// is a genuine store failure (never collapsed to "not logged in").
func (m *Manager) loadTokenSet() (set tokens.TokenSet, ok bool, err error) {
	t, err := m.cfg.Store.LoadTokens(m.cfg.Issuer)
	if errors.Is(err, tokenstore.ErrNotFound) {
		return tokens.TokenSet{}, false, nil
	}
	if err != nil {
		return tokens.TokenSet{}, false, fmt.Errorf("load core token: %w", err)
	}
	return t, true, nil
}

// doRefresh runs the refresh_token grant for the currently stored refresh
// token and persists the rotated result. Assumes the caller holds both the
// in-process mutex and the cross-process lock and has already confirmed the
// stored login JWT is expired with a refresh token present.
//
// On invalid_grant it re-reads the store: if the refresh token changed
// (a non-cooperating actor rotated it under us) it retries once with the
// new token; otherwise the family is genuinely dead → ErrReauthRequired.
// Transport and other errors are returned as-is, never as reauth, and
// never delete the stored credential.
func (m *Manager) doRefresh(ctx context.Context) (string, error) {
	set, ok, err := m.loadTokenSet()
	if err != nil {
		return "", err
	}
	if !ok || !set.HasRefresh() {
		return "", ErrNotLoggedIn
	}
	sent := set.RefreshToken

	res, err := m.runRefresh(ctx, sent)
	if err == nil {
		if perr := m.persistRefreshed(set, res); perr != nil {
			return "", perr
		}
		return res.AccessToken, nil
	}
	if !errors.Is(err, refresh.ErrInvalidGrant) {
		return "", err
	}

	// Rotation-race recovery: another actor may have rotated the refresh
	// token between our read and our grant. Re-read; retry once if so.
	cur, ok, rerr := m.loadTokenSet()
	if rerr != nil {
		return "", rerr
	}
	if !ok {
		return "", ErrNotLoggedIn // credential deleted concurrently (e.g. logout)
	}
	if !cur.HasRefresh() {
		return "", ErrNotLoggedIn // refresh token cleared concurrently
	}
	if cur.RefreshToken != sent {
		// A non-cooperating actor rotated the RT under us; retry once.
		res, err = m.runRefresh(ctx, cur.RefreshToken)
		if err == nil {
			if perr := m.persistRefreshed(cur, res); perr != nil {
				return "", perr
			}
			return res.AccessToken, nil
		}
		if !errors.Is(err, refresh.ErrInvalidGrant) {
			return "", err
		}
	}
	return "", ErrReauthRequired
}

// persistRefreshed merges the grant response onto the prior set and saves
// it. A non-rotating server (empty refresh_token / scope in the response)
// must not wipe a still-valid refresh token, so empty fields fall back to
// the prior values. The new login JWT and ExpiresAt always replace.
// SaveCoreToken clears the in-process exchange cache as a side effect, so
// the next Token() re-exchanges against the new login JWT.
func (m *Manager) persistRefreshed(prev tokens.TokenSet, res *tokens.TokenSet) error {
	merged := *res
	if merged.RefreshToken == "" {
		merged.RefreshToken = prev.RefreshToken
	}
	if merged.Scope == "" {
		merged.Scope = prev.Scope
	}
	if merged.TokenType == "" {
		merged.TokenType = prev.TokenType
	}
	// saveCoreTokenLocked (NOT SaveCoreToken) — persistRefreshed runs from
	// inside refreshLocked, which already holds refreshMu + processLock.
	// Re-entering them here would self-deadlock.
	if err := m.saveCoreTokenLocked(merged); err != nil {
		return fmt.Errorf("refresh: persist: %w", err)
	}
	return nil
}

// ensureFreshLogin returns a usable login JWT, transparently re-minting an
// expired one from the stored refresh token. The fast path takes no locks:
// a still-fresh token (the common case) returns immediately. ErrNotLoggedIn
// when no credential is stored or an expired one has no refresh token;
// ErrReauthRequired when the refresh token is revoked/expired.
// The fast path intentionally mirrors freshOrProceed's checks to avoid
// taking refreshMu on the common case of a still-fresh token; keep the two
// in sync if you add an early-exit condition.
func (m *Manager) ensureFreshLogin(ctx context.Context) (string, error) {
	set, ok, err := m.loadTokenSet()
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrNotLoggedIn
	}
	// A usable token must be non-empty as well as unexpired. A BYO Store
	// that returns a TokenSet with an empty AccessToken (without
	// ErrNotFound) must not yield an empty bearer — coreTokenExpired("")
	// reports not-expired (parse failure), so guard the empty case here.
	if set.AccessToken != "" && !coreTokenExpired(set.AccessToken, m.now()) {
		return set.AccessToken, nil
	}
	if !set.HasRefresh() {
		return "", ErrNotLoggedIn
	}
	return m.refreshLocked(ctx)
}

// refreshLocked performs the serialize-and-double-check re-mint: the
// in-process mutex coalesces goroutines, the cross-process lock coalesces
// processes, and a store re-read after each gate lets a late waiter return
// the token a peer just minted instead of re-minting.
func (m *Manager) refreshLocked(ctx context.Context) (string, error) {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	if tok, done, err := m.freshOrProceed(); done {
		return tok, err
	}

	release, err := m.processLock().Acquire(ctx)
	if err != nil {
		return "", fmt.Errorf("refresh: acquire lock: %w", err)
	}
	defer release()

	if tok, done, err := m.freshOrProceed(); done {
		return tok, err
	}

	return m.doRefresh(ctx)
}

// freshOrProceed re-reads the store and reports whether the caller has a
// terminal result. done=true means return (tok, err) directly — the token
// is fresh now, no credential exists, or an expired token has no refresh
// token. done=false means "still expired with a refresh token — proceed to
// the re-mint".
func (m *Manager) freshOrProceed() (string, bool, error) {
	set, ok, err := m.loadTokenSet()
	if err != nil {
		return "", true, err
	}
	if !ok {
		return "", true, ErrNotLoggedIn
	}
	if set.AccessToken != "" && !coreTokenExpired(set.AccessToken, m.now()) {
		return set.AccessToken, true, nil
	}
	if !set.HasRefresh() {
		return "", true, ErrNotLoggedIn
	}
	return "", false, nil
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
		// Public-client identification per RFC 6749 §3.2.1 (public
		// clients SHOULD include client_id on requests; we go further
		// and ALWAYS include it). Sent on both surfaces simultaneously:
		//   - ClientID populates HTTP Basic Auth — required by servers
		//     that read credentials only from the Basic header on the
		//     token-exchange grant (zitadel-based servers as of
		//     2026-05 are a known example: pkg/op/token_exchange.go
		//     reads only from r.BasicAuth()).
		//   - Extra["client_id"] populates the form body — required by
		//     servers that read credentials from the form, plus it's
		//     the §2.3.1 form for confidential clients.
		// DO NOT delete either line independently. The two surfaces
		// target different server implementations; the test server
		// validates both, so passing tests do not prove production
		// safety against arbitrary auth servers. m.cfg.ClientID is
		// non-empty by Config.validate, so the resulting request has
		// at least one credential surface populated.
		ClientID: m.cfg.ClientID,
		Extra:    url.Values{"client_id": {m.cfg.ClientID}},
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
