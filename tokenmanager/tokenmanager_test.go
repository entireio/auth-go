package tokenmanager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/entireio/cli/auth/sts"
	"github.com/entireio/cli/auth/tokens"
	"github.com/entireio/cli/auth/tokenstore"
)

// memStore is an in-memory tokenstore.Store for tests. Avoids pulling
// the keyring backend into tokenmanager's test surface.
type memStore struct {
	data map[string]tokens.TokenSet
}

func newMemStore() *memStore { return &memStore{data: map[string]tokens.TokenSet{}} }

func (s *memStore) SaveTokens(profile string, t tokens.TokenSet) error {
	s.data[profile] = t
	return nil
}

func (s *memStore) LoadTokens(profile string) (tokens.TokenSet, error) {
	t, ok := s.data[profile]
	if !ok {
		return tokens.TokenSet{}, tokenstore.ErrNotFound
	}
	return t, nil
}

func (s *memStore) DeleteTokens(profile string) error {
	delete(s.data, profile)
	return nil
}

const (
	testIssuer   = "https://auth.example.com"
	testResource = "https://api.example.com"
	testClientID = "test-cli"
	testSTSPath  = "/sts/token"
)

func makeJWTWithAudience(t *testing.T, aud []string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, err := json.Marshal(map[string]any{"aud": aud, "sub": "test"})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	sig := base64.RawURLEncoding.EncodeToString([]byte("not-real"))
	return header + "." + body + "." + sig
}

func newTestManager(t *testing.T, store tokenstore.Store, exchange func(context.Context, sts.ExchangeRequest) (*tokens.TokenSet, error)) *Manager {
	t.Helper()
	m, err := New(Config{
		Issuer:   testIssuer,
		ClientID: testClientID,
		STSPath:  testSTSPath,
		Store:    store,
		Exchange: exchange,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestNew_RequiresFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing issuer", Config{ClientID: "x", STSPath: "/p", Store: newMemStore()}},
		{"missing clientID", Config{Issuer: "https://x", STSPath: "/p", Store: newMemStore()}},
		{"missing Store", Config{Issuer: "https://x", ClientID: "x", STSPath: "/p"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// TestNew_AllowsEmptySTSPath documents that single-host configs can
// omit STSPath because the same-host shortcut always wins. The error
// surfaces only if an exchange is actually attempted.
func TestNew_AllowsEmptySTSPath(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{
		Issuer:   testIssuer,
		ClientID: testClientID,
		Store:    newMemStore(),
	}); err != nil {
		t.Fatalf("New: %v", err)
	}
}

// TestExchange_FailsWithoutSTSPath checks that triggering an exchange
// against a manager configured without an STS path returns ErrNoSTSPath
// (rather than POSTing to a bogus URL).
func TestExchange_FailsWithoutSTSPath(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: core}

	m, err := New(Config{
		Issuer:   testIssuer,
		ClientID: testClientID,
		Store:    store,
		// STSPath intentionally empty
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = m.TokenForResource(context.Background(), testResource)
	if !errors.Is(err, ErrNoSTSPath) {
		t.Fatalf("err = %v, want ErrNoSTSPath", err)
	}
}

func TestNew_DefaultRequestedTokenType(t *testing.T) {
	t.Parallel()
	m, err := New(Config{Issuer: testIssuer, ClientID: testClientID, STSPath: testSTSPath, Store: newMemStore()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m.cfg.RequestedTokenType != DefaultRequestedTokenType {
		t.Fatalf("RequestedTokenType default = %q, want %q", m.cfg.RequestedTokenType, DefaultRequestedTokenType)
	}
}

func TestToken_NotLoggedIn(t *testing.T) {
	t.Parallel()
	m := newTestManager(t, newMemStore(), nil)
	_, err := m.TokenForResource(context.Background(), testResource)
	if !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("err = %v, want ErrNotLoggedIn", err)
	}
}

func TestToken_SameHostShortcut(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: "core-tok"}

	m, err := New(Config{
		Issuer: testIssuer, ClientID: testClientID, STSPath: testSTSPath, Store: store,
		Exchange: func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
			t.Fatal("exchange must not run when issuer == resource")
			return nil, errors.New("unreachable")
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := m.TokenForResource(context.Background(), testIssuer)
	if err != nil {
		t.Fatalf("TokenForResource: %v", err)
	}
	if got != "core-tok" {
		t.Fatalf("got %q, want core token verbatim", got)
	}
}

func TestToken_AudienceShortcut(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer, testResource})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: core}

	m, err := New(Config{
		Issuer: testIssuer, ClientID: testClientID, STSPath: testSTSPath, Store: store,
		Exchange: func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
			t.Fatal("exchange must not run when core token's aud already covers resource")
			return nil, errors.New("unreachable")
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := m.TokenForResource(context.Background(), testResource)
	if err != nil {
		t.Fatalf("TokenForResource: %v", err)
	}
	if got != core {
		t.Fatal("expected core token verbatim when aud already matches")
	}
}

func TestToken_ExplicitAudienceBypassesAudienceShortcut(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer, testResource})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: core}

	const requestedAudience = "https://tokens.example.com"
	var got sts.ExchangeRequest
	var calls int
	m := newTestManager(t, store, func(_ context.Context, req sts.ExchangeRequest) (*tokens.TokenSet, error) {
		calls++
		got = req
		return &tokens.TokenSet{AccessToken: "exchanged"}, nil
	})

	token, err := m.Token(context.Background(), TokenRequest{Resource: testResource, Audience: requestedAudience})
	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	if token != "exchanged" || calls != 1 {
		t.Fatalf("Token returned %q with %d exchange calls, want exchanged token from one exchange", token, calls)
	}
	if got.Audience != requestedAudience {
		t.Fatalf("exchange Audience = %q, want %q", got.Audience, requestedAudience)
	}
}

func TestToken_ExchangesAndCaches(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: core}

	var calls int
	var lastReq sts.ExchangeRequest
	m, err := New(Config{
		Issuer: testIssuer, ClientID: testClientID, STSPath: testSTSPath, Store: store,
		Exchange: func(_ context.Context, req sts.ExchangeRequest) (*tokens.TokenSet, error) {
			calls++
			lastReq = req
			return &tokens.TokenSet{AccessToken: "exchanged-1", ExpiresAt: time.Now().Add(10 * time.Minute)}, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	first, err := m.TokenForResource(context.Background(), testResource)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if first != "exchanged-1" {
		t.Fatalf("first = %q", first)
	}
	second, err := m.TokenForResource(context.Background(), testResource)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if second != "exchanged-1" || calls != 1 {
		t.Fatalf("expected cache hit, got calls=%d second=%q", calls, second)
	}

	// Wire shape: default RequestedTokenType, empty audience, client_id.
	if lastReq.RequestedTokenType != DefaultRequestedTokenType {
		t.Errorf("RequestedTokenType = %q", lastReq.RequestedTokenType)
	}
	if lastReq.Audience != "" {
		t.Errorf("Audience = %q, want empty", lastReq.Audience)
	}
	if got := lastReq.Extra.Get("client_id"); got != testClientID {
		t.Errorf("client_id = %q", got)
	}
}

func TestToken_ExchangeIncludesResource(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: core}

	var got sts.ExchangeRequest
	m := newTestManager(t, store, func(_ context.Context, req sts.ExchangeRequest) (*tokens.TokenSet, error) {
		got = req
		return &tokens.TokenSet{AccessToken: "exchanged"}, nil
	})

	if _, err := m.TokenForResource(context.Background(), testResource); err != nil {
		t.Fatalf("TokenForResource: %v", err)
	}

	if got.Resource != testResource {
		t.Fatalf("exchange Resource = %q, want %q", got.Resource, testResource)
	}
}

func TestToken_OverridesAudienceAndType(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: core}

	const customAud = "https://elsewhere.example.com"
	const customType = "urn:ietf:params:oauth:token-type:jwt"
	const customScope = "narrower"

	var got sts.ExchangeRequest
	m := newTestManager(t, store, func(_ context.Context, req sts.ExchangeRequest) (*tokens.TokenSet, error) {
		got = req
		return &tokens.TokenSet{AccessToken: "ok"}, nil
	})

	if _, err := m.Token(context.Background(), TokenRequest{
		Resource:           testResource,
		Audience:           customAud,
		RequestedTokenType: customType,
		Scope:              customScope,
	}); err != nil {
		t.Fatalf("Token: %v", err)
	}

	if got.Audience != customAud {
		t.Errorf("Audience = %q", got.Audience)
	}
	if got.RequestedTokenType != customType {
		t.Errorf("RequestedTokenType = %q", got.RequestedTokenType)
	}
	if got.Scope != customScope {
		t.Errorf("Scope = %q", got.Scope)
	}
}

func TestToken_DifferentAudiencesCacheIndependently(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: core}

	var calls int
	m := newTestManager(t, store, func(_ context.Context, req sts.ExchangeRequest) (*tokens.TokenSet, error) {
		calls++
		return &tokens.TokenSet{AccessToken: "tok-" + req.Audience}, nil
	})

	a, err := m.Token(context.Background(), TokenRequest{Resource: testResource, Audience: "aud-a"})
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := m.Token(context.Background(), TokenRequest{Resource: testResource, Audience: "aud-b"})
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a == b || calls != 2 {
		t.Fatalf("expected separate cache entries, got a=%q b=%q calls=%d", a, b, calls)
	}

	// Repeat A — cache hit.
	if _, err := m.Token(context.Background(), TokenRequest{Resource: testResource, Audience: "aud-a"}); err != nil {
		t.Fatalf("a repeat: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected cache hit on repeat, got %d calls", calls)
	}
}

func TestToken_CacheExpires(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: core}

	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	var calls int
	m, err := New(Config{
		Issuer: testIssuer, ClientID: testClientID, STSPath: testSTSPath, Store: store,
		Now: func() time.Time { return now },
		Exchange: func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
			calls++
			return &tokens.TokenSet{AccessToken: "exchanged", ExpiresAt: now.Add(time.Minute)}, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := m.TokenForResource(context.Background(), testResource); err != nil {
		t.Fatalf("first: %v", err)
	}
	now = now.Add(2 * time.Minute) // past expiry
	if _, err := m.TokenForResource(context.Background(), testResource); err != nil {
		t.Fatalf("second: %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2 (cache must miss after expiry)", calls)
	}
}

func TestToken_RequiresResource(t *testing.T) {
	t.Parallel()
	m := newTestManager(t, newMemStore(), nil)
	_, err := m.Token(context.Background(), TokenRequest{})
	if err == nil {
		t.Fatal("expected error for empty Resource")
	}
}

func TestToken_ExchangeFailureSurfaces(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: core}

	m := newTestManager(t, store, func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
		return nil, errors.New("token exchange: status 400: invalid_target")
	})

	_, err := m.TokenForResource(context.Background(), testResource)
	if err == nil || !strings.Contains(err.Error(), "invalid_target") {
		t.Fatalf("err = %v, want underlying message", err)
	}
}

func TestSaveLookupDeleteCoreToken(t *testing.T) {
	t.Parallel()
	m := newTestManager(t, newMemStore(), nil)

	if got, err := m.LookupCoreToken(); err != nil || got != "" {
		t.Fatalf("initial lookup: got=%q err=%v, want empty/nil", got, err)
	}

	if err := m.SaveCoreToken("new-core"); err != nil {
		t.Fatalf("SaveCoreToken: %v", err)
	}
	got, err := m.LookupCoreToken()
	if err != nil || got != "new-core" {
		t.Fatalf("after save: got=%q err=%v", got, err)
	}

	if err := m.DeleteCoreToken(); err != nil {
		t.Fatalf("DeleteCoreToken: %v", err)
	}
	if got, err := m.LookupCoreToken(); err != nil || got != "" {
		t.Fatalf("after delete: got=%q err=%v", got, err)
	}
}

// TestDeleteCoreToken_ClearsExchangeCache exercises the cache-clear
// side of DeleteCoreToken. Without it, a subsequent Token() call after
// re-login could return a stale exchanged token derived from the old
// core token (currently safe because cacheKey includes the core token,
// but the manager promises a clean slate on delete and tests should
// pin that).
func TestDeleteCoreToken_ClearsExchangeCache(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: core}

	var exchangeCalls int
	m := newTestManager(t, store, func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
		exchangeCalls++
		return &tokens.TokenSet{AccessToken: "exchanged-old", ExpiresAt: time.Now().Add(time.Hour)}, nil
	})

	// Prime the cache.
	if _, err := m.TokenForResource(context.Background(), testResource); err != nil {
		t.Fatalf("prime: %v", err)
	}
	if exchangeCalls != 1 {
		t.Fatalf("prime exchanges = %d, want 1", exchangeCalls)
	}

	if err := m.DeleteCoreToken(); err != nil {
		t.Fatalf("DeleteCoreToken: %v", err)
	}

	// Re-login with a fresh core token; the next Token() must not
	// surface the stale cached entry.
	freshCore := makeJWTWithAudience(t, []string{testIssuer})
	if err := m.SaveCoreToken(freshCore); err != nil {
		t.Fatalf("SaveCoreToken: %v", err)
	}
	if _, err := m.TokenForResource(context.Background(), testResource); err != nil {
		t.Fatalf("post-relogin: %v", err)
	}
	if exchangeCalls != 2 {
		t.Fatalf("post-relogin exchanges = %d, want 2 (cache must miss after delete)", exchangeCalls)
	}
}

// TestDeleteCoreToken_PreservesCacheOnStoreFailure pins the order-of-
// operations: if Store.DeleteTokens fails, the in-memory cache must
// stay populated. Clearing pre-emptively would create a window where
// the CLI thinks it's logged out but the keyring still hands out the
// core token to the next process.
func TestDeleteCoreToken_PreservesCacheOnStoreFailure(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer})
	store := &erroringStore{inner: newMemStore(), deleteErr: errors.New("keyring locked")}
	store.inner.data[testIssuer] = tokens.TokenSet{AccessToken: core}

	var exchangeCalls int
	m := newTestManager(t, store, func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
		exchangeCalls++
		return &tokens.TokenSet{AccessToken: "exchanged-1", ExpiresAt: time.Now().Add(time.Hour)}, nil
	})

	if _, err := m.TokenForResource(context.Background(), testResource); err != nil {
		t.Fatalf("prime: %v", err)
	}
	if exchangeCalls != 1 {
		t.Fatalf("prime exchanges = %d, want 1", exchangeCalls)
	}

	if err := m.DeleteCoreToken(); err == nil {
		t.Fatal("DeleteCoreToken must surface store error")
	}

	// Cache must still hand out the previously exchanged token —
	// no exchange call should fire on the second Token().
	if _, err := m.TokenForResource(context.Background(), testResource); err != nil {
		t.Fatalf("post-failed-delete: %v", err)
	}
	if exchangeCalls != 1 {
		t.Fatalf("post-failed-delete exchanges = %d, want 1 (cache must survive failed delete)", exchangeCalls)
	}
}

// erroringStore wraps memStore and lets a test force a specific store
// op to fail, so we can exercise failure paths without a flaky real
// keyring.
type erroringStore struct {
	inner     *memStore
	loadErr   error
	deleteErr error
}

func (s *erroringStore) SaveTokens(profile string, t tokens.TokenSet) error {
	return s.inner.SaveTokens(profile, t)
}

func (s *erroringStore) LoadTokens(profile string) (tokens.TokenSet, error) {
	if s.loadErr != nil {
		return tokens.TokenSet{}, s.loadErr
	}
	return s.inner.LoadTokens(profile)
}

func (s *erroringStore) DeleteTokens(profile string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.inner.DeleteTokens(profile)
}

// TestToken_CacheKeyDistinguishesRequestedTokenType complements the
// existing audience-independence test: different requested_token_type
// URIs must not shadow each other in the cache.
func TestToken_CacheKeyDistinguishesRequestedTokenType(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: core}

	var calls int
	m := newTestManager(t, store, func(_ context.Context, req sts.ExchangeRequest) (*tokens.TokenSet, error) {
		calls++
		return &tokens.TokenSet{AccessToken: "tok-" + req.RequestedTokenType}, nil
	})

	const otherType = "urn:ietf:params:oauth:token-type:jwt"
	a, err := m.Token(context.Background(), TokenRequest{Resource: testResource})
	if err != nil {
		t.Fatalf("Token(default type): %v", err)
	}
	b, err := m.Token(context.Background(), TokenRequest{Resource: testResource, RequestedTokenType: otherType})
	if err != nil {
		t.Fatalf("Token(otherType): %v", err)
	}
	if a == b || calls != 2 {
		t.Fatalf("expected separate cache entries per requested_token_type, got a=%q b=%q calls=%d", a, b, calls)
	}
}

// TestToken_CacheKeyDistinguishesScope same shape, locks scope into
// the cache key.
func TestToken_CacheKeyDistinguishesScope(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: core}

	var calls int
	m := newTestManager(t, store, func(_ context.Context, req sts.ExchangeRequest) (*tokens.TokenSet, error) {
		calls++
		return &tokens.TokenSet{AccessToken: "tok-" + req.Scope}, nil
	})

	a, err := m.Token(context.Background(), TokenRequest{Resource: testResource, Scope: "scope-a"})
	if err != nil {
		t.Fatalf("Token(scope-a): %v", err)
	}
	b, err := m.Token(context.Background(), TokenRequest{Resource: testResource, Scope: "scope-b"})
	if err != nil {
		t.Fatalf("Token(scope-b): %v", err)
	}
	if a == b || calls != 2 {
		t.Fatalf("expected separate cache entries per scope, got a=%q b=%q calls=%d", a, b, calls)
	}
}

// TestCoreTokenAudienceShortcut_FallsThroughOnMalformedJWT pins a
// security-sensitive contract: a non-JWT (or malformed JWT) core token
// must NOT be silently treated as audience-matching the resource.
// Otherwise a corrupt/forged-but-undecodeable token could bypass the
// exchange path. The "fallthrough to exchange" behaviour is what makes
// signature-skipping ParseClaims safe here.
func TestCoreTokenAudienceShortcut_FallsThroughOnMalformedJWT(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: "not-a-jwt"}

	var exchangeCalls int
	m := newTestManager(t, store, func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
		exchangeCalls++
		return &tokens.TokenSet{AccessToken: "exchanged"}, nil
	})

	got, err := m.TokenForResource(context.Background(), testResource)
	if err != nil {
		t.Fatalf("TokenForResource: %v", err)
	}
	if got == "not-a-jwt" {
		t.Fatal("malformed core token must not be returned verbatim — exchange path must fire")
	}
	if exchangeCalls != 1 {
		t.Fatalf("exchanges = %d, want 1 (exchange must run on unparseable JWT)", exchangeCalls)
	}
}

// TestToken_StoreErrorSurfacesNotAsErrNotLoggedIn pins the contract
// that a non-ErrNotFound store error is *not* collapsed to
// ErrNotLoggedIn. Doing so would mask real keyring failures behind a
// "run entire login" message that does nothing.
func TestToken_StoreErrorSurfacesNotAsErrNotLoggedIn(t *testing.T) {
	t.Parallel()
	store := &erroringStore{inner: newMemStore(), loadErr: errors.New("keyring permission denied")}

	m := newTestManager(t, store, nil)

	_, err := m.TokenForResource(context.Background(), testResource)
	if err == nil {
		t.Fatal("expected store error to surface")
	}
	if errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("err = %v, must NOT be ErrNotLoggedIn (real failures must not be silenced)", err)
	}
	if !strings.Contains(err.Error(), "keyring permission denied") {
		t.Fatalf("err = %v, want underlying store error", err)
	}
}
