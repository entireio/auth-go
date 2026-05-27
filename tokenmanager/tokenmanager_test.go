package tokenmanager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/entireio/auth-go/sts"
	"github.com/entireio/auth-go/tokens"
	"github.com/entireio/auth-go/tokenstore"
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
	testIssuer       = "https://auth.example.com"
	testResource     = "https://api.example.com"
	testClientID     = "test-cli"
	testSTSPath      = "/sts/token"
	testExchangedTok = "exchanged"
)

func makeJWTWithAudience(t *testing.T, aud []string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	payload, err := json.Marshal(map[string]any{"aud": aud, "sub": "test"})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	sig := base64.RawURLEncoding.EncodeToString([]byte("not-real"))
	return header + "." + body + "." + sig
}

// makeJWTWithExp builds an unsigned JWT carrying `exp` (and optionally
// `aud`). The signature segment is junk — tokenmanager never verifies
// it, ParseClaims is documented as unverified.
func makeJWTWithExp(t *testing.T, exp time.Time, aud []string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	claims := map[string]any{"sub": "test", "exp": exp.Unix()}
	if len(aud) > 0 {
		claims["aud"] = aud
	}
	payload, err := json.Marshal(claims)
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
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if exchange != nil {
		SetExchangeForTest(t, m, exchange)
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

// TestNew_RejectsRelativeIssuer pins that an Issuer without scheme or
// host is rejected at construction time. Without this, a misconfigured
// caller's Store profile-key writes go somewhere unpredictable.
func TestNew_RejectsRelativeIssuer(t *testing.T) {
	t.Parallel()
	cases := []string{
		"auth.example.com",     // no scheme
		"https:///oauth/token", // no host
		"://broken",            // invalid scheme syntax
	}
	for _, iss := range cases {
		t.Run(iss, func(t *testing.T) {
			t.Parallel()
			_, err := New(Config{
				Issuer:   iss,
				ClientID: testClientID,
				STSPath:  testSTSPath,
				Store:    newMemStore(),
			})
			if err == nil {
				t.Fatalf("New(Issuer=%q) returned nil error, want absolute-URL error", iss)
			}
		})
	}
}

// TestNew_RejectsNonOriginIssuer pins that Issuer is held to the same
// origin-URL contract as TokenRequest.Resource. The same-host shortcut
// in Token byte-compares a normalised Resource against cfg.Issuer; an
// Issuer that still carries userinfo or a path would silently fail
// that equality and force every "same origin" call through the STS.
func TestNew_RejectsNonOriginIssuer(t *testing.T) {
	t.Parallel()
	cases := []string{
		"https://user:pass@auth.example.com", // userinfo
		"https://auth.example.com/oauth",     // path
		"https://auth.example.com?x=1",       // query
		"https://auth.example.com#frag",      // fragment
		"http://auth.example.com",            // non-loopback http
		"ftp://auth.example.com",             // unsupported scheme
	}
	for _, iss := range cases {
		t.Run(iss, func(t *testing.T) {
			t.Parallel()
			_, err := New(Config{
				Issuer:   iss,
				ClientID: testClientID,
				STSPath:  testSTSPath,
				Store:    newMemStore(),
			})
			if err == nil {
				t.Fatalf("New(Issuer=%q) returned nil error, want origin-URL rejection", iss)
			}
		})
	}
}

// TestNew_NormalizesIssuer pins the keyring/shortcut symmetry. Two
// Managers configured with cosmetically-different but equivalent
// issuers must share state — otherwise SaveCoreToken writes to one
// profile key while Token's same-host shortcut compares against
// another, and a session-save from one Manager doesn't show up in the
// other.
func TestNew_NormalizesIssuer(t *testing.T) {
	t.Parallel()
	store := newMemStore()

	withTrailing, err := New(Config{
		Issuer:   "https://Auth.Example.com/",
		ClientID: testClientID,
		STSPath:  testSTSPath,
		Store:    store,
	})
	if err != nil {
		t.Fatalf("New(trailing slash + uppercase): %v", err)
	}
	if err := withTrailing.SaveCoreToken(tokens.TokenSet{AccessToken: "core-tok"}); err != nil {
		t.Fatalf("SaveCoreToken: %v", err)
	}

	withoutTrailing, err := New(Config{
		Issuer:   "https://auth.example.com",
		ClientID: testClientID,
		STSPath:  testSTSPath,
		Store:    store,
	})
	if err != nil {
		t.Fatalf("New(canonical): %v", err)
	}
	got, err := withoutTrailing.LookupCoreToken()
	if err != nil {
		t.Fatalf("LookupCoreToken: %v", err)
	}
	if got != "core-tok" {
		t.Fatalf("LookupCoreToken from cosmetically-different issuer = %q, want %q", got, "core-tok")
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
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	SetExchangeForTest(t, m, func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
		t.Fatal("exchange must not run when issuer == resource")
		return nil, errors.New("unreachable")
	})

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
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	SetExchangeForTest(t, m, func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
		t.Fatal("exchange must not run when core token's aud already covers resource")
		return nil, errors.New("unreachable")
	})

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
		return &tokens.TokenSet{AccessToken: testExchangedTok}, nil
	})

	token, err := m.Token(context.Background(), TokenRequest{Resource: testResource, Audience: requestedAudience})
	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	if token != testExchangedTok || calls != 1 {
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
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	SetExchangeForTest(t, m, func(_ context.Context, req sts.ExchangeRequest) (*tokens.TokenSet, error) {
		calls++
		lastReq = req
		return &tokens.TokenSet{AccessToken: "exchanged-1", ExpiresAt: time.Now().Add(10 * time.Minute)}, nil
	})

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

	// Wire shape: default RequestedTokenType, default SubjectTokenType,
	// empty audience, client_id on both surfaces (Basic Auth via
	// ClientID field + form via Extra). Both are populated so the
	// request works against zitadel-based servers (Basic-only for
	// token-exchange) and form-reading servers alike — see
	// sts.ExchangeRequest.ClientID doc for the why.
	if lastReq.RequestedTokenType != DefaultRequestedTokenType {
		t.Errorf("RequestedTokenType = %q", lastReq.RequestedTokenType)
	}
	// SubjectTokenType is :access_token rather than :jwt because the
	// core token we exchange is the OAuth access_token returned from
	// the device-code grant, and RFC 8693 §3 reserves :jwt for
	// callers that genuinely want JWT-as-credential semantics. The
	// distinction matters in practice — zitadel-oidc's STS validator
	// only handles :access_token / :refresh_token / :id_token in
	// GetTokenIDAndSubjectFromToken and silently rejects :jwt as
	// "subject_token is invalid", even when the underlying token is
	// a perfectly valid JWS access token.
	if lastReq.SubjectTokenType != sts.SubjectTokenTypeAccessToken {
		t.Errorf("SubjectTokenType = %q, want %q", lastReq.SubjectTokenType, sts.SubjectTokenTypeAccessToken)
	}
	// Audience defaults to the normalized resource URI when the caller
	// didn't set it explicitly. RFC 8693 §2.1 treats audience and
	// resource as overlapping identifiers, but some AS implementations
	// (notably zitadel-OIDC-backed servers such as entire-core) gate
	// token exchange on audience being populated and return
	// "invalid_target: audience is required" when it's missing.
	if lastReq.Audience != testResource {
		t.Errorf("Audience = %q, want %q (defaulted from Resource)", lastReq.Audience, testResource)
	}
	if lastReq.ClientID != testClientID {
		t.Errorf("ClientID = %q, want %q", lastReq.ClientID, testClientID)
	}
	if got := lastReq.Extra.Get("client_id"); got != testClientID {
		t.Errorf("form client_id = %q", got)
	}
}

// TestToken_SubjectTokenTypeOverride pins the override surface on the
// new Config.SubjectTokenType field. Without this, a regression that
// drops the cfg.SubjectTokenType default and hard-codes :access_token
// at the call site still passes the default-path tests but silently
// breaks callers who genuinely want :jwt semantics (RFC 7519 JWT-as-
// credential, not OAuth-issued bearer).
func TestToken_SubjectTokenTypeOverride(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: core}

	var lastReq sts.ExchangeRequest
	m, err := New(Config{
		Issuer:           testIssuer,
		ClientID:         testClientID,
		STSPath:          testSTSPath,
		Store:            store,
		SubjectTokenType: sts.SubjectTokenTypeJWT,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	SetExchangeForTest(t, m, func(_ context.Context, req sts.ExchangeRequest) (*tokens.TokenSet, error) {
		lastReq = req
		return &tokens.TokenSet{AccessToken: testExchangedTok}, nil
	})

	if _, err := m.Token(context.Background(), TokenRequest{Resource: testResource}); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if lastReq.SubjectTokenType != sts.SubjectTokenTypeJWT {
		t.Fatalf("SubjectTokenType = %q, want %q (override)", lastReq.SubjectTokenType, sts.SubjectTokenTypeJWT)
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
		return &tokens.TokenSet{AccessToken: testExchangedTok}, nil
	})

	if _, err := m.TokenForResource(context.Background(), testResource+"/"); err != nil {
		t.Fatalf("TokenForResource: %v", err)
	}

	if got.Resource != testResource {
		t.Fatalf("exchange Resource = %q, want normalised %q", got.Resource, testResource)
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
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	SetNowForTest(t, m, func() time.Time { return now })
	SetExchangeForTest(t, m, func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
		calls++
		return &tokens.TokenSet{AccessToken: testExchangedTok, ExpiresAt: now.Add(time.Minute)}, nil
	})

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

func TestToken_RejectsNonOriginResource(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: core}
	m := newTestManager(t, store, nil)

	cases := []string{
		"api.example.com",
		"http://api.example.com",
		"https://user:pass@api.example.com",
		"https://api.example.com/path",
		"https://api.example.com?x=1",
		"https://api.example.com#frag",
	}
	for _, resource := range cases {
		resource := resource
		t.Run(resource, func(t *testing.T) {
			t.Parallel()
			if _, err := m.TokenForResource(context.Background(), resource); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestToken_ValidatesResourceBeforeLoginLookup(t *testing.T) {
	t.Parallel()
	m := newTestManager(t, newMemStore(), nil)
	_, err := m.TokenForResource(context.Background(), "not-a-url")
	if err == nil || !strings.Contains(err.Error(), "TokenRequest.Resource") {
		t.Fatalf("err = %v, want resource validation error", err)
	}
	if errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("err = %v, should validate resource before login state", err)
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

	if err := m.SaveCoreToken(tokens.TokenSet{AccessToken: "new-core"}); err != nil {
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
	if err := m.SaveCoreToken(tokens.TokenSet{AccessToken: freshCore}); err != nil {
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
	saveErr   error
	deleteErr error
}

func (s *erroringStore) SaveTokens(profile string, t tokens.TokenSet) error {
	if s.saveErr != nil {
		return s.saveErr
	}
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
		return &tokens.TokenSet{AccessToken: testExchangedTok}, nil
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

// TestToken_ExpiredCoreReturnsNotLoggedIn pins the preflight behaviour:
// a core token whose JWT `exp` is in the past surfaces ErrNotLoggedIn
// before the request reaches STS or the resource. Without preflight,
// users see a confusing "invalid_grant" / "401" instead of "run login".
func TestToken_ExpiredCoreReturnsNotLoggedIn(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	expired := makeJWTWithExp(t, now.Add(-time.Hour), nil)

	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expired}

	m, err := New(Config{
		Issuer: testIssuer, ClientID: testClientID, STSPath: testSTSPath, Store: store,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	SetNowForTest(t, m, func() time.Time { return now })
	SetExchangeForTest(t, m, func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
		t.Fatal("exchange must not run for an expired core token")
		return nil, errors.New("unreachable")
	})

	_, err = m.TokenForResource(context.Background(), testResource)
	if !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("err = %v, want ErrNotLoggedIn", err)
	}
}

// TestToken_OpaqueCorePassesPreflight guards the parse-failure branch:
// non-JWT (opaque) access tokens have no client-visible expiry, so
// they must NOT be classified as expired by the preflight check.
func TestToken_OpaqueCorePassesPreflight(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: "opaque-not-a-jwt"}

	m, err := New(Config{
		Issuer: testIssuer, ClientID: testClientID, Store: store,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	SetExchangeForTest(t, m, func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
		t.Fatal("same-host shortcut should win for opaque core token == issuer")
		return nil, errors.New("unreachable")
	})

	got, err := m.TokenForResource(context.Background(), testIssuer)
	if err != nil {
		t.Fatalf("TokenForResource: %v", err)
	}
	if got != "opaque-not-a-jwt" {
		t.Fatalf("got %q, want opaque core verbatim", got)
	}
}

// TestSaveCoreToken_ClearsExchangeCache pins the cache-invalidation
// contract on save: a re-login under a different identity must not
// return the previous user's exchanged tokens, even if a future
// refactor accidentally drops CoreToken from the cache key.
func TestSaveCoreToken_ClearsExchangeCache(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: "user-a-core"}

	calls := 0
	m := newTestManager(t, store, func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
		calls++
		return &tokens.TokenSet{AccessToken: "user-a-exchanged"}, nil
	})

	if _, err := m.TokenForResource(context.Background(), testResource); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls after first Token = %d, want 1", calls)
	}

	if err := m.SaveCoreToken(tokens.TokenSet{AccessToken: "user-b-core"}); err != nil {
		t.Fatalf("SaveCoreToken: %v", err)
	}

	if _, err := m.TokenForResource(context.Background(), testResource); err != nil {
		t.Fatalf("post-save call: %v", err)
	}
	if calls != 2 {
		t.Fatalf("exchange calls after save = %d, want 2 (cache must be cleared on save)", calls)
	}
}

// TestToken_SameHostShortcut_NormalisesURLs guards against a regression
// where a trailing-slash or case difference between Issuer and Resource
// forces a needless STS exchange (or fails outright on single-host
// deployments where STSPath is empty).
func TestToken_SameHostShortcut_NormalisesURLs(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: "core-tok"}

	m, err := New(Config{
		Issuer: testIssuer, ClientID: testClientID, // STSPath intentionally empty
		Store: store,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	SetExchangeForTest(t, m, func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
		t.Fatal("exchange must not run when issuer == resource modulo trailing slash / case")
		return nil, errors.New("unreachable")
	})

	for _, resource := range []string{
		testIssuer + "/", // trailing slash
		strings.ToUpper(testIssuer[:8]) + testIssuer[8:], // uppercase scheme
	} {
		got, err := m.TokenForResource(context.Background(), resource)
		if err != nil {
			t.Fatalf("TokenForResource(%q): %v", resource, err)
		}
		if got != "core-tok" {
			t.Fatalf("TokenForResource(%q) = %q, want core token verbatim", resource, got)
		}
	}
}

// TestToken_CacheCollapsesURLEquivalents pins the cache key being
// computed off the normalised resource: two equivalent forms must
// share a single entry rather than each driving its own STS round-trip.
func TestToken_CacheCollapsesURLEquivalents(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: "core-tok"}

	var calls int
	m := newTestManager(t, store, func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
		calls++
		return &tokens.TokenSet{AccessToken: testExchangedTok}, nil
	})

	first, err := m.TokenForResource(context.Background(), testResource)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := m.TokenForResource(context.Background(), testResource+"/")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if first != testExchangedTok || second != testExchangedTok {
		t.Fatalf("tokens = (%q, %q), want both exchanged", first, second)
	}
	if calls != 1 {
		t.Fatalf("exchange calls = %d, want 1 (trailing-slash variant must hit cache)", calls)
	}
}

// TestSetSeams_ConcurrentReadDuringWrite pins the test-seam fields as
// race-free under the Go memory model. Without atomic.Pointer (or a
// mutex on the read path) a concurrent Token() call hitting m.now() /
// runExchange while SetNowForTest / SetExchangeForTest stores the
// override would race — `go test -race` would catch it. Bugbot
// flagged this in v0.2.0 review.
func TestSetSeams_ConcurrentReadDuringWrite(t *testing.T) {
	t.Parallel()
	core := makeJWTWithAudience(t, []string{testIssuer})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: core}

	m, err := New(Config{
		Issuer: testIssuer, ClientID: testClientID, STSPath: testSTSPath, Store: store,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Seed an exchange override so runExchange's pointer-load path runs.
	SetExchangeForTest(t, m, func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
		return &tokens.TokenSet{AccessToken: "ok", ExpiresAt: time.Now().Add(time.Hour)}, nil
	})

	// Reader goroutines spin on Token; writer goroutine repeatedly
	// replaces the seam. With atomic.Pointer this is a no-op for
	// the race detector; with the previous plain-field implementation
	// it would have tripped.
	stop := make(chan struct{})
	readers := 4
	done := make(chan struct{}, readers)
	for i := 0; i < readers; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = m.TokenForResource(context.Background(), testResource)
				}
			}
		}()
	}

	// 200 writes are enough to give the race detector ample chances
	// to find an unsynchronised read; takes <100ms with atomic.Pointer.
	for i := 0; i < 200; i++ {
		SetNowForTest(t, m, func() time.Time { return time.Unix(int64(i), 0).UTC() })
		SetExchangeForTest(t, m, func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
			return &tokens.TokenSet{AccessToken: "ok", ExpiresAt: time.Now().Add(time.Hour)}, nil
		})
	}
	close(stop)
	for i := 0; i < readers; i++ {
		<-done
	}
}

// TestCachedToken_UsableCeiling exercises cachedToken.usable directly
// to pin the maxCachedTokenLifetime defence. Today no production code
// path stores a cachedToken with zero ExpiresAt (sts.Exchange rejects
// non-positive expires_in at the boundary), so the ceiling is
// defence-in-depth — this test keeps it honest against future code
// paths that might add such a store.
func TestCachedToken_UsableCeiling(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name  string
		entry cachedToken
		want  bool
	}{
		{
			name:  "no expiry, just cached",
			entry: cachedToken{accessToken: "tok", cachedAt: now},
			want:  true,
		},
		{
			name:  "no expiry, 30 min in",
			entry: cachedToken{accessToken: "tok", cachedAt: now.Add(-30 * time.Minute)},
			want:  true,
		},
		{
			name:  "no expiry, one second past 1h ceiling",
			entry: cachedToken{accessToken: "tok", cachedAt: now.Add(-time.Hour - time.Second)},
			want:  false,
		},
		{
			name:  "future expiry, well within skew",
			entry: cachedToken{accessToken: "tok", expiresAt: now.Add(10 * time.Minute)},
			want:  true,
		},
		{
			name:  "expiry in the past",
			entry: cachedToken{accessToken: "tok", expiresAt: now.Add(-time.Minute)},
			want:  false,
		},
		{
			name:  "empty access token is never usable",
			entry: cachedToken{accessToken: "", cachedAt: now, expiresAt: now.Add(time.Hour)},
			want:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.entry.usable(now); got != tc.want {
				t.Fatalf("usable(%v) = %v, want %v", now, got, tc.want)
			}
		})
	}
}

// makeJWTWithExpNbf builds an unsigned JWT carrying exp and (optionally)
// nbf claims. Used to exercise the boundary behaviour of
// coreTokenExpired's two time-window checks. The signature segment is
// junk because tokenmanager never verifies it.
func makeJWTWithExpNbf(t *testing.T, exp, nbf time.Time) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	claims := map[string]any{"sub": "test"}
	if !exp.IsZero() {
		claims["exp"] = exp.Unix()
	}
	if !nbf.IsZero() {
		claims["nbf"] = nbf.Unix()
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	sig := base64.RawURLEncoding.EncodeToString([]byte("not-real"))
	return header + "." + body + "." + sig
}

// TestCoreTokenExpired_AppliesExchangeSkew pins the v0.3.0 finding
// #11 contract: a token whose exp is within exchangeSkew of now is
// treated as expired, not live. Without the skew, a token expiring
// in 1ms passes the preflight, gets presented to the AS, and races
// the wire-side validation past exp — the AS rejects, the CLI
// surfaces a confusing invalid_grant, the user re-logs in. The
// skew sacrifices one fresh login slightly earlier to eliminate
// that race; the cache's exchangeSkew uses the same window so the
// two stay in sync.
func TestCoreTokenExpired_AppliesExchangeSkew(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		exp  time.Time
		want bool
	}{
		{"comfortably future", now.Add(time.Hour), false},
		{"just outside skew", now.Add(exchangeSkew + time.Second), false},
		{"inside skew window", now.Add(exchangeSkew / 2), true},
		{"exactly at exp", now, true},
		{"already past exp", now.Add(-time.Second), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			jwt := makeJWTWithExpNbf(t, tc.exp, time.Time{})
			if got := coreTokenExpired(jwt, now); got != tc.want {
				t.Fatalf("coreTokenExpired(exp=%v, now=%v) = %v, want %v",
					tc.exp.Sub(now), now, got, tc.want)
			}
		})
	}
}

// TestCoreTokenExpired_EnforcesNotBefore pins finding #12: a token
// whose nbf is in the future is unusable per RFC 7519 §4.1.5,
// regardless of exp. Defence in depth — the resource server is also
// expected to reject — but a CLI that presents a not-yet-valid
// token wastes a round-trip and surfaces a confusing rejection.
func TestCoreTokenExpired_EnforcesNotBefore(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	exp := now.Add(time.Hour) // comfortably future so only nbf matters

	cases := []struct {
		name string
		nbf  time.Time
		want bool
	}{
		{"nbf in past (active token)", now.Add(-time.Hour), false},
		{"nbf exactly now", now, false},
		{"nbf in future (not yet valid)", now.Add(time.Minute), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			jwt := makeJWTWithExpNbf(t, exp, tc.nbf)
			if got := coreTokenExpired(jwt, now); got != tc.want {
				t.Fatalf("coreTokenExpired(nbf=%v, now=%v) = %v, want %v",
					tc.nbf.Sub(now), now, got, tc.want)
			}
		})
	}
}

// TestCoreTokenExpired_OpaqueTokensFlowThrough pins the
// parse-failure escape hatch: opaque (non-JWT) access tokens cannot
// be checked for exp/nbf, so coreTokenExpired returns false and lets
// them flow to the rest of the resolution rules. Otherwise opaque
// tokens (which the AS may legitimately issue) would all be
// classified as expired and break every login.
func TestCoreTokenExpired_OpaqueTokensFlowThrough(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	for _, opaque := range []string{
		"opaque-access-token-no-dots",
		"two.segments",
		"",
	} {
		if coreTokenExpired(opaque, now) {
			t.Fatalf("coreTokenExpired(opaque=%q) = true, want false (opaque tokens must flow through)", opaque)
		}
	}
}

// TestSaveCoreToken_RejectsEmptyAccessToken pins finding #15's
// storage-layer guard: an empty AccessToken is rejected at
// SaveCoreToken rather than producing a confusing `Bearer <empty>`
// at the first authenticated request. The previous
// SaveCoreToken(string) signature couldn't make this distinction
// cleanly; the TokenSet form makes the empty-token case explicit.
func TestSaveCoreToken_RejectsEmptyAccessToken(t *testing.T) {
	t.Parallel()

	m := newTestManager(t, newMemStore(), nil)

	err := m.SaveCoreToken(tokens.TokenSet{AccessToken: "", RefreshToken: "rt"})
	if err == nil {
		t.Fatal("SaveCoreToken(empty AccessToken) = nil, want error")
	}
	if !strings.Contains(err.Error(), "AccessToken") {
		t.Fatalf("err = %v, should mention AccessToken", err)
	}

	// And the store should not have been touched.
	got, err := m.LookupCoreToken()
	if err != nil || got != "" {
		t.Fatalf("LookupCoreToken after failed save = (%q, %v), want (\"\", nil)", got, err)
	}
}

// TestSaveCoreToken_PersistsFullTokenSet pins the upgrade: the full
// TokenSet (including RefreshToken, ExpiresAt, Scope) survives the
// round-trip through the store. The previous SaveCoreToken(string)
// signature silently dropped these, which blocked refresh-token
// support and lost the wire-side expiry hint for opaque tokens.
func TestSaveCoreToken_PersistsFullTokenSet(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	m := newTestManager(t, store, nil)

	want := tokens.TokenSet{
		AccessToken:  "core-tok",
		RefreshToken: "refresh-tok",
		TokenType:    "Bearer",
		ExpiresAt:    time.Date(2026, 5, 6, 13, 0, 0, 0, time.UTC),
		Scope:        "cli",
	}
	if err := m.SaveCoreToken(want); err != nil {
		t.Fatalf("SaveCoreToken: %v", err)
	}
	got, err := store.LoadTokens(testIssuer)
	if err != nil {
		t.Fatalf("LoadTokens: %v", err)
	}
	if got != want {
		t.Fatalf("LoadTokens = %+v, want %+v", got, want)
	}
}

// TestMakeCacheKey_HashesCoreToken pins finding #10's privacy
// invariant: the cache map key holds SHA-256 of the bearer, not the
// bearer itself. A long-running embedder accumulates one entry per
// (Resource, Audience, RequestedTokenType, Scope) tuple, and the
// bearer must not be replicated across those entries — memory dumps
// and heap profiles would otherwise leak N copies of the credential.
//
// SHA-256 isn't a one-way function in any security sense (anyone with
// process-memory access already has the bearer), but it does
// eliminate the per-entry replication.
func TestMakeCacheKey_HashesCoreToken(t *testing.T) {
	t.Parallel()

	coreToken := "core-token-must-not-appear-in-cache-key"
	req := TokenRequest{
		Resource:           "https://api.example.com",
		Audience:           "https://api.example.com",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		Scope:              "read",
	}

	key := makeCacheKey(coreToken, req, req.Resource)

	// The field is fixed-size sha256 output, not the raw token.
	if string(key.CoreTokenHash[:]) == coreToken {
		t.Fatal("CoreTokenHash contains the raw token, not a hash")
	}
	// Hashing the same token must produce the same key — otherwise
	// cache hits are impossible.
	again := makeCacheKey(coreToken, req, req.Resource)
	if key != again {
		t.Fatal("makeCacheKey is not deterministic for the same input")
	}
	// And a different core token must produce a different key.
	other := makeCacheKey("a-different-core-token", req, req.Resource)
	if key == other {
		t.Fatal("makeCacheKey collides across different core tokens")
	}
}
