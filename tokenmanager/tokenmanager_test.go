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
		{"missing STSPath", Config{Issuer: "https://x", ClientID: "x", Store: newMemStore()}},
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
