package tokenmanager

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entireio/auth-go/refresh"
	"github.com/entireio/auth-go/sts"
	"github.com/entireio/auth-go/tokens"
)

func TestRunRefresh_NoRefreshPath(t *testing.T) {
	t.Parallel()
	m, err := New(Config{Issuer: testIssuer, ClientID: testClientID, Store: newMemStore()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// No RefreshPath, no override → ErrNoRefreshPath.
	if _, err := m.runRefresh(context.Background(), "rt"); !errors.Is(err, ErrNoRefreshPath) {
		t.Fatalf("err = %v, want ErrNoRefreshPath", err)
	}
}

func TestRunRefresh_OverrideReceivesClientIDOnBothSurfaces(t *testing.T) {
	t.Parallel()
	m, err := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/oauth/token", Store: newMemStore()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var got refresh.Request
	SetRefreshForTest(t, m, func(_ context.Context, req refresh.Request) (*tokens.TokenSet, error) {
		got = req
		return &tokens.TokenSet{AccessToken: "x"}, nil
	})
	if _, err := m.runRefresh(context.Background(), "rt-1"); err != nil {
		t.Fatalf("runRefresh: %v", err)
	}
	if got.RefreshToken != "rt-1" {
		t.Errorf("RefreshToken = %q, want rt-1", got.RefreshToken)
	}
	if got.ClientID != testClientID {
		t.Errorf("ClientID = %q, want %q (Basic-auth surface)", got.ClientID, testClientID)
	}
	if got.Extra.Get("client_id") != testClientID {
		t.Errorf("Extra client_id = %q, want %q (form surface)", got.Extra.Get("client_id"), testClientID)
	}
}

func TestProcessLock_DefaultDerivesPerIdentityPath(t *testing.T) {
	t.Parallel()
	m1, _ := New(Config{Issuer: testIssuer, ClientID: "cli-a", Store: newMemStore()})
	m2, _ := New(Config{Issuer: testIssuer, ClientID: "cli-b", Store: newMemStore()})
	m3, _ := New(Config{Issuer: testIssuer, ClientID: "cli-a", Store: newMemStore()})

	p1 := m1.processLock().(*fileLockPath).path
	p2 := m2.processLock().(*fileLockPath).path
	p3 := m3.processLock().(*fileLockPath).path
	if p1 == p2 {
		t.Fatal("different ClientIDs must derive different lock paths")
	}
	if p1 != p3 {
		t.Fatal("same (ClientID, Issuer) must derive the same lock path")
	}
}

func expiredJWT(t *testing.T) string {
	t.Helper()
	return makeJWTWithExp(t, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), nil)
}

func freshJWT(t *testing.T) string {
	t.Helper()
	return makeJWTWithExp(t, time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), nil)
}

func TestDoRefresh_HappyRotation(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	fresh := freshJWT(t)
	SetRefreshForTest(t, m, func(_ context.Context, req refresh.Request) (*tokens.TokenSet, error) {
		if req.RefreshToken != "rt-1" {
			t.Errorf("grant used RT %q, want rt-1", req.RefreshToken)
		}
		return &tokens.TokenSet{AccessToken: fresh, RefreshToken: "rt-2"}, nil
	})

	got, err := m.doRefresh(context.Background())
	if err != nil {
		t.Fatalf("doRefresh: %v", err)
	}
	if got != fresh {
		t.Fatalf("returned %q, want fresh login JWT", got)
	}
	saved := store.data[testIssuer]
	if saved.AccessToken != fresh || saved.RefreshToken != "rt-2" {
		t.Fatalf("persisted %q / %q, want fresh / rt-2", saved.AccessToken, saved.RefreshToken)
	}
}

func TestDoRefresh_NonRotatingServerRetainsRT(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1", Scope: "cli"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	fresh := freshJWT(t)
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		// Server doesn't rotate: empty refresh_token, empty scope.
		return &tokens.TokenSet{AccessToken: fresh}, nil
	})

	if _, err := m.doRefresh(context.Background()); err != nil {
		t.Fatalf("doRefresh: %v", err)
	}
	saved := store.data[testIssuer]
	if saved.RefreshToken != "rt-1" {
		t.Fatalf("RefreshToken = %q, want retained rt-1", saved.RefreshToken)
	}
	if saved.Scope != "cli" {
		t.Fatalf("Scope = %q, want retained cli", saved.Scope)
	}
}

func TestDoRefresh_RotationRaceRetriesWithNewRT(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	fresh := freshJWT(t)
	calls := 0
	SetRefreshForTest(t, m, func(_ context.Context, req refresh.Request) (*tokens.TokenSet, error) {
		calls++
		if calls == 1 {
			// Simulate another process having rotated the RT in the store
			// just before our grant landed.
			store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-from-other"}
			return nil, refresh.ErrInvalidGrant
		}
		if req.RefreshToken != "rt-from-other" {
			t.Errorf("retry used RT %q, want rt-from-other", req.RefreshToken)
		}
		return &tokens.TokenSet{AccessToken: fresh, RefreshToken: "rt-3"}, nil
	})

	got, err := m.doRefresh(context.Background())
	if err != nil {
		t.Fatalf("doRefresh: %v", err)
	}
	if got != fresh || calls != 2 {
		t.Fatalf("got %q after %d calls, want fresh after 2", got, calls)
	}
}

func TestDoRefresh_TerminalInvalidGrant(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		return nil, refresh.ErrInvalidGrant
	})

	_, err := m.doRefresh(context.Background())
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v, want ErrReauthRequired", err)
	}
	// Creds must NOT be deleted — a transient invalid_grant shouldn't wipe
	// the keyring; the next login overwrites.
	if _, ok := store.data[testIssuer]; !ok {
		t.Fatal("credentials deleted on terminal invalid_grant, want preserved")
	}
}

func TestDoRefresh_NetworkErrorNotReauth(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		return nil, errors.New("connection refused")
	})

	_, err := m.doRefresh(context.Background())
	if errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v, must NOT be ErrReauthRequired for a transport error", err)
	}
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("err = %v, want underlying transport error", err)
	}
}

// TestDoRefresh_RotationRaceRetryTransportErrorNotReauth pins that a
// transport error on the RETRY attempt (after a rotation race) surfaces
// verbatim rather than being misreported as ErrReauthRequired — the same
// contract the first attempt already honours.
func TestDoRefresh_RotationRaceRetryTransportErrorNotReauth(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	calls := 0
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		calls++
		if calls == 1 {
			// Another process rotated the RT, then our grant got invalid_grant.
			store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-from-other"}
			return nil, refresh.ErrInvalidGrant
		}
		// Retry attempt hits a transport failure.
		return nil, errors.New("connection refused")
	})

	_, err := m.doRefresh(context.Background())
	if errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v, must NOT be ErrReauthRequired for a retry transport error", err)
	}
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("err = %v, want underlying transport error from the retry", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2 (one initial + one retry)", calls)
	}
}

// recordingLock is a fake ProcessLock that counts acquire/release. The
// in-process mutex already serialises goroutines, so the fake need not
// enforce real mutual exclusion.
type recordingLock struct {
	mu                 sync.Mutex
	acquired, released int
}

func (l *recordingLock) Acquire(_ context.Context) (func(), error) {
	l.mu.Lock()
	l.acquired++
	l.mu.Unlock()
	return func() {
		l.mu.Lock()
		l.released++
		l.mu.Unlock()
	}, nil
}

// syncStore is a mutex-guarded tokenstore.Store for the concurrency test.
// memStore is a bare map; the coalescing test reads it on the fast path
// while a peer writes it via SaveCoreToken, which would be a concurrent
// map read/write (-race fatal). The production keyring store does its own
// locking; this wrapper gives the test the same guarantee. Seed via the
// inner map BEFORE launching goroutines.
type syncStore struct {
	mu    sync.Mutex
	inner *memStore
}

func newSyncStore() *syncStore { return &syncStore{inner: newMemStore()} }

func (s *syncStore) SaveTokens(p string, t tokens.TokenSet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.SaveTokens(p, t)
}

func (s *syncStore) LoadTokens(p string) (tokens.TokenSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.LoadTokens(p)
}

func (s *syncStore) DeleteTokens(p string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.DeleteTokens(p)
}

func TestEnsureFreshLogin_FreshReturnsWithoutGrant(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	fresh := freshJWT(t)
	store.data[testIssuer] = tokens.TokenSet{AccessToken: fresh, RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		t.Fatal("grant must not run when the login JWT is still fresh")
		return nil, errors.New("unreachable")
	})

	got, err := m.ensureFreshLogin(context.Background())
	if err != nil || got != fresh {
		t.Fatalf("ensureFreshLogin = (%q, %v), want fresh / nil", got, err)
	}
}

func TestEnsureFreshLogin_ExpiredNoRefreshIsNotLoggedIn(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t)} // no refresh token
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	if _, err := m.ensureFreshLogin(context.Background()); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("err = %v, want ErrNotLoggedIn", err)
	}
}

func TestEnsureFreshLogin_NoCredentialIsNotLoggedIn(t *testing.T) {
	t.Parallel()
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: newMemStore()})
	if _, err := m.ensureFreshLogin(context.Background()); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("err = %v, want ErrNotLoggedIn", err)
	}
}

func TestEnsureFreshLogin_AcquiresAndReleasesLock(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	lock := &recordingLock{}
	SetProcessLockForTest(t, m, lock)
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		return &tokens.TokenSet{AccessToken: freshJWT(t), RefreshToken: "rt-2"}, nil
	})

	if _, err := m.ensureFreshLogin(context.Background()); err != nil {
		t.Fatalf("ensureFreshLogin: %v", err)
	}
	if lock.acquired != 1 || lock.released != 1 {
		t.Fatalf("lock acquired=%d released=%d, want 1/1", lock.acquired, lock.released)
	}
}

// TestEnsureFreshLogin_CoalescesConcurrentCallers pins single-flight: many
// goroutines hit an expired login JWT at once, but the double-check after
// each gate means exactly one grant fires; the rest read the freshly
// persisted token.
func TestEnsureFreshLogin_CoalescesConcurrentCallers(t *testing.T) {
	t.Parallel()
	store := newSyncStore()
	store.inner.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	lock := &recordingLock{}
	SetProcessLockForTest(t, m, lock)

	fresh := freshJWT(t)
	var grants atomic.Int32
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		grants.Add(1)
		return &tokens.TokenSet{AccessToken: fresh, RefreshToken: "rt-2"}, nil
	})

	const n = 8
	var wg sync.WaitGroup
	var ready sync.WaitGroup
	ready.Add(n)
	start := make(chan struct{})
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-start // park until all goroutines are live, then race together
			got, err := m.ensureFreshLogin(context.Background())
			if err == nil && got != fresh {
				err = errors.New("got stale token")
			}
			errs <- err
		}()
	}
	ready.Wait() // all goroutines parked at the barrier
	close(start) // release them simultaneously
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent ensureFreshLogin: %v", err)
		}
	}
	if g := grants.Load(); g != 1 {
		t.Fatalf("grants fired = %d, want exactly 1 (single-flight)", g)
	}
	if lock.acquired != 1 {
		t.Fatalf("cross-process lock acquired = %d, want 1 (only one goroutine should reach the gate)", lock.acquired)
	}
}

// TestToken_RefreshesExpiredThenExchanges pins the end-to-end path: an
// expired login JWT is re-minted before the exchange runs, and the exchange
// cache is cleared by the re-mint so a fresh exchange fires against the new
// login JWT.
func TestToken_RefreshesExpiredThenExchanges(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	// Start with a fresh login JWT (aud = issuer only, so testResource
	// needs an exchange) plus a refresh token.
	liveCore := makeJWTWithExp(t, now.Add(time.Hour), []string{testIssuer})
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: liveCore, RefreshToken: "rt-1"}

	m, err := New(Config{Issuer: testIssuer, ClientID: testClientID, STSPath: testSTSPath, RefreshPath: "/p", Store: store})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	SetNowForTest(t, m, func() time.Time { return now })

	var exchanges int
	SetExchangeForTest(t, m, func(_ context.Context, _ sts.ExchangeRequest) (*tokens.TokenSet, error) {
		exchanges++
		return &tokens.TokenSet{AccessToken: "exchanged", ExpiresAt: now.Add(5 * time.Minute)}, nil
	})

	var grants int
	newCore := makeJWTWithExp(t, now.Add(8*time.Hour), []string{testIssuer})
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		grants++
		return &tokens.TokenSet{AccessToken: newCore, RefreshToken: "rt-2"}, nil
	})

	// First call: core live → exchange fires once, cached.
	if _, err := m.TokenForResource(context.Background(), testResource); err != nil {
		t.Fatalf("first: %v", err)
	}
	if exchanges != 1 || grants != 0 {
		t.Fatalf("after first: exchanges=%d grants=%d, want 1/0", exchanges, grants)
	}

	// Advance past the login JWT's exp; the next call must refresh first,
	// which clears the exchange cache, then re-exchange.
	now = now.Add(2 * time.Hour)
	if _, err := m.TokenForResource(context.Background(), testResource); err != nil {
		t.Fatalf("second: %v", err)
	}
	if grants != 1 {
		t.Fatalf("grants = %d, want 1 (refresh on expiry)", grants)
	}
	if exchanges != 2 {
		t.Fatalf("exchanges = %d, want 2 (cache cleared by refresh)", exchanges)
	}
	if store.data[testIssuer].RefreshToken != "rt-2" {
		t.Fatalf("stored RT = %q, want rotated rt-2", store.data[testIssuer].RefreshToken)
	}
}

// TestToken_RefreshExhaustedSurfacesReauth pins that a terminal refresh
// failure surfaces as ErrReauthRequired through Token.
func TestToken_RefreshExhaustedSurfacesReauth(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: makeJWTWithExp(t, now.Add(-time.Hour), nil), RefreshToken: "rt-1"}

	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, STSPath: testSTSPath, RefreshPath: "/p", Store: store})
	SetNowForTest(t, m, func() time.Time { return now })
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		return nil, refresh.ErrInvalidGrant
	})

	if _, err := m.TokenForResource(context.Background(), testResource); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v, want ErrReauthRequired", err)
	}
}

// TestToken_RefreshNeededWithoutPathSurfacesNoRefreshPath pins that the
// missing-config error propagates through Token.
func TestToken_RefreshNeededWithoutPathSurfacesNoRefreshPath(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: makeJWTWithExp(t, now.Add(-time.Hour), nil), RefreshToken: "rt-1"}
	// No RefreshPath, no refresh override.
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, STSPath: testSTSPath, Store: store})
	SetNowForTest(t, m, func() time.Time { return now })

	if _, err := m.TokenForResource(context.Background(), testResource); !errors.Is(err, ErrNoRefreshPath) {
		t.Fatalf("err = %v, want ErrNoRefreshPath", err)
	}
}

func TestRefresh_ExportedIdempotentWhenFresh(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	fresh := freshJWT(t)
	store.data[testIssuer] = tokens.TokenSet{AccessToken: fresh, RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		t.Fatal("Refresh must not grant when token is fresh")
		return nil, errors.New("unreachable")
	})
	got, err := m.Refresh(context.Background())
	if err != nil || got != fresh {
		t.Fatalf("Refresh = (%q, %v), want fresh / nil", got, err)
	}
}

func TestRefresh_ExportedReMintsWhenExpired(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})
	fresh := freshJWT(t)
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		return &tokens.TokenSet{AccessToken: fresh, RefreshToken: "rt-2"}, nil
	})
	got, err := m.Refresh(context.Background())
	if err != nil || got != fresh {
		t.Fatalf("Refresh = (%q, %v), want fresh / nil", got, err)
	}
	if store.data[testIssuer].RefreshToken != "rt-2" {
		t.Fatalf("stored RT = %q, want rotated rt-2", store.data[testIssuer].RefreshToken)
	}
}
