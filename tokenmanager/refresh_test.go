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
	"github.com/entireio/auth-go/tokenstore"
)

// TestDeleteCoreToken_SerializesWithInFlightRefresh pins the lock invariant
// added to defend against post-logout session resurrection: a concurrent
// DeleteCoreToken must block until an in-flight refresh has released the
// refresh+process lock, then the delete wins and the store is empty.
//
// Without the coordination, the refresh's persist would race the logout
// and write the rotated credentials back over the deleted entry.
func TestDeleteCoreToken_SerializesWithInFlightRefresh(t *testing.T) {
	t.Parallel()
	store := newSyncStore()
	store.inner.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})
	SetProcessLockForTest(t, m, &recordingLock{})

	grantStarted := make(chan struct{})
	releaseGrant := make(chan struct{})
	fresh := freshJWT(t)
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		close(grantStarted)
		<-releaseGrant
		return &tokens.TokenSet{AccessToken: fresh, RefreshToken: "rt-2"}, nil
	})

	// Start the refresh; it will block in the fake grant fn while holding
	// refreshMu + processLock.
	refreshErr := make(chan error, 1)
	go func() {
		_, err := m.ensureFreshLogin(context.Background())
		refreshErr <- err
	}()
	<-grantStarted

	// Concurrent DeleteCoreToken — must block on refreshMu.
	deleteErr := make(chan error, 1)
	go func() { deleteErr <- m.DeleteCoreToken() }()

	select {
	case <-deleteErr:
		t.Fatal("DeleteCoreToken returned while refresh held the lock; coordination not honored")
	case <-time.After(75 * time.Millisecond):
		// Expected: blocked behind refreshMu.
	}

	// Let the refresh complete; it persists, releases the locks, the
	// pending DeleteCoreToken then runs and wipes the entry.
	close(releaseGrant)
	if err := <-refreshErr; err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := <-deleteErr; err != nil {
		t.Fatalf("DeleteCoreToken: %v", err)
	}

	store.mu.Lock()
	_, present := store.inner.data[testIssuer]
	store.mu.Unlock()
	if present {
		t.Fatal("store entry present after logout; refresh resurrected the credential")
	}
}

// TestSaveCoreToken_SerializesWithInFlightRefresh pins the same invariant
// for re-login: a concurrent SaveCoreToken(otherUser) must block until the
// refresh releases the locks, then the new login wins (the refresh's
// rotated old-user credentials must not overwrite it).
func TestSaveCoreToken_SerializesWithInFlightRefresh(t *testing.T) {
	t.Parallel()
	store := newSyncStore()
	store.inner.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-old"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})
	SetProcessLockForTest(t, m, &recordingLock{})

	grantStarted := make(chan struct{})
	releaseGrant := make(chan struct{})
	oldRefreshed := freshJWT(t)
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		close(grantStarted)
		<-releaseGrant
		return &tokens.TokenSet{AccessToken: oldRefreshed, RefreshToken: "rt-old-rotated"}, nil
	})

	refreshErr := make(chan error, 1)
	go func() {
		_, err := m.ensureFreshLogin(context.Background())
		refreshErr <- err
	}()
	<-grantStarted

	// Concurrent re-login as a different account.
	newUserToken := tokens.TokenSet{AccessToken: "new-user-jwt", RefreshToken: "rt-new"}
	saveErr := make(chan error, 1)
	go func() { saveErr <- m.SaveCoreToken(newUserToken) }()

	select {
	case <-saveErr:
		t.Fatal("SaveCoreToken returned while refresh held the lock; coordination not honored")
	case <-time.After(75 * time.Millisecond):
		// Expected: blocked.
	}

	close(releaseGrant)
	if err := <-refreshErr; err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := <-saveErr; err != nil {
		t.Fatalf("SaveCoreToken: %v", err)
	}

	store.mu.Lock()
	got := store.inner.data[testIssuer]
	store.mu.Unlock()
	if got.AccessToken != newUserToken.AccessToken || got.RefreshToken != newUserToken.RefreshToken {
		t.Fatalf("store = %+v, want new-user credentials (refresh must not have overwritten)", got)
	}
}

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

func (l *recordingLock) counts() (acquired, released int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.acquired, l.released
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

// TestForceRefresh_ReMintsLocallyLiveToken pins the reason ForceRefresh
// exists: the server rejected a token whose exp hasn't passed locally
// (signing-key rotation, revocation ahead of expiry). Refresh's fast path
// returns the same rejected token; ForceRefresh must run the grant.
func TestForceRefresh_ReMintsLocallyLiveToken(t *testing.T) {
	t.Parallel()
	rejected := freshJWT(t) // locally live, server-side dead
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: rejected, RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	grants := 0
	reminted := makeJWTWithExp(t, time.Date(2098, 1, 1, 0, 0, 0, 0, time.UTC), nil)
	SetRefreshForTest(t, m, func(_ context.Context, req refresh.Request) (*tokens.TokenSet, error) {
		grants++
		if req.RefreshToken != "rt-1" {
			t.Errorf("grant used RT %q, want rt-1", req.RefreshToken)
		}
		return &tokens.TokenSet{AccessToken: reminted, RefreshToken: "rt-2"}, nil
	})

	// Refresh sees a locally-live token and (correctly, for its contract)
	// returns it without a grant — this is exactly the reactive-401 gap.
	if got, err := m.Refresh(context.Background()); err != nil || got != rejected {
		t.Fatalf("Refresh = (%q, %v), want the stored token / nil", got, err)
	}
	if grants != 0 {
		t.Fatalf("grants after Refresh = %d, want 0", grants)
	}

	got, err := m.ForceRefresh(context.Background(), rejected)
	if err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}
	if got != reminted || grants != 1 {
		t.Fatalf("ForceRefresh = %q after %d grants, want re-minted token after 1", got, grants)
	}
	if saved := store.data[testIssuer]; saved.AccessToken != reminted || saved.RefreshToken != "rt-2" {
		t.Fatalf("persisted %q / %q, want reminted / rt-2", saved.AccessToken, saved.RefreshToken)
	}
}

// TestForceRefresh_PeerAlreadyReMintedSkipsGrant pins the anti-stampede
// property: if the store already holds a different, locally-live token by the
// time the locks are acquired, a cooperating peer re-minted first and
// ForceRefresh returns that token without burning another rotation.
func TestForceRefresh_PeerAlreadyReMintedSkipsGrant(t *testing.T) {
	t.Parallel()
	rejected := freshJWT(t)
	peerMinted := makeJWTWithExp(t, time.Date(2098, 1, 1, 0, 0, 0, 0, time.UTC), nil)
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: peerMinted, RefreshToken: "rt-2"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		t.Fatal("grant must not run when a peer already re-minted")
		return nil, errors.New("unreachable")
	})

	got, err := m.ForceRefresh(context.Background(), rejected)
	if err != nil || got != peerMinted {
		t.Fatalf("ForceRefresh = (%q, %v), want peer-minted token / nil", got, err)
	}
}

// TestForceRefresh_ExpiredPeerTokenStillGrants pins the peer-check guard:
// a stored token that differs from staleToken but is locally expired is not
// good enough — returning it would just earn another 401, so the grant runs.
func TestForceRefresh_ExpiredPeerTokenStillGrants(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	fresh := freshJWT(t)
	grants := 0
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		grants++
		return &tokens.TokenSet{AccessToken: fresh, RefreshToken: "rt-2"}, nil
	})

	got, err := m.ForceRefresh(context.Background(), "some-other-rejected-token")
	if err != nil || got != fresh {
		t.Fatalf("ForceRefresh = (%q, %v), want re-minted token / nil", got, err)
	}
	if grants != 1 {
		t.Fatalf("grants = %d, want 1 (expired store token must not satisfy the peer check)", grants)
	}
}

// TestForceRefresh_EmptyStaleTokenAlwaysGrants pins the documented ""
// semantics: no comparator means no peer check — an unconditional forced
// re-mint even when the stored token is locally live.
func TestForceRefresh_EmptyStaleTokenAlwaysGrants(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: freshJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	reminted := makeJWTWithExp(t, time.Date(2098, 1, 1, 0, 0, 0, 0, time.UTC), nil)
	grants := 0
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		grants++
		return &tokens.TokenSet{AccessToken: reminted, RefreshToken: "rt-2"}, nil
	})

	got, err := m.ForceRefresh(context.Background(), "")
	if err != nil || got != reminted {
		t.Fatalf("ForceRefresh = (%q, %v), want re-minted token / nil", got, err)
	}
	if grants != 1 {
		t.Fatalf("grants = %d, want 1 (empty staleToken forces the grant)", grants)
	}
}

// TestForceRefresh_TerminalInvalidGrantIsReauth pins sentinel parity with
// Refresh: a genuinely dead refresh token surfaces as ErrReauthRequired.
func TestForceRefresh_TerminalInvalidGrantIsReauth(t *testing.T) {
	t.Parallel()
	rejected := freshJWT(t)
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: rejected, RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		return nil, refresh.ErrInvalidGrant
	})

	if _, err := m.ForceRefresh(context.Background(), rejected); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v, want ErrReauthRequired", err)
	}
}

// TestForceRefresh_NoCredentialIsNotLoggedIn pins sentinel parity for the
// missing-credential case, on both the peer-check and the ""-path.
func TestForceRefresh_NoCredentialIsNotLoggedIn(t *testing.T) {
	t.Parallel()
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: newMemStore()})

	if _, err := m.ForceRefresh(context.Background(), "whatever"); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("err = %v, want ErrNotLoggedIn (peer-check path)", err)
	}
	if _, err := m.ForceRefresh(context.Background(), ""); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("err = %v, want ErrNotLoggedIn (unconditional path)", err)
	}
}

// TestForceRefresh_AcquiresAndReleasesLock pins that the whole operation runs
// under the cross-process lock, acquired and released exactly once.
func TestForceRefresh_AcquiresAndReleasesLock(t *testing.T) {
	t.Parallel()
	rejected := freshJWT(t)
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: rejected, RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	lock := &recordingLock{}
	SetProcessLockForTest(t, m, lock)
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		// The grant runs while the lock is held.
		if a, r := lock.counts(); a != 1 || r != 0 {
			t.Errorf("mid-grant lock acquired=%d released=%d, want 1/0", a, r)
		}
		return &tokens.TokenSet{AccessToken: makeJWTWithExp(t, time.Date(2098, 1, 1, 0, 0, 0, 0, time.UTC), nil), RefreshToken: "rt-2"}, nil
	})

	if _, err := m.ForceRefresh(context.Background(), rejected); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}
	if a, r := lock.counts(); a != 1 || r != 1 {
		t.Fatalf("lock acquired=%d released=%d, want 1/1", a, r)
	}
}

// errAcquireLock is a ProcessLock whose Acquire always fails, exercising
// refreshLocked's lock-acquisition error path.
type errAcquireLock struct{ err error }

func (l errAcquireLock) Acquire(_ context.Context) (func(), error) { return nil, l.err }

// TestEnsureFreshLogin_LockAcquireFailureSurfaces pins that a cross-process
// lock-acquisition failure surfaces as a wrapped error (not a credential
// sentinel) and does not run the grant.
func TestEnsureFreshLogin_LockAcquireFailureSurfaces(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	SetProcessLockForTest(t, m, errAcquireLock{err: errors.New("flock failed")})
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		t.Fatal("grant must not run when the lock can't be acquired")
		return nil, errors.New("unreachable")
	})

	_, err := m.ensureFreshLogin(context.Background())
	if err == nil || !strings.Contains(err.Error(), "acquire lock") {
		t.Fatalf("err = %v, want wrapped acquire-lock error", err)
	}
	if errors.Is(err, ErrReauthRequired) || errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("err = %v, must not be a credential sentinel", err)
	}
	if !strings.Contains(err.Error(), "flock failed") {
		t.Fatalf("err = %v, want underlying lock error surfaced", err)
	}
}

// TestDoRefresh_PersistFailureSurfaces pins that a keyring write failure
// after a successful grant surfaces (rather than returning the new token as
// if the rotated refresh token had been saved). The failure is distinguishable
// as ErrPersistFailed and still carries the underlying store error.
func TestDoRefresh_PersistFailureSurfaces(t *testing.T) {
	t.Parallel()
	store := &erroringStore{inner: newMemStore(), saveErr: errors.New("keyring locked")}
	store.inner.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})
	SetSleepForTest(t, m, func(context.Context, time.Duration) error { return nil }) // don't actually back off

	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		return &tokens.TokenSet{AccessToken: freshJWT(t), RefreshToken: "rt-2"}, nil
	})

	tok, err := m.doRefresh(context.Background())
	if !errors.Is(err, ErrPersistFailed) {
		t.Fatalf("err = %v, want wrapped ErrPersistFailed", err)
	}
	if !strings.Contains(err.Error(), "keyring locked") {
		t.Fatalf("err = %v, want underlying store error surfaced", err)
	}
	if tok != "" {
		t.Fatalf("tok = %q, want empty (must not hand back a token on a doomed session)", tok)
	}
}

// flakyStore fails its first failSaves SaveTokens calls, then behaves
// normally. It counts save/load calls and guards all state with a mutex so
// the retry/lock tests stay race-clean. Seed via data before use.
type flakyStore struct {
	mu        sync.Mutex
	data      map[string]tokens.TokenSet
	failSaves int
	saveCalls int
	loadCalls int
}

func newFlakyStore(failSaves int) *flakyStore {
	return &flakyStore{data: map[string]tokens.TokenSet{}, failSaves: failSaves}
}

func (s *flakyStore) SaveTokens(profile string, t tokens.TokenSet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveCalls++
	if s.saveCalls <= s.failSaves {
		return errors.New("keyring locked")
	}
	s.data[profile] = t
	return nil
}

func (s *flakyStore) LoadTokens(profile string) (tokens.TokenSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadCalls++
	t, ok := s.data[profile]
	if !ok {
		return tokens.TokenSet{}, tokenstore.ErrNotFound
	}
	return t, nil
}

func (s *flakyStore) DeleteTokens(profile string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, profile)
	return nil
}

func (s *flakyStore) get(profile string) tokens.TokenSet {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[profile]
}

func (s *flakyStore) saves() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveCalls
}

// TestDoRefresh_PersistRetriesThenSucceeds pins that a transient keyring
// failure is ridden out: the persist fails persistMaxAttempts-1 times then
// succeeds, the fresh token is returned, and the store ends up holding the
// rotated pair.
func TestDoRefresh_PersistRetriesThenSucceeds(t *testing.T) {
	t.Parallel()
	store := newFlakyStore(persistMaxAttempts - 1) // fail all but the last
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	var sleeps int
	SetSleepForTest(t, m, func(context.Context, time.Duration) error { sleeps++; return nil })

	fresh := freshJWT(t)
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		return &tokens.TokenSet{AccessToken: fresh, RefreshToken: "rt-2"}, nil
	})

	got, err := m.doRefresh(context.Background())
	if err != nil {
		t.Fatalf("doRefresh: %v", err)
	}
	if got != fresh {
		t.Fatalf("returned %q, want fresh login JWT", got)
	}
	if saved := store.get(testIssuer); saved.AccessToken != fresh || saved.RefreshToken != "rt-2" {
		t.Fatalf("persisted %q / %q, want fresh / rt-2", saved.AccessToken, saved.RefreshToken)
	}
	if store.saves() != persistMaxAttempts {
		t.Fatalf("save attempts = %d, want %d", store.saves(), persistMaxAttempts)
	}
	if sleeps != persistMaxAttempts-1 {
		t.Fatalf("backoff sleeps = %d, want %d", sleeps, persistMaxAttempts-1)
	}
}

// TestDoRefresh_PersistExhaustedReturnsSentinel pins that when every persist
// attempt fails, doRefresh returns ErrPersistFailed with a re-login hint and
// no token, and that it tried exactly persistMaxAttempts times.
func TestDoRefresh_PersistExhaustedReturnsSentinel(t *testing.T) {
	t.Parallel()
	store := newFlakyStore(persistMaxAttempts + 5) // always fail
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})
	SetSleepForTest(t, m, func(context.Context, time.Duration) error { return nil })

	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		return &tokens.TokenSet{AccessToken: freshJWT(t), RefreshToken: "rt-2"}, nil
	})

	tok, err := m.doRefresh(context.Background())
	if !errors.Is(err, ErrPersistFailed) {
		t.Fatalf("err = %v, want wrapped ErrPersistFailed", err)
	}
	if !strings.Contains(err.Error(), "re-login") {
		t.Fatalf("err = %v, want the re-login hint in the message", err)
	}
	if tok != "" {
		t.Fatalf("tok = %q, want empty (rotation consumed server-side, don't hand back a token)", tok)
	}
	if store.saves() != persistMaxAttempts {
		t.Fatalf("save attempts = %d, want %d", store.saves(), persistMaxAttempts)
	}
}

// TestDoRefresh_PersistCancelledMidBackoffStillMakesFinalAttempt pins the
// cancellation wrinkle: the grant already consumed the rotation server-side,
// so ctx cancellation during the backoff must not abandon the persist — one
// final immediate save attempt runs, and when it succeeds the token is
// returned and the store holds the rotated pair.
func TestDoRefresh_PersistCancelledMidBackoffStillMakesFinalAttempt(t *testing.T) {
	t.Parallel()
	store := newFlakyStore(1) // first save fails; the final attempt succeeds
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sleeps int
	SetSleepForTest(t, m, func(ctx context.Context, _ time.Duration) error {
		sleeps++
		cancel() // caller gives up mid-backoff
		return ctx.Err()
	})

	fresh := freshJWT(t)
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		return &tokens.TokenSet{AccessToken: fresh, RefreshToken: "rt-2"}, nil
	})

	got, err := m.doRefresh(ctx)
	if err != nil {
		t.Fatalf("doRefresh: %v", err)
	}
	if got != fresh {
		t.Fatalf("returned %q, want fresh login JWT", got)
	}
	if saved := store.get(testIssuer); saved.AccessToken != fresh || saved.RefreshToken != "rt-2" {
		t.Fatalf("persisted %q / %q, want fresh / rt-2", saved.AccessToken, saved.RefreshToken)
	}
	if store.saves() != 2 {
		t.Fatalf("save attempts = %d, want 2 (initial failure + final immediate attempt)", store.saves())
	}
	if sleeps != 1 {
		t.Fatalf("backoff sleeps = %d, want 1 (cancellation short-circuits the rest)", sleeps)
	}
}

// TestDoRefresh_PersistCancelledMidBackoffFinalAttemptFails pins the error
// shape when the final cancellation-path attempt also fails: the result wraps
// ErrPersistFailed, the underlying store error, AND ctx.Err(), with no token.
func TestDoRefresh_PersistCancelledMidBackoffFinalAttemptFails(t *testing.T) {
	t.Parallel()
	store := newFlakyStore(persistMaxAttempts + 5) // always fail
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	SetSleepForTest(t, m, func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	})

	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		return &tokens.TokenSet{AccessToken: freshJWT(t), RefreshToken: "rt-2"}, nil
	})

	tok, err := m.doRefresh(ctx)
	if !errors.Is(err, ErrPersistFailed) {
		t.Fatalf("err = %v, want wrapped ErrPersistFailed", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want ctx.Err() wrapped so callers see why the retries stopped", err)
	}
	if !strings.Contains(err.Error(), "keyring locked") {
		t.Fatalf("err = %v, want underlying store error surfaced", err)
	}
	if tok != "" {
		t.Fatalf("tok = %q, want empty (must not hand back a token on a doomed session)", tok)
	}
	if store.saves() != 2 {
		t.Fatalf("save attempts = %d, want 2 (initial failure + final immediate attempt)", store.saves())
	}
}

// TestDoRefresh_PersistRetriesHoldLockContinuously pins that the retry loop
// runs while still holding refreshMu + the process lock: the lock is acquired
// exactly once (not re-acquired per attempt), and a concurrent SaveCoreToken
// (re-login) cannot interleave with the retries — it blocks until the refresh
// finishes. This is what stops a peer reading the stale predecessor token
// mid-retry.
func TestDoRefresh_PersistRetriesHoldLockContinuously(t *testing.T) {
	t.Parallel()
	store := newFlakyStore(1) // fail once, then succeed on the retry
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	lock := &recordingLock{}
	SetProcessLockForTest(t, m, lock)

	// Kick off a concurrent re-login from inside the backoff window — while
	// the refresh still holds refreshMu + the process lock. It must block.
	saveErr := make(chan error, 1)
	saveStarted := make(chan struct{})
	newUser := tokens.TokenSet{AccessToken: "new-user-jwt", RefreshToken: "rt-new"}
	SetSleepForTest(t, m, func(context.Context, time.Duration) error {
		go func() {
			close(saveStarted)
			saveErr <- m.SaveCoreToken(newUser)
		}()
		<-saveStarted
		select {
		case <-saveErr:
			t.Error("SaveCoreToken completed during persist retry; lock not held across retries")
		case <-time.After(50 * time.Millisecond):
			// Expected: blocked on refreshMu until the refresh returns.
		}
		// Mid-retry the process lock is held continuously: acquired exactly
		// once and not yet released (and the blocked re-login hasn't reached
		// Acquire). Re-acquiring per attempt would show acquired>1 / released>0.
		if a, r := lock.counts(); a != 1 || r != 0 {
			t.Errorf("mid-retry lock acquired=%d released=%d, want 1/0 (held continuously)", a, r)
		}
		return nil
	})

	fresh := freshJWT(t)
	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		return &tokens.TokenSet{AccessToken: fresh, RefreshToken: "rt-2"}, nil
	})

	got, err := m.ensureFreshLogin(context.Background())
	if err != nil {
		t.Fatalf("ensureFreshLogin: %v", err)
	}
	if got != fresh {
		t.Fatalf("returned %q, want fresh login JWT", got)
	}
	// The blocked re-login now proceeds and wins (its credentials must not be
	// clobbered by the refresh's rotated old-user token).
	if err := <-saveErr; err != nil {
		t.Fatalf("SaveCoreToken: %v", err)
	}
	if saved := store.get(testIssuer); saved.AccessToken != newUser.AccessToken || saved.RefreshToken != newUser.RefreshToken {
		t.Fatalf("store = %+v, want new-user credentials after the queued re-login", saved)
	}
}

// TestDoRefresh_ConcurrentLogoutDuringRefresh pins that if the credential is
// removed concurrently (e.g. a logout) and the grant then returns
// invalid_grant, doRefresh reports ErrNotLoggedIn (credential gone), not
// ErrReauthRequired (which implies a still-present-but-dead refresh token).
func TestDoRefresh_ConcurrentLogoutDuringRefresh(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.data[testIssuer] = tokens.TokenSet{AccessToken: expiredJWT(t), RefreshToken: "rt-1"}
	m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

	SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
		delete(store.data, testIssuer) // simulate concurrent logout
		return nil, refresh.ErrInvalidGrant
	})

	_, err := m.doRefresh(context.Background())
	if !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("err = %v, want ErrNotLoggedIn (creds deleted concurrently)", err)
	}
}

// TestEnsureFreshLogin_EmptyAccessTokenNeverReturnedAsBearer pins that a
// BYO Store returning a TokenSet with an empty AccessToken (without
// ErrNotFound) never yields an empty bearer with a nil error. The old
// Token() path had an explicit `core == ""` guard that the ensureFreshLogin
// refactor must preserve.
func TestEnsureFreshLogin_EmptyAccessTokenNeverReturnedAsBearer(t *testing.T) {
	t.Parallel()

	t.Run("no refresh token", func(t *testing.T) {
		t.Parallel()
		store := newMemStore()
		store.data[testIssuer] = tokens.TokenSet{AccessToken: ""} // present but empty, no RT
		m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})

		tok, err := m.ensureFreshLogin(context.Background())
		if !errors.Is(err, ErrNotLoggedIn) {
			t.Fatalf("err = %v, want ErrNotLoggedIn", err)
		}
		if tok != "" {
			t.Fatalf("tok = %q, want empty", tok)
		}
	})

	t.Run("with refresh token re-mints", func(t *testing.T) {
		t.Parallel()
		store := newMemStore()
		store.data[testIssuer] = tokens.TokenSet{AccessToken: "", RefreshToken: "rt-1"}
		m, _ := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/p", Store: store})
		SetProcessLockForTest(t, m, &recordingLock{})

		fresh := freshJWT(t)
		SetRefreshForTest(t, m, func(_ context.Context, _ refresh.Request) (*tokens.TokenSet, error) {
			return &tokens.TokenSet{AccessToken: fresh, RefreshToken: "rt-2"}, nil
		})

		tok, err := m.ensureFreshLogin(context.Background())
		if err != nil || tok != fresh {
			t.Fatalf("ensureFreshLogin = (%q, %v), want fresh / nil", tok, err)
		}
	})
}
