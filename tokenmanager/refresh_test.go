package tokenmanager

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/entireio/auth-go/refresh"
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
