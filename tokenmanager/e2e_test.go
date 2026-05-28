package tokenmanager

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entireio/auth-go/internal/testoauth"
	"github.com/entireio/auth-go/refresh"
	"github.com/entireio/auth-go/tokens"
)

// newE2EManager builds a Manager wired to srv for end-to-end tests.
// store must be non-nil; the caller seeds store.data directly before use.
func newE2EManager(t *testing.T, srv *testoauth.Server, store e2eStore, lockDir string) *Manager {
	t.Helper()
	m, err := New(Config{
		Issuer:            srv.URL(),
		ClientID:          "test-cli",
		STSPath:           "/oauth/token",
		RefreshPath:       "/oauth/token",
		LockDir:           lockDir,
		AllowInsecureHTTP: true,
		Store:             store,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// e2eStore is the tokenstore.Store interface as seen from the e2e tests.
// memStore and syncStore both satisfy it.
type e2eStore interface {
	SaveTokens(string, tokens.TokenSet) error
	LoadTokens(string) (tokens.TokenSet, error)
	DeleteTokens(string) error
}

// TestE2E_RefreshOnExpiredJWTThenExchange pins the full composition:
// expired login JWT → ensureFreshLogin triggers refresh → store updated
// with rotated RT → exchange runs against the new login JWT.
//
// The resource intentionally differs from the family audience so the
// audience shortcut does NOT fire and a real STS exchange is required.
func TestE2E_RefreshOnExpiredJWTThenExchange(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	clock := now
	clockFn := func() time.Time { return clock }

	srv := testoauth.NewServer(t, testoauth.Config{
		Now:         clockFn,
		LoginJWTTTL: time.Hour,
	})

	// Seed with only srv.URL() as audience so the login JWT's aud does NOT
	// cover the resource — the audience shortcut won't fire and a token
	// exchange is required.
	const resource = "https://api.example.com"
	seed := srv.SeedFamily("user-1", []string{srv.URL()})

	store := newMemStore()
	// Seed the store with the login JWT that was minted at `now`.
	// After advancing the clock 2h it will be expired (TTL=1h).
	store.data[srv.URL()] = tokens.TokenSet{
		AccessToken:  seed.LoginJWT,
		RefreshToken: seed.RefreshToken,
	}

	m := newE2EManager(t, srv, store, t.TempDir())
	SetNowForTest(t, m, clockFn)

	// Advance the clock past the login JWT's exp so ensureFreshLogin
	// triggers a refresh.
	clock = clock.Add(2 * time.Hour)

	got, err := m.TokenForResource(context.Background(), resource)
	if err != nil {
		t.Fatalf("TokenForResource: %v", err)
	}
	if got == "" {
		t.Fatal("empty token")
	}
	if srv.RefreshGrantCount() != 1 {
		t.Errorf("RefreshGrantCount = %d, want 1", srv.RefreshGrantCount())
	}
	if srv.ExchangeGrantCount() != 1 {
		t.Errorf("ExchangeGrantCount = %d, want 1", srv.ExchangeGrantCount())
	}
	if store.data[srv.URL()].RefreshToken == seed.RefreshToken {
		t.Error("stored refresh token did not rotate")
	}

	// Verify the returned token is the exchanged token scoped to the requested
	// resource, not the login JWT. A mock bug returning the wrong token would
	// have a different audience and be caught here.
	claims, err := tokens.ParseClaims(got)
	if err != nil {
		t.Fatalf("ParseClaims(got): %v", err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != resource {
		t.Fatalf("Audience = %v, want [%q] (token must be aud-scoped to the requested resource, not the issuer)", claims.Audience, resource)
	}
}

// TestE2E_SilentRefreshAcrossTwoCycles runs two full refresh cycles and
// asserts the second cycle also fires a fresh grant and rotates the RT again.
func TestE2E_SilentRefreshAcrossTwoCycles(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	clock := now
	clockFn := func() time.Time { return clock }

	srv := testoauth.NewServer(t, testoauth.Config{
		Now:         clockFn,
		LoginJWTTTL: time.Hour,
	})

	// Only srv.URL() in audience so the resource triggers an exchange
	// (not bypassed by the audience shortcut).
	const resource = "https://api.example.com"
	seed := srv.SeedFamily("user-2", []string{srv.URL()})

	store := newMemStore()
	store.data[srv.URL()] = tokens.TokenSet{
		AccessToken:  seed.LoginJWT,
		RefreshToken: seed.RefreshToken,
	}

	m := newE2EManager(t, srv, store, t.TempDir())
	SetNowForTest(t, m, clockFn)

	// Cycle 1: advance past TTL, trigger refresh + exchange.
	clock = clock.Add(2 * time.Hour)
	if _, err := m.TokenForResource(context.Background(), resource); err != nil {
		t.Fatalf("cycle 1 TokenForResource: %v", err)
	}
	if srv.RefreshGrantCount() != 1 {
		t.Errorf("after cycle 1: RefreshGrantCount = %d, want 1", srv.RefreshGrantCount())
	}
	if srv.ExchangeGrantCount() != 1 {
		t.Errorf("after cycle 1: ExchangeGrantCount = %d, want 1", srv.ExchangeGrantCount())
	}
	rt1 := store.data[srv.URL()].RefreshToken
	if rt1 == seed.RefreshToken {
		t.Fatal("after cycle 1: stored RT did not rotate")
	}

	// Cycle 2: advance another 2h so the new login JWT (TTL=1h) is expired.
	// The Manager's clock also advances, so the new JWT is expired.
	clock = clock.Add(2 * time.Hour)
	if _, err := m.TokenForResource(context.Background(), resource); err != nil {
		t.Fatalf("cycle 2 TokenForResource: %v", err)
	}
	if srv.RefreshGrantCount() != 2 {
		t.Errorf("after cycle 2: RefreshGrantCount = %d, want 2", srv.RefreshGrantCount())
	}
	if srv.ExchangeGrantCount() != 2 {
		t.Errorf("after cycle 2: ExchangeGrantCount = %d, want 2 (cache invalidated by refresh)", srv.ExchangeGrantCount())
	}
	rt2 := store.data[srv.URL()].RefreshToken
	if rt2 == rt1 {
		t.Fatal("after cycle 2: stored RT did not rotate for the second time")
	}
	if rt2 == seed.RefreshToken {
		t.Fatal("after cycle 2: stored RT reverted to original")
	}
}

// TestE2E_GoroutineCoalescingAgainstRealServer asserts that 8 concurrent
// goroutines racing on an expired JWT drive exactly one refresh grant through
// the real HTTP server (single-flight coalescing).
func TestE2E_GoroutineCoalescingAgainstRealServer(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	clock := now
	clockFn := func() time.Time { return clock }

	srv := testoauth.NewServer(t, testoauth.Config{
		Now:         clockFn,
		LoginJWTTTL: time.Hour,
	})

	const resource = "https://api.example.com"
	seed := srv.SeedFamily("user-3", []string{srv.URL(), resource})

	store := newSyncStore()
	store.inner.data[srv.URL()] = tokens.TokenSet{
		AccessToken:  seed.LoginJWT,
		RefreshToken: seed.RefreshToken,
	}

	m := newE2EManager(t, srv, store, t.TempDir())
	SetNowForTest(t, m, clockFn)

	// Advance past the JWT's TTL so all goroutines see an expired token.
	clock = clock.Add(2 * time.Hour)

	const n = 8
	var wg sync.WaitGroup
	var ready sync.WaitGroup
	ready.Add(n)
	start := make(chan struct{})
	errs := make(chan error, n)
	var emptyCount atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-start
			tok, err := m.TokenForResource(context.Background(), resource)
			if err != nil {
				errs <- err
				return
			}
			if tok == "" {
				emptyCount.Add(1)
			}
			errs <- nil
		}()
	}
	ready.Wait()
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("concurrent TokenForResource: %v", err)
		}
	}
	if emptyCount.Load() > 0 {
		t.Errorf("%d goroutines got empty token", emptyCount.Load())
	}
	if srv.RefreshGrantCount() != 1 {
		t.Errorf("RefreshGrantCount = %d, want 1 (single-flight)", srv.RefreshGrantCount())
	}
}

// TestE2E_RotationReuseDetectionRevokesFamily seeds a family, performs one
// refresh via the Manager (RT1 → RT2), then directly POSTs RT1 to the server.
// The server detects the replay, revokes the family, and returns invalid_grant.
// A subsequent m.Refresh call with RT2 also returns invalid_grant (dead family),
// which the Manager surfaces as ErrReauthRequired. Credentials are NOT deleted.
func TestE2E_RotationReuseDetectionRevokesFamily(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	clock := now
	clockFn := func() time.Time { return clock }

	srv := testoauth.NewServer(t, testoauth.Config{
		Now:         clockFn,
		LoginJWTTTL: time.Hour,
	})

	seed := srv.SeedFamily("user-4", []string{srv.URL()})

	store := newMemStore()
	store.data[srv.URL()] = tokens.TokenSet{
		AccessToken:  seed.LoginJWT,
		RefreshToken: seed.RefreshToken,
	}

	m := newE2EManager(t, srv, store, t.TempDir())
	SetNowForTest(t, m, clockFn)

	// Advance past the original JWT's TTL (1h) so the Manager refreshes.
	// After refresh, the server mints a new JWT at clock=now+2h with exp=now+3h.
	clock = clock.Add(2 * time.Hour)
	if _, err := m.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	if srv.RefreshGrantCount() != 1 {
		t.Fatalf("after first Refresh: RefreshGrantCount = %d, want 1", srv.RefreshGrantCount())
	}
	// RT has rotated: store now has RT2, server has consumed RT1.
	if store.data[srv.URL()].RefreshToken == seed.RefreshToken {
		t.Fatal("RT did not rotate after first Refresh")
	}

	// Directly POST RT1 to the server (bypass the Manager).
	// This triggers reuse detection — RT1 was already consumed.
	status, body := postRefreshDirect(t, srv.URL(), seed.RefreshToken)
	if status != http.StatusBadRequest {
		t.Fatalf("direct RT1 replay: status = %d, want 400", status)
	}
	if errCode, _ := body["error"].(string); errCode != "invalid_grant" {
		t.Fatalf("direct RT1 replay: error = %q, want invalid_grant", errCode)
	}
	if !srv.FamilyRevoked(seed.FamilyID) {
		t.Fatal("family not revoked after RT1 replay")
	}

	// Advance past the new login JWT's exp (minted at now+2h, exp=now+3h).
	// This forces the Manager to attempt a refresh again (JWT is expired).
	clock = clock.Add(2 * time.Hour)

	// Now call m.Refresh with RT2 — the family is dead, so the server returns
	// invalid_grant. The Manager re-reads the store, finds the same RT2 (no
	// rotation race), and surfaces ErrReauthRequired.
	_, err := m.Refresh(context.Background())
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("post-revoke Refresh: err = %v, want ErrReauthRequired", err)
	}

	// Credentials must NOT be deleted.
	if _, ok := store.data[srv.URL()]; !ok {
		t.Fatal("credentials deleted after ErrReauthRequired, want preserved")
	}
}

// TestE2E_IdempotencySuccessorAbsorbsReplay configures the server with a
// 500ms idempotency window and asserts that a direct replay of RT1 within
// the window returns the same successor (RT2) without revoking the family.
// The Manager itself is unaffected — this exercises the server primitive.
func TestE2E_IdempotencySuccessorAbsorbsReplay(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	clockFn := func() time.Time { return now }

	srv := testoauth.NewServer(t, testoauth.Config{
		Now:                  clockFn,
		LoginJWTTTL:          time.Hour,
		IdempotencySuccessor: 500 * time.Millisecond,
	})

	seed := srv.SeedFamily("user-5", []string{srv.URL()})

	store := newMemStore()
	store.data[srv.URL()] = tokens.TokenSet{
		AccessToken:  seed.LoginJWT,
		RefreshToken: seed.RefreshToken,
	}

	m := newE2EManager(t, srv, store, t.TempDir())

	// The Manager's clock is advanced 2h so the seeded login JWT (TTL=1h) is
	// expired and a refresh is triggered. The server clock stays at `now` so
	// a direct RT1 replay is within the 500ms idempotency window.
	managerClock := now.Add(2 * time.Hour)
	SetNowForTest(t, m, func() time.Time { return managerClock })

	// Refresh via the Manager: RT1 is consumed on the server, RT2 issued.
	if _, err := m.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	rt2 := store.data[srv.URL()].RefreshToken
	if rt2 == seed.RefreshToken {
		t.Fatal("RT did not rotate after Manager Refresh")
	}

	// Directly POST the original RT1 within the idempotency window (server
	// clock is still at `now`, well within 500ms of the consumedAt).
	// The server should return the same RT2 idempotently, NOT revoke the family.
	status, body := postRefreshDirect(t, srv.URL(), seed.RefreshToken)
	if status != http.StatusOK {
		t.Fatalf("idempotent RT1 replay: status = %d, want 200; body = %v", status, body)
	}
	respondedRT, _ := body["refresh_token"].(string)
	if respondedRT != rt2 {
		t.Fatalf("idempotent replay returned RT %q, want same successor RT %q", respondedRT, rt2)
	}
	if srv.FamilyRevoked(seed.FamilyID) {
		t.Fatal("family was revoked on idempotent replay, want NOT revoked")
	}
}

// TestE2E_NetworkFailureNotMisclassifiedAsReauth asserts that a transport
// error from ForceNextRefresh(FailNetworkError) surfaces as a plain error,
// NOT ErrReauthRequired, and does not modify the stored credentials.
// A follow-up Refresh (without the forced failure) succeeds normally.
func TestE2E_NetworkFailureNotMisclassifiedAsReauth(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	clock := now
	clockFn := func() time.Time { return clock }

	srv := testoauth.NewServer(t, testoauth.Config{
		Now:         clockFn,
		LoginJWTTTL: time.Hour,
	})

	seed := srv.SeedFamily("user-6", []string{srv.URL()})

	store := newMemStore()
	store.data[srv.URL()] = tokens.TokenSet{
		AccessToken:  seed.LoginJWT,
		RefreshToken: seed.RefreshToken,
	}

	m := newE2EManager(t, srv, store, t.TempDir())
	SetNowForTest(t, m, clockFn)

	// Advance past the JWT's TTL so a refresh is needed.
	clock = clock.Add(2 * time.Hour)

	// Force a network error on the next refresh.
	release := srv.ForceNextRefresh(testoauth.FailNetworkError)
	t.Cleanup(release)

	_, err := m.Refresh(context.Background())
	if err == nil {
		t.Fatal("expected error from network failure, got nil")
	}
	if errors.Is(err, ErrReauthRequired) {
		t.Fatalf("network failure classified as ErrReauthRequired: %v", err)
	}
	if errors.Is(err, refresh.ErrInvalidGrant) {
		t.Fatalf("network failure classified as refresh.ErrInvalidGrant: %v", err)
	}

	// Credentials must NOT be modified — the RT is still the original.
	stored := store.data[srv.URL()]
	if stored.RefreshToken != seed.RefreshToken {
		t.Fatalf("refresh token changed on network failure: got %q, want %q", stored.RefreshToken, seed.RefreshToken)
	}

	// The forced error is one-shot and was consumed. The server's RT was NOT
	// consumed during the forced failure (connection closed before Consume ran).
	// A follow-up Refresh must succeed.
	got, err := m.Refresh(context.Background())
	if err != nil {
		t.Fatalf("follow-up Refresh after network failure: %v", err)
	}
	if got == "" {
		t.Fatal("follow-up Refresh returned empty token")
	}
	if srv.RefreshGrantCount() != 1 {
		t.Errorf("RefreshGrantCount = %d, want 1 (only the follow-up succeeded)", srv.RefreshGrantCount())
	}
}

// postRefreshDirect POSTs a refresh_token grant directly to the server,
// bypassing the Manager. Used by tests that exercise server-side behavior
// (reuse detection, idempotency window) against the same family the
// Manager is using.
func postRefreshDirect(t *testing.T, srvURL, rt string) (status int, body map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"test-cli"},
	}
	resp, err := http.Post(srvURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("direct refresh POST: %v", err)
	}
	defer resp.Body.Close()
	body = map[string]any{}
	if err := decodeJSONBody(resp, &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return resp.StatusCode, body
}

func decodeJSONBody(resp *http.Response, v any) error {
	dec := json.NewDecoder(resp.Body)
	return dec.Decode(v)
}
