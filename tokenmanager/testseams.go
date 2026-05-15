package tokenmanager

import (
	"context"
	"time"

	"github.com/entireio/auth-go/sts"
	"github.com/entireio/auth-go/tokens"
)

// TestingTB is the subset of testing.TB used by the test-seam setters.
// It's a minimal interface so tests can use *testing.T directly without
// the seam helpers having to import "testing" in production builds.
//
// Production code should never construct one of these by hand. The
// presence of the Cleanup method is the signal: misusing the seams
// requires manufacturing a fake t.Cleanup, which is awkward enough to
// trip a reviewer.
type TestingTB interface {
	Helper()
	Cleanup(func())
}

// SetExchangeForTest replaces the STS-exchange dispatch on m with fn
// for the lifetime of the test. The previous override (if any) is
// restored when t.Cleanup runs.
//
// This is the test seam previously exposed as Config.Exchange. It was
// moved off the public Config so production callers can't bypass the
// STS call by setting a struct field — a fn that returns
// attacker-controlled tokens defeats every server-side validation
// the library otherwise relies on.
func SetExchangeForTest(t TestingTB, m *Manager, fn func(context.Context, sts.ExchangeRequest) (*tokens.TokenSet, error)) {
	t.Helper()
	m.mu.Lock()
	prev := m.exchangeOverride
	m.exchangeOverride = fn
	m.mu.Unlock()
	t.Cleanup(func() {
		m.mu.Lock()
		m.exchangeOverride = prev
		m.mu.Unlock()
	})
}

// SetNowForTest replaces the manager's clock with now for the lifetime
// of the test. The previous override (if any) is restored when
// t.Cleanup runs.
//
// This is the test seam previously exposed as Config.Now. It was moved
// off the public Config alongside Exchange so the two have a single
// idiom for test injection.
func SetNowForTest(t TestingTB, m *Manager, now func() time.Time) {
	t.Helper()
	m.mu.Lock()
	prev := m.nowOverride
	m.nowOverride = now
	m.mu.Unlock()
	t.Cleanup(func() {
		m.mu.Lock()
		m.nowOverride = prev
		m.mu.Unlock()
	})
}
