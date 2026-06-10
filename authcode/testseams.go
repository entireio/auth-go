package authcode

import "time"

// TestingTB is the subset of testing.TB used by SetNowForTest. Minimal so
// production builds never import "testing"; the Cleanup method is the
// signal that misusing the seam requires manufacturing a fake t.
type TestingTB interface {
	Helper()
	Cleanup(func())
}

// SetNowForTest replaces c.now()'s clock for the lifetime of the test. The
// previous override (if any) is restored when t.Cleanup runs. Stores go
// through atomic.Pointer so they don't race the expiry read in Exchange.
// Per-Client (not package-global) so t.Parallel tests with independent
// Clients don't race each other — the same hazard the deviceflow v0.2.0
// review surfaced.
func SetNowForTest(t TestingTB, c *Client, now func() time.Time) {
	t.Helper()
	prev := c.nowOverride.Load()
	if now == nil {
		c.nowOverride.Store(nil)
	} else {
		stored := nowFuncType(now)
		c.nowOverride.Store(&stored)
	}
	t.Cleanup(func() {
		c.nowOverride.Store(prev)
	})
}
