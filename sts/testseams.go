package sts

import "time"

// TestingTB is the subset of testing.TB used by SetNowForTest.
type TestingTB interface {
	Helper()
	Cleanup(func())
}

// SetNowForTest replaces c.now()'s clock for the lifetime of the
// test. The previous override (if any) is restored when t.Cleanup
// runs. Stores go through atomic.Pointer so they don't race the
// unsynchronised hot-path reads in Exchange.
//
// Replaces the previous package-global `nowFunc` shim, which
// `t.Parallel`-running tests could race against each other on. With
// a per-Client field, two parallel tests each freeze their own
// Client's clock without interference.
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
