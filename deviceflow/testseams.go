package deviceflow

import "time"

// TestingTB is the subset of testing.TB used by SetNowForTest. It's
// minimal so tests can use *testing.T directly without the seam
// helper having to import "testing" into production builds.
//
// Production code should never construct one of these by hand. The
// presence of the Cleanup method is the signal: misusing the seam
// requires manufacturing a fake t.Cleanup, which is awkward enough
// to trip a reviewer.
type TestingTB interface {
	Helper()
	Cleanup(func())
}

// SetNowForTest replaces c.now()'s clock for the lifetime of the
// test. The previous override (if any) is restored when t.Cleanup
// runs. Stores go through atomic.Pointer so they don't race the
// unsynchronised hot-path reads in PollDeviceAuth / PollUntil.
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
