package refresh

import "time"

// TestingTB is the subset of testing.TB used by SetNowForTest.
type TestingTB interface {
	Helper()
	Cleanup(func())
}

// SetNowForTest replaces the client's clock with now for the lifetime of
// the test, restoring the previous override on t.Cleanup. Stored via
// atomic.Pointer so it doesn't race the hot-path read in Refresh.
//
// Production code should never construct a Client via this path; it is
// exported for use in test files only.
func SetNowForTest(t TestingTB, c *Client, now func() time.Time) {
	t.Helper()
	prev := c.nowOverride.Load()
	if now == nil {
		c.nowOverride.Store(nil)
	} else {
		stored := nowFuncType(now)
		c.nowOverride.Store(&stored)
	}
	t.Cleanup(func() { c.nowOverride.Store(prev) })
}
