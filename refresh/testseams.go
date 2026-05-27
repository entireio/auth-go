package refresh

import (
	"testing"
	"time"
)

// SetNowForTest replaces the client's clock with now for the lifetime of
// the test, restoring the previous override on t.Cleanup. Stored via
// atomic.Pointer so it doesn't race the hot-path read in Refresh.
func SetNowForTest(t *testing.T, c *Client, now func() time.Time) {
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
