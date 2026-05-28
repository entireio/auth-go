package proclock_test

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entireio/auth-go/internal/proclock"
)

// TestFileLock_MutualExclusion runs many goroutines through the same lock
// path and asserts the guarded region is never entered concurrently.
func TestFileLock_MutualExclusion(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "test.lock")

	var inside atomic.Int32
	var maxSeen atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lock := proclock.New(path)
			release, err := lock.Acquire(context.Background())
			if err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			defer release()
			n := inside.Add(1)
			for {
				old := maxSeen.Load()
				if n <= old || maxSeen.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			inside.Add(-1)
		}()
	}
	wg.Wait()
	if got := maxSeen.Load(); got != 1 {
		t.Fatalf("max concurrent holders = %d, want 1", got)
	}
}

// TestFileLock_ContextCancel pins that Acquire returns when ctx is done
// while another holder keeps the lock.
func TestFileLock_ContextCancel(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "test.lock")

	holder := proclock.New(path)
	release, err := holder.Acquire(context.Background())
	if err != nil {
		t.Fatalf("holder Acquire: %v", err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	waiter := proclock.New(path)
	start := time.Now()
	if _, err := waiter.Acquire(ctx); err == nil {
		t.Fatal("waiter Acquire returned nil error, want ctx deadline")
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("waiter blocked %v, want to honour the 50ms ctx deadline", elapsed)
	}
}

// TestFileLock_ReleaseIdempotent pins that calling release twice is safe.
func TestFileLock_ReleaseIdempotent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "test.lock")
	release, err := proclock.New(path).Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	release()
	release() // must not panic
}
