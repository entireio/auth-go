// Package proclock is a cross-process advisory file lock used to
// single-flight credential refreshes across cooperating processes.
//
// The lock file holds no data — it exists only as a flock(2) /
// LockFileEx handle. The advisory lock is released automatically when the
// holding process exits, so a crashed holder never wedges the lock
// permanently (the property a hand-rolled O_EXCL lockfile lacks).
package proclock

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// pollInterval is how often Acquire retries a non-blocking lock attempt
// while waiting. Small enough to feel instant, large enough not to spin.
const pollInterval = 20 * time.Millisecond

// defaultAcquireTimeout bounds a single Acquire when the caller's context
// carries no earlier deadline, guarding against a live-but-wedged holder.
const defaultAcquireTimeout = 30 * time.Second

// FileLock is an advisory lock keyed to a filesystem path. Construct one
// per (path) with New. A FileLock is safe to reuse across Acquire calls
// but a single FileLock value must not be Acquired re-entrantly.
type FileLock struct {
	path string
}

// New returns a FileLock for path. The file and its parent directory are
// created lazily on Acquire.
func New(path string) *FileLock { return &FileLock{path: path} }

// Acquire blocks until the exclusive lock is held or ctx is done. It
// returns an idempotent release func; call it to release the lock and
// close the underlying handle. Acquire applies defaultAcquireTimeout as a
// ceiling: if ctx already carries an earlier deadline, that deadline wins.
func (l *FileLock) Acquire(ctx context.Context) (func(), error) {
	ctx, cancel := context.WithTimeout(ctx, defaultAcquireTimeout)
	// cancel is deferred to the release path (not called eagerly on
	// success) so the timeout context's goroutine is cleaned up only when
	// the caller releases the lock.

	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		cancel()
		return nil, fmt.Errorf("proclock: create dir: %w", err)
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("proclock: open lock file: %w", err)
	}

	for {
		ok, err := tryLock(f)
		if err != nil {
			_ = f.Close()
			cancel()
			return nil, fmt.Errorf("proclock: lock: %w", err)
		}
		if ok {
			var once sync.Once
			return func() {
				once.Do(func() {
					_ = unlock(f)
					_ = f.Close()
					cancel()
				})
			}, nil
		}

		select {
		case <-ctx.Done():
			_ = f.Close()
			cancel()
			return nil, fmt.Errorf("proclock: %w", ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}
