//go:build unix

package proclock

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// tryLock attempts a non-blocking exclusive flock. Returns (true, nil)
// when the lock is taken, (false, nil) when another holder has it, and a
// non-nil error for any other failure.
func tryLock(f *os.File) (bool, error) {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.EWOULDBLOCK) {
		return false, nil
	}
	return false, err
}

// unlock releases the lock held on f.
func unlock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
