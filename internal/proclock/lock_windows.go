//go:build windows

package proclock

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// tryLock attempts a non-blocking exclusive lock via LockFileEx. Returns
// (true, nil) when taken, (false, nil) when another holder has it, and a
// non-nil error otherwise. ERROR_LOCK_VIOLATION is the would-block signal
// under LOCKFILE_FAIL_IMMEDIATELY.
func tryLock(f *os.File) (bool, error) {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &overlapped,
	)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return false, err
}

func unlock(f *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlapped)
}
