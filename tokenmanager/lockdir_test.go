package tokenmanager

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Config.LockDir is honoured verbatim — it is the caller's escape hatch
// from the implicit default, so it must not be reinterpreted.
func TestProcessLock_UsesConfiguredLockDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m, err := New(Config{Issuer: testIssuer, ClientID: testClientID, Store: newMemStore(), LockDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := m.processLock().(*fileLockPath).path
	if filepath.Dir(got) != dir {
		t.Fatalf("lock path %q is not under LockDir %q", got, dir)
	}
}

// With a cache dir available the default sits under it, unchanged.
func TestDefaultLockDir_PrefersUserCacheDir(t *testing.T) {
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Skipf("no user cache dir on this platform: %v", err)
	}
	if got, want := defaultLockDir(), filepath.Join(cache, "auth-go"); got != want {
		t.Fatalf("defaultLockDir() = %q, want %q", got, want)
	}
}

// When os.UserCacheDir fails the fallback lands in os.TempDir, which on
// Linux is the shared /tmp. A fixed name there is a path every account on
// the host derives identically; the uid suffix keeps them apart.
func TestDefaultLockDir_TempFallbackIsPerUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.UserCacheDir does not read HOME on windows")
	}
	// Emptying both is what makes os.UserCacheDir fail on linux and darwin.
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	if _, err := os.UserCacheDir(); err == nil {
		t.Skip("os.UserCacheDir still resolves with HOME unset on this platform")
	}

	got := defaultLockDir()
	if filepath.Dir(got) != filepath.Clean(os.TempDir()) {
		t.Fatalf("fallback %q is not under os.TempDir() %q", got, os.TempDir())
	}
	base := filepath.Base(got)
	if uid := os.Getuid(); uid >= 0 {
		if want := "auth-go-" + strconv.Itoa(uid); base != want {
			t.Fatalf("fallback dir %q is not namespaced by uid, want %q", base, want)
		}
	}
	if base == "auth-go" {
		t.Fatal("fallback dir name is shared across every account on the host")
	}
	if strings.ContainsAny(base, `/\`) {
		t.Fatalf("fallback dir name %q must be a single path element", base)
	}
}
