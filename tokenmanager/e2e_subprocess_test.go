package tokenmanager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/entireio/auth-go/internal/proclock"
	"github.com/entireio/auth-go/internal/testoauth"
	"github.com/entireio/auth-go/tokens"
	"github.com/entireio/auth-go/tokenstore"
)

// TestMain dispatches to a helper body when AUTHGO_E2E_HELPER is set.
// Subprocess tests spawn this binary with the env var to drive Manager
// actions from a separate process. Without the env var the normal test
// suite runs.
func TestMain(m *testing.M) {
	if mode := os.Getenv("AUTHGO_E2E_HELPER"); mode != "" {
		runHelper(mode)
		// runHelper never returns; explicit exit guards against future drift.
		os.Exit(99)
	}
	os.Exit(m.Run())
}

// TestE2ESub_Helper is the entry point parent tests target with -test.run.
// It just lets the test binary start; the real work happens in TestMain via
// the env-var dispatch (which os.Exit'd before reaching here).
func TestE2ESub_Helper(t *testing.T) {
	t.Skip("helper entry point — invoked only as a subprocess via TestMain")
}

// helperResult is the JSON line each helper subprocess prints to stdout.
type helperResult struct {
	OK          bool   `json:"ok"`
	AccessToken string `json:"access_token,omitempty"`
	Error       string `json:"error,omitempty"`
	ElapsedMs   int64  `json:"elapsed_ms"`
}

func runHelper(mode string) {
	start := time.Now()
	result := helperResult{}
	defer func() {
		result.ElapsedMs = time.Since(start).Milliseconds()
		_ = json.NewEncoder(os.Stdout).Encode(result)
		if !result.OK {
			os.Exit(1)
		}
		os.Exit(0)
	}()
	defer func() {
		if r := recover(); r != nil {
			result.Error = fmt.Sprintf("panic: %v", r)
		}
	}()

	switch mode {
	case "refresh-once":
		result = helperRefreshOnce()
	case "refresh-with-timeout":
		result = helperRefreshWithTimeout()
	case "logout":
		result = helperLogout()
	case "relogin":
		result = helperRelogin()
	case "proclock-contend":
		result = helperProclockContend()
	default:
		result.Error = "unknown helper mode: " + mode
	}
}

// newHelperManager builds a Manager from env vars using a file-backed store
// when AUTHGO_E2E_STORE_DIR is set. A seed from AUTHGO_E2E_SEED_JSON is
// written to the store before returning (when non-empty).
func newHelperManager() *Manager {
	storeDir := os.Getenv("AUTHGO_E2E_STORE_DIR")
	var store tokenstore.Store
	if storeDir != "" {
		fs := newFileStore(storeDir)
		if seed := os.Getenv("AUTHGO_E2E_SEED_JSON"); seed != "" {
			var ts tokens.TokenSet
			if err := json.Unmarshal([]byte(seed), &ts); err != nil {
				panic("bad AUTHGO_E2E_SEED_JSON: " + err.Error())
			}
			if err := fs.SaveTokens(os.Getenv("AUTHGO_E2E_ISSUER"), ts); err != nil {
				panic("seed fileStore: " + err.Error())
			}
		}
		store = fs
	} else {
		ms := newMemStore()
		if seed := os.Getenv("AUTHGO_E2E_SEED_JSON"); seed != "" {
			var ts tokens.TokenSet
			if err := json.Unmarshal([]byte(seed), &ts); err != nil {
				panic("bad AUTHGO_E2E_SEED_JSON: " + err.Error())
			}
			ms.data[os.Getenv("AUTHGO_E2E_ISSUER")] = ts
		}
		store = ms
	}

	m, err := New(Config{
		Issuer:            os.Getenv("AUTHGO_E2E_ISSUER"),
		ClientID:          os.Getenv("AUTHGO_E2E_CLIENT_ID"),
		STSPath:           "/oauth/token",
		RefreshPath:       "/oauth/token",
		LockDir:           os.Getenv("AUTHGO_E2E_LOCK_DIR"),
		AllowInsecureHTTP: true,
		Store:             store,
	})
	if err != nil {
		panic("helper New: " + err.Error())
	}
	return m
}

func helperRefreshOnce() helperResult {
	m := newHelperManager()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tok, err := m.Refresh(ctx)
	if err != nil {
		return helperResult{Error: err.Error()}
	}
	return helperResult{OK: true, AccessToken: tok}
}

func helperRefreshWithTimeout() helperResult {
	m := newHelperManager()
	timeoutMs, _ := strconv.Atoi(os.Getenv("AUTHGO_E2E_CTX_TIMEOUT_MS"))
	if timeoutMs <= 0 {
		timeoutMs = 150
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	tok, err := m.Refresh(ctx)
	r := helperResult{AccessToken: tok}
	if err == nil {
		r.OK = true
		return r
	}
	// A real ctx-cancel surfaces as context.DeadlineExceeded (the typed
	// cause) OR a transport error containing that sentinel string (e.g.
	// `Post "...": context deadline exceeded` from net/http). We accept
	// context.Canceled too because some transport paths surface a parent-
	// cancelled write as Canceled before the deadline propagates. The
	// substring fallback is deliberately narrow ("context deadline" or
	// "context canceled") so unrelated errors that happen to mention the
	// word "context" don't get classified as the expected outcome.
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) ||
		strings.Contains(err.Error(), "context deadline") ||
		strings.Contains(err.Error(), "context canceled") {
		r.OK = true
		r.Error = err.Error()
		return r
	}
	r.Error = err.Error()
	return r
}

func helperLogout() helperResult {
	m := newHelperManager()
	if err := m.DeleteCoreToken(); err != nil {
		return helperResult{Error: err.Error()}
	}
	return helperResult{OK: true}
}

func helperRelogin() helperResult {
	m := newHelperManager()
	var newSet tokens.TokenSet
	if err := json.Unmarshal([]byte(os.Getenv("AUTHGO_E2E_NEW_USER_JSON")), &newSet); err != nil {
		return helperResult{Error: "bad AUTHGO_E2E_NEW_USER_JSON: " + err.Error()}
	}
	if err := m.SaveCoreToken(newSet); err != nil {
		return helperResult{Error: err.Error()}
	}
	return helperResult{OK: true}
}

func helperProclockContend() helperResult {
	// Pure proclock test — no Manager, no OAuth. Each round: acquire the
	// shared lock, bump a counter file under the lock, sleep briefly, release.
	// Parent inspects the counter file at the end.
	path := os.Getenv("AUTHGO_E2E_LOCK_PATH")
	counter := os.Getenv("AUTHGO_E2E_COUNTER_PATH")
	rounds, _ := strconv.Atoi(os.Getenv("AUTHGO_E2E_PROCLOCK_ROUNDS"))
	if rounds == 0 {
		rounds = 20
	}
	for i := 0; i < rounds; i++ {
		release, err := proclock.New(path).Acquire(context.Background())
		if err != nil {
			return helperResult{Error: "Acquire: " + err.Error()}
		}
		// Read-modify-write the counter file under the lock. If two processes
		// ever interleave reads+writes here, the counter ends up < 2*rounds.
		current := readCounter(counter)
		time.Sleep(2 * time.Millisecond) // widen the race window
		writeCounter(counter, current+1)
		release()
	}
	return helperResult{OK: true}
}

// readCounter reads an integer from path. Returns 0 if the file doesn't exist.
// Panics on any other read error or parse failure so the proclock test cannot
// silently pass on a broken counter file.
func readCounter(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0
		}
		panic(fmt.Sprintf("readCounter %q: %v", path, err))
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		panic(fmt.Sprintf("readCounter %q parse: content=%q: %v", path, string(b), err))
	}
	return n
}

// writeCounter writes n to path atomically (write tmp + rename).
func writeCounter(path string, n int) {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(n)), 0o600); err != nil {
		panic("writeCounter: " + err.Error())
	}
	if err := os.Rename(tmp, path); err != nil {
		panic("writeCounter rename: " + err.Error())
	}
}

// fileStore is a JSON-file-backed tokenstore.Store usable across processes.
// SaveTokens writes profile→file atomically; LoadTokens reads; DeleteTokens
// removes. Used only by the subprocess e2e tests.
type fileStore struct {
	dir string
}

func newFileStore(dir string) *fileStore {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		panic("newFileStore mkdir: " + err.Error())
	}
	return &fileStore{dir: dir}
}

// filePath encodes the profile string into a filename-safe path using SHA-256.
func (s *fileStore) filePath(profile string) string {
	sum := sha256.Sum256([]byte(profile))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+".json")
}

func (s *fileStore) SaveTokens(profile string, t tokens.TokenSet) error {
	if t.AccessToken == "" {
		return fmt.Errorf("fileStore: refusing to save TokenSet with empty access token")
	}
	b, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("fileStore SaveTokens marshal: %w", err)
	}
	p := s.filePath(profile)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("fileStore SaveTokens write: %w", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("fileStore SaveTokens rename: %w", err)
	}
	return nil
}

func (s *fileStore) LoadTokens(profile string) (tokens.TokenSet, error) {
	b, err := os.ReadFile(s.filePath(profile))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return tokens.TokenSet{}, tokenstore.ErrNotFound
		}
		return tokens.TokenSet{}, fmt.Errorf("fileStore LoadTokens: %w", err)
	}
	var t tokens.TokenSet
	if err := json.Unmarshal(b, &t); err != nil {
		return tokens.TokenSet{}, fmt.Errorf("fileStore LoadTokens unmarshal: %w", err)
	}
	return t, nil
}

func (s *fileStore) DeleteTokens(profile string) error {
	if err := os.Remove(s.filePath(profile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("fileStore DeleteTokens: %w", err)
	}
	return nil
}

// --- Parent-side subprocess infrastructure ---

// lineCaptureWriter forwards subprocess stderr lines to t.Log with a prefix.
type lineCaptureWriter struct {
	t      *testing.T
	prefix string
	buf    []byte
}

func (w *lineCaptureWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.t.Logf("%s%s", w.prefix, string(w.buf[:i]))
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}

// flush writes any buffered bytes that don't end with '\n' as a final log line.
// Called after cmd.Wait so residual subprocess output (e.g. a panic stack
// ending mid-line) is not lost.
func (w *lineCaptureWriter) flush() {
	if len(w.buf) > 0 {
		w.t.Logf("%s%s (no trailing newline)", w.prefix, string(w.buf))
		w.buf = nil
	}
}

// spawnHelper builds an *exec.Cmd that re-execs the test binary in helper
// mode. Stdout is captured into out; stderr is written to t.Log. A Cleanup
// is registered to flush any residual stderr bytes that lacked a trailing
// newline (e.g. a mid-line panic stack).
func spawnHelper(t *testing.T, mode string, env map[string]string, out *bytes.Buffer) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestE2ESub_Helper$", "-test.v=false")
	envv := os.Environ()
	envv = append(envv, "AUTHGO_E2E_HELPER="+mode)
	for k, v := range env {
		envv = append(envv, k+"="+v)
	}
	cmd.Env = envv
	cmd.Stdout = out
	lcw := &lineCaptureWriter{t: t, prefix: mode + ": "}
	cmd.Stderr = lcw
	t.Cleanup(lcw.flush)
	return cmd
}

// mustMarshal marshals v to JSON or fails the test.
func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// decodeHelperOutput decodes the last helperResult from stdout.
func decodeHelperOutput(stdout string) (helperResult, error) {
	var r helperResult
	dec := json.NewDecoder(strings.NewReader(stdout))
	for dec.More() {
		if err := dec.Decode(&r); err != nil {
			return helperResult{}, err
		}
	}
	return r, nil
}

// mintExpiredJWT mints a test JWT that is definitely expired: its exp is set
// to 2000-01-01, well in the past from any real system clock. The `now`
// parameter is used only for IssuedAt (informational). Used to seed the store
// with a token that will always trigger a refresh in subprocess Managers that
// use time.Now() as their clock.
func mintExpiredJWT(issuer, sub string, now time.Time) string {
	expiredAt := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	return testoauth.MintUnsignedJWT(testoauth.Claims{
		Issuer:    issuer,
		Subject:   sub,
		Audience:  []string{issuer},
		IssuedAt:  now.Add(-24 * time.Hour),
		ExpiresAt: expiredAt,
	})
}

// --- The four cross-process tests ---

// TestE2ESub_CrossProcessSingleFlight verifies that two refresh subprocesses
// against the same server + LockDir + shared file store drive exactly one
// server refresh grant. The file-backed store lets the second subprocess (the
// lock waiter) re-read the token the first one persisted, skipping its grant.
func TestE2ESub_CrossProcessSingleFlight(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess test; skipped in -short")
	}
	t.Parallel()

	// Use real wall time on the server (not a pinned date) so the JWT exp
	// the server mints into refresh responses (server.now + LoginJWTTTL)
	// is always live for the test run. Pinning the server clock to a
	// fixed date while the subprocess Manager uses real time.Now creates
	// a time-of-day-dependent flake: once wall-clock passes the pinned
	// exp, the second subprocess sees the persisted token as expired and
	// refreshes again, breaking the single-flight assertion.
	now := time.Now()
	srv := testoauth.NewServer(t, testoauth.Config{
		LoginJWTTTL: time.Hour,
	})
	seed := srv.SeedFamily("u", []string{srv.URL()})

	storeDir := t.TempDir()
	lockDir := t.TempDir()

	// Seed the file store with an expired login JWT so both subprocesses
	// trigger a refresh.
	parentStore := newFileStore(storeDir)
	if err := parentStore.SaveTokens(srv.URL(), tokens.TokenSet{
		AccessToken:  mintExpiredJWT(srv.URL(), "u", now),
		RefreshToken: seed.RefreshToken,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	commonEnv := map[string]string{
		"AUTHGO_E2E_ISSUER":    srv.URL(),
		"AUTHGO_E2E_CLIENT_ID": "cli",
		"AUTHGO_E2E_LOCK_DIR":  lockDir,
		"AUTHGO_E2E_STORE_DIR": storeDir,
	}

	type spawnedResult struct {
		res helperResult
		err error
	}
	resultCh := make(chan spawnedResult, 2)
	for range 2 {
		go func() {
			var out bytes.Buffer
			cmd := spawnHelper(t, "refresh-once", commonEnv, &out)
			runErr := cmd.Run()
			r, decErr := decodeHelperOutput(out.String())
			if decErr != nil {
				resultCh <- spawnedResult{err: fmt.Errorf("decode: %v\nraw: %s", decErr, out.String())}
				return
			}
			if runErr != nil && !r.OK {
				// Non-zero exit with a decoded error is a helper-level failure.
				resultCh <- spawnedResult{res: r}
				return
			}
			if runErr != nil {
				resultCh <- spawnedResult{err: fmt.Errorf("run: %v\nstdout: %s", runErr, out.String())}
				return
			}
			resultCh <- spawnedResult{res: r}
		}()
	}

	var got []helperResult
	for range 2 {
		r := <-resultCh
		if r.err != nil {
			t.Fatalf("subprocess: %v", r.err)
		}
		got = append(got, r.res)
	}

	if srv.RefreshGrantCount() != 1 {
		t.Errorf("RefreshGrantCount = %d, want 1 (cross-process single-flight)", srv.RefreshGrantCount())
	}
	for i, r := range got {
		if !r.OK {
			t.Errorf("subprocess[%d] err: %s", i, r.Error)
		}
		if r.AccessToken == "" {
			t.Errorf("subprocess[%d] empty access token", i)
		}
	}
	if len(got) == 2 && got[0].AccessToken != got[1].AccessToken {
		t.Fatalf("subprocesses got different access tokens — they didn't share the persisted token via the file store + lock\ngot[0]=%q\ngot[1]=%q", got[0].AccessToken, got[1].AccessToken)
	}
}

// TestE2ESub_LogoutWinsOverInFlightRefresh verifies that a logout subprocess
// blocks on the cross-process lock while a refresh is in-flight (stalled at
// the server). After the stall is released and both subprocesses complete,
// the store is empty — logout wins as the later writer.
func TestE2ESub_LogoutWinsOverInFlightRefresh(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess test; skipped in -short")
	}
	t.Parallel()

	// Use real wall time on the server (not a pinned date) so the JWT exp
	// the server mints into refresh responses (server.now + LoginJWTTTL)
	// is always live for the test run. Pinning the server clock to a
	// fixed date while the subprocess Manager uses real time.Now creates
	// a time-of-day-dependent flake: once wall-clock passes the pinned
	// exp, the second subprocess sees the persisted token as expired and
	// refreshes again, breaking the single-flight assertion.
	now := time.Now()
	srv := testoauth.NewServer(t, testoauth.Config{
		LoginJWTTTL: time.Hour,
	})
	seed := srv.SeedFamily("u", []string{srv.URL()})

	storeDir := t.TempDir()
	lockDir := t.TempDir()
	parentStore := newFileStore(storeDir)
	if err := parentStore.SaveTokens(srv.URL(), tokens.TokenSet{
		AccessToken:  mintExpiredJWT(srv.URL(), "u", now),
		RefreshToken: seed.RefreshToken,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	commonEnv := map[string]string{
		"AUTHGO_E2E_ISSUER":    srv.URL(),
		"AUTHGO_E2E_CLIENT_ID": "cli",
		"AUTHGO_E2E_LOCK_DIR":  lockDir,
		"AUTHGO_E2E_STORE_DIR": storeDir,
	}

	release, _ := srv.StallNextRefresh()
	// Always release on test exit so we don't hang if the test fails early.
	t.Cleanup(release)

	// Start refresh subprocess — it will hold the cross-process lock while
	// stalled at the server.
	var refreshOut bytes.Buffer
	refreshCmd := spawnHelper(t, "refresh-once", commonEnv, &refreshOut)
	if err := refreshCmd.Start(); err != nil {
		t.Fatalf("start refresh: %v", err)
	}

	// Wait for the refresh to hit the server and stall there.
	time.Sleep(200 * time.Millisecond)

	// Start logout subprocess — it will block on the cross-process lock.
	var logoutOut bytes.Buffer
	logoutCmd := spawnHelper(t, "logout", commonEnv, &logoutOut)
	if err := logoutCmd.Start(); err != nil {
		t.Fatalf("start logout: %v", err)
	}

	// Give logout time to attempt the lock and block, then release the stall.
	// 300ms gives the subprocess enough runway to start, acquire the lock
	// attempt, and block — so its elapsed_ms is dominated by actual lock-wait.
	time.Sleep(300 * time.Millisecond)
	release() // idempotent; t.Cleanup won't double-release harmfully

	if err := refreshCmd.Wait(); err != nil {
		t.Fatalf("refresh subprocess: %v\nstdout: %s", err, refreshOut.String())
	}
	if err := logoutCmd.Wait(); err != nil {
		t.Fatalf("logout subprocess: %v\nstdout: %s", err, logoutOut.String())
	}

	// Decode the logout subprocess's own elapsed time. This measures from
	// Manager construction to result return, capturing actual lock-wait time
	// rather than parent-side wall-clock (which would include the parent's
	// own pre-release sleep and is a tautology).
	const stallWindowMs = 200
	logoutResult, err := decodeHelperOutput(logoutOut.String())
	if err != nil {
		t.Fatalf("decode logout result: %v", err)
	}
	if !logoutResult.OK {
		t.Fatalf("logout subprocess error: %s", logoutResult.Error)
	}
	if logoutResult.ElapsedMs < stallWindowMs {
		t.Fatalf("logout elapsed_ms = %d, want >= %d (subprocess must wait on the cross-process lock)", logoutResult.ElapsedMs, stallWindowMs)
	}

	// Refresh must have completed exactly once before the logout ran.
	if got := srv.RefreshGrantCount(); got != 1 {
		t.Fatalf("RefreshGrantCount = %d, want exactly 1 (the in-flight refresh must complete before the mutation runs)", got)
	}

	// Final state: store empty (logout deletes after refresh persists).
	if _, err := parentStore.LoadTokens(srv.URL()); !errors.Is(err, tokenstore.ErrNotFound) {
		t.Fatalf("store after logout: err=%v, want tokenstore.ErrNotFound", err)
	}
}

// TestE2ESub_ReloginWinsOverInFlightRefresh verifies that a relogin subprocess
// blocks on the cross-process lock while a refresh is in-flight (stalled at
// the server). After both complete, the store has the new user's credentials.
func TestE2ESub_ReloginWinsOverInFlightRefresh(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess test; skipped in -short")
	}
	t.Parallel()

	// Use real wall time on the server (not a pinned date) so the JWT exp
	// the server mints into refresh responses (server.now + LoginJWTTTL)
	// is always live for the test run. Pinning the server clock to a
	// fixed date while the subprocess Manager uses real time.Now creates
	// a time-of-day-dependent flake: once wall-clock passes the pinned
	// exp, the second subprocess sees the persisted token as expired and
	// refreshes again, breaking the single-flight assertion.
	now := time.Now()
	srv := testoauth.NewServer(t, testoauth.Config{
		LoginJWTTTL: time.Hour,
	})
	seed := srv.SeedFamily("u", []string{srv.URL()})

	// Seed a second family representing the "new user" after relogin.
	newUser := srv.SeedFamily("new-user", []string{srv.URL()})
	newUserSet := tokens.TokenSet{
		AccessToken:  newUser.LoginJWT,
		RefreshToken: newUser.RefreshToken,
	}

	storeDir := t.TempDir()
	lockDir := t.TempDir()
	parentStore := newFileStore(storeDir)
	if err := parentStore.SaveTokens(srv.URL(), tokens.TokenSet{
		AccessToken:  mintExpiredJWT(srv.URL(), "u", now),
		RefreshToken: seed.RefreshToken,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	commonEnv := map[string]string{
		"AUTHGO_E2E_ISSUER":        srv.URL(),
		"AUTHGO_E2E_CLIENT_ID":     "cli",
		"AUTHGO_E2E_LOCK_DIR":      lockDir,
		"AUTHGO_E2E_STORE_DIR":     storeDir,
		"AUTHGO_E2E_NEW_USER_JSON": mustMarshal(t, newUserSet),
	}

	release, _ := srv.StallNextRefresh()
	t.Cleanup(release)

	// Start refresh subprocess.
	var refreshOut bytes.Buffer
	refreshCmd := spawnHelper(t, "refresh-once", commonEnv, &refreshOut)
	if err := refreshCmd.Start(); err != nil {
		t.Fatalf("start refresh: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Start relogin subprocess — it blocks on the lock until refresh releases.
	var reloginOut bytes.Buffer
	reloginCmd := spawnHelper(t, "relogin", commonEnv, &reloginOut)
	if err := reloginCmd.Start(); err != nil {
		t.Fatalf("start relogin: %v", err)
	}

	// 300ms gives the subprocess enough runway to start, acquire the lock
	// attempt, and block — so its elapsed_ms is dominated by actual lock-wait.
	time.Sleep(300 * time.Millisecond)
	release()

	if err := refreshCmd.Wait(); err != nil {
		t.Fatalf("refresh subprocess: %v\nstdout: %s", err, refreshOut.String())
	}
	if err := reloginCmd.Wait(); err != nil {
		t.Fatalf("relogin subprocess: %v\nstdout: %s", err, reloginOut.String())
	}

	// Decode the relogin subprocess's own elapsed time. This measures from
	// Manager construction to result return, capturing actual lock-wait time
	// rather than parent-side wall-clock (which would include the parent's
	// own pre-release sleep and is a tautology).
	const stallWindowMs = 200
	reloginResult, err := decodeHelperOutput(reloginOut.String())
	if err != nil {
		t.Fatalf("decode relogin result: %v", err)
	}
	if !reloginResult.OK {
		t.Fatalf("relogin subprocess error: %s", reloginResult.Error)
	}
	if reloginResult.ElapsedMs < stallWindowMs {
		t.Fatalf("relogin elapsed_ms = %d, want >= %d (subprocess must wait on the cross-process lock)", reloginResult.ElapsedMs, stallWindowMs)
	}

	// Refresh must have completed exactly once before the relogin ran.
	if got := srv.RefreshGrantCount(); got != 1 {
		t.Fatalf("RefreshGrantCount = %d, want exactly 1 (the in-flight refresh must complete before the mutation runs)", got)
	}

	// Final state: store has the new user's access token.
	stored, err := parentStore.LoadTokens(srv.URL())
	if err != nil {
		t.Fatalf("load store after relogin: %v", err)
	}
	if stored.AccessToken != newUser.LoginJWT {
		t.Fatalf("stored access token = %q, want new user's token %q (relogin must win)", stored.AccessToken, newUser.LoginJWT)
	}
}

// TestE2ESub_ProclockMutualExclusion verifies cross-process mutual exclusion:
// two subprocesses each acquire the same lock and atomically increment a
// shared counter 20 times. The final counter must equal 40.
func TestE2ESub_ProclockMutualExclusion(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess test; skipped in -short")
	}
	t.Parallel()

	tmp := t.TempDir()
	lockPath := filepath.Join(tmp, "lock")
	counterPath := filepath.Join(tmp, "counter")
	env := map[string]string{
		"AUTHGO_E2E_LOCK_PATH":       lockPath,
		"AUTHGO_E2E_COUNTER_PATH":    counterPath,
		"AUTHGO_E2E_PROCLOCK_ROUNDS": "20",
	}

	done := make(chan error, 2)
	for range 2 {
		go func() {
			var out bytes.Buffer
			cmd := spawnHelper(t, "proclock-contend", env, &out)
			if err := cmd.Run(); err != nil {
				done <- fmt.Errorf("%v\nstdout: %s", err, out.String())
			} else {
				done <- nil
			}
		}()
	}
	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("subprocess: %v", err)
		}
	}

	final := readCounter(counterPath)
	if final != 40 {
		t.Fatalf("counter = %d, want 40 (2 procs × 20 rounds each; less means the lock failed)", final)
	}
}

// TestE2ESub_CtxCancelReleasesLocks verifies that a context cancellation
// mid-refresh releases both refreshMu and the cross-process proclock cleanly.
// Helper A's 150ms ctx expires while the server is stalled; helper B then
// succeeds quickly against the same LockDir, proving both locks were freed.
func TestE2ESub_CtxCancelReleasesLocks(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess test")
	}
	t.Parallel()

	srv := testoauth.NewServer(t, testoauth.Config{LoginJWTTTL: time.Hour})
	seed := srv.SeedFamily("u", []string{srv.URL()})

	storeDir := t.TempDir()
	lockDir := t.TempDir()
	parentStore := newFileStore(storeDir)
	expired := mintExpiredJWT(srv.URL(), "u", time.Now())
	if err := parentStore.SaveTokens(srv.URL(), tokens.TokenSet{AccessToken: expired, RefreshToken: seed.RefreshToken}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	release, _ := srv.StallNextRefresh()
	t.Cleanup(release)

	commonEnv := map[string]string{
		"AUTHGO_E2E_ISSUER":    srv.URL(),
		"AUTHGO_E2E_CLIENT_ID": "cli",
		"AUTHGO_E2E_LOCK_DIR":  lockDir,
		"AUTHGO_E2E_STORE_DIR": storeDir,
	}

	// Helper A: ctx-cancel during stalled grant.
	envA := make(map[string]string, len(commonEnv)+1)
	for k, v := range commonEnv {
		envA[k] = v
	}
	envA["AUTHGO_E2E_CTX_TIMEOUT_MS"] = "150"

	var outA bytes.Buffer
	cmdA := spawnHelper(t, "refresh-with-timeout", envA, &outA)
	if err := cmdA.Run(); err != nil {
		t.Fatalf("helper A: %v\nstdout: %s", err, outA.String())
	}
	resA, err := decodeHelperOutput(outA.String())
	if err != nil {
		t.Fatalf("decode A: %v", err)
	}
	if !resA.OK {
		t.Fatalf("helper A: not OK, error=%q", resA.Error)
	}
	// A's ctx had a 150ms budget; the lock-acquire timeout default is 30s.
	// If the ctx fired correctly mid-grant, A's elapsed should be roughly
	// 150ms + a bit of startup. We give generous margin for CI: < 2s.
	if resA.ElapsedMs >= 2000 {
		t.Fatalf("helper A elapsed = %dms; suggests something other than ctx-cancel fired (lock-acquire timeout?) > 2s", resA.ElapsedMs)
	}

	// Helper B: standard refresh after A's cancellation. Should succeed
	// quickly — proves the locks were released cleanly.
	// NOTE: do NOT call release() before B. The server-side stall goroutine
	// is blocked and has NOT consumed RT_orig yet. B can freely use RT_orig
	// (the proclock from A's process was released on A's process exit).
	// After B finishes, release() unblocks the stall goroutine — that server
	// goroutine will see RT_orig already consumed and get invalid_grant, but
	// nobody is watching that path any more.
	var outB bytes.Buffer
	cmdB := spawnHelper(t, "refresh-once", commonEnv, &outB)
	if err := cmdB.Run(); err != nil {
		t.Fatalf("helper B: %v\nstdout: %s", err, outB.String())
	}
	resB, err := decodeHelperOutput(outB.String())
	if err != nil {
		t.Fatalf("decode B: %v", err)
	}
	if !resB.OK {
		t.Fatalf("helper B not OK: %s", resB.Error)
	}
	if resB.AccessToken == "" {
		t.Fatal("helper B returned empty access token")
	}
	// If A had orphaned either lock, B would wait up to ~30s on the
	// cross-process lock acquire. A few seconds is fine — anything in the
	// teens-of-seconds range indicates the lock wasn't released.
	if resB.ElapsedMs >= 2000 {
		t.Fatalf("helper B elapsed = %dms; suggests the previous helper orphaned a lock > 2s", resB.ElapsedMs)
	}

	// Release the stall so the t.Cleanup stall goroutine can drain cleanly.
	release()

	// Server saw exactly one successful refresh (helper B's). The stall
	// goroutine will eventually get invalid_grant after RT_orig is consumed
	// by B, but that doesn't count as a successful refresh grant.
	if got := srv.RefreshGrantCount(); got != 1 {
		t.Fatalf("RefreshGrantCount = %d, want 1 (only B's refresh succeeded)", got)
	}

	// Final store state: B's rotated RT.
	got, err := parentStore.LoadTokens(srv.URL())
	if err != nil {
		t.Fatalf("LoadTokens: %v", err)
	}
	if got.RefreshToken == seed.RefreshToken {
		t.Fatal("stored RT did not rotate after helper B's refresh")
	}
}

// TestE2ESub_NonCooperatingRaceStrictRevokes verifies the doRefresh retry
// path: two helpers with distinct LockDirs share a fileStore. With
// IdempotencySuccessor: 0 (strict), the loser's first grant gets
// invalid_grant + family revocation; its retry with cur.RefreshToken also
// fails (family revoked); surfaces ErrReauthRequired.
func TestE2ESub_NonCooperatingRaceStrictRevokes(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess test")
	}
	t.Parallel()

	srv := testoauth.NewServer(t, testoauth.Config{
		LoginJWTTTL:          time.Hour,
		IdempotencySuccessor: 0,
	})
	seed := srv.SeedFamily("u", []string{srv.URL()})

	storeDir := t.TempDir()
	lockDirA := t.TempDir()
	lockDirB := t.TempDir()

	parentStore := newFileStore(storeDir)
	expired := mintExpiredJWT(srv.URL(), "u", time.Now())
	if err := parentStore.SaveTokens(srv.URL(), tokens.TokenSet{AccessToken: expired, RefreshToken: seed.RefreshToken}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	commonStore := map[string]string{
		"AUTHGO_E2E_ISSUER":    srv.URL(),
		"AUTHGO_E2E_CLIENT_ID": "cli",
		"AUTHGO_E2E_STORE_DIR": storeDir,
	}

	envA := make(map[string]string, len(commonStore)+1)
	for k, v := range commonStore {
		envA[k] = v
	}
	envA["AUTHGO_E2E_LOCK_DIR"] = lockDirA

	envB := make(map[string]string, len(commonStore)+1)
	for k, v := range commonStore {
		envB[k] = v
	}
	envB["AUTHGO_E2E_LOCK_DIR"] = lockDirB

	release, stalled := srv.StallNextRefresh()
	t.Cleanup(release)

	// Spawn A in background so the parent can continue while A is stalled.
	var outA bytes.Buffer
	cmdA := spawnHelper(t, "refresh-once", envA, &outA)
	if err := cmdA.Start(); err != nil {
		t.Fatalf("start A: %v", err)
	}

	// Wait for A's request to be definitively inside the stall wait before
	// spawning B. The stalled channel closes the moment A's goroutine enters
	// <-stallCh, so this is a precise synchronisation point with no sleep.
	select {
	case <-stalled:
		// A's request is now blocked on the stall channel — safe to spawn B.
	case <-time.After(2 * time.Second):
		t.Fatal("helper A did not enter the stall within 2s")
	}

	// Spawn B and wait for it to finish. B is not stalled (one-shot consumed by A).
	// B consumes RT_orig → gets RT_new1 → persists to shared fileStore.
	var outB bytes.Buffer
	cmdB := spawnHelper(t, "refresh-once", envB, &outB)
	if err := cmdB.Run(); err != nil {
		t.Fatalf("B: %v\n%s", err, outB.String())
	}
	resB, err := decodeHelperOutput(outB.String())
	if err != nil {
		t.Fatalf("decode B: %v", err)
	}

	// Release stall, wait for A.
	release()
	// A exits with code 1 (resA.OK == false) — don't fatal on that.
	_ = cmdA.Wait()

	resA, err := decodeHelperOutput(outA.String())
	if err != nil {
		t.Fatalf("decode A: %v\nraw: %s", err, outA.String())
	}

	// A's first grant gets invalid_grant + family revocation; retry with
	// cur.RefreshToken (= RT_new1) also gets invalid_grant (family revoked).
	// A returns ErrReauthRequired.
	if resA.OK {
		t.Fatalf("helper A: expected not OK (ErrReauthRequired), got OK with token=%q", resA.AccessToken)
	}
	if !strings.Contains(resA.Error, "reauthentication required") {
		t.Fatalf("helper A error = %q, want string containing \"reauthentication required\"", resA.Error)
	}

	if !resB.OK {
		t.Fatalf("helper B not OK: %s", resB.Error)
	}
	if resB.AccessToken == "" {
		t.Fatal("helper B returned empty access token")
	}

	// Only B's grant succeeded.
	if got := srv.RefreshGrantCount(); got != 1 {
		t.Fatalf("RefreshGrantCount = %d, want 1 (only B succeeded)", got)
	}
	// GrantCount == 3 + RefreshGrantCount == 1 proves the retry path fired
	// (two handler entries from A — first attempt + retry — plus B's success).
	// Note this does NOT externally distinguish "retry used cur.RefreshToken
	// from the store" from "retry used the original sent RT again" — both
	// would leave the family revoked. The unit test
	// TestDoRefresh_RotationRaceRetriesWithNewRT covers that distinction
	// directly with a fake refresh fn.
	if got := srv.GrantCount(); got != 3 {
		t.Fatalf("GrantCount = %d, want 3 (B's success + A's first + A's retry)", got)
	}
	// Family was revoked by the strict reuse-detection.
	if !srv.FamilyRevoked(seed.FamilyID) {
		t.Fatal("family was not revoked, want revoked (strict IdempotencySuccessor=0)")
	}

	// Final store state: B's rotated RT (A persisted nothing).
	stored, err := parentStore.LoadTokens(srv.URL())
	if err != nil {
		t.Fatalf("LoadTokens: %v", err)
	}
	if stored.RefreshToken == seed.RefreshToken {
		t.Fatal("stored RT == seed.RefreshToken; expected B's rotated RT")
	}
}

// TestE2ESub_NonCooperatingRaceLaxAbsorbs verifies that with a non-zero
// IdempotencySuccessor window, the loser's grant returns the already-issued
// successor idempotently — no retry fires, no family revocation.
func TestE2ESub_NonCooperatingRaceLaxAbsorbs(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess test")
	}
	t.Parallel()

	srv := testoauth.NewServer(t, testoauth.Config{
		LoginJWTTTL:          time.Hour,
		IdempotencySuccessor: 5 * time.Second,
	})
	seed := srv.SeedFamily("u", []string{srv.URL()})

	storeDir := t.TempDir()
	lockDirA := t.TempDir()
	lockDirB := t.TempDir()

	parentStore := newFileStore(storeDir)
	expired := mintExpiredJWT(srv.URL(), "u", time.Now())
	if err := parentStore.SaveTokens(srv.URL(), tokens.TokenSet{AccessToken: expired, RefreshToken: seed.RefreshToken}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	commonStore := map[string]string{
		"AUTHGO_E2E_ISSUER":    srv.URL(),
		"AUTHGO_E2E_CLIENT_ID": "cli",
		"AUTHGO_E2E_STORE_DIR": storeDir,
	}

	envA := make(map[string]string, len(commonStore)+1)
	for k, v := range commonStore {
		envA[k] = v
	}
	envA["AUTHGO_E2E_LOCK_DIR"] = lockDirA

	envB := make(map[string]string, len(commonStore)+1)
	for k, v := range commonStore {
		envB[k] = v
	}
	envB["AUTHGO_E2E_LOCK_DIR"] = lockDirB

	release, stalled := srv.StallNextRefresh()
	t.Cleanup(release)

	// Spawn A in background so the parent can continue while A is stalled.
	var outA bytes.Buffer
	cmdA := spawnHelper(t, "refresh-once", envA, &outA)
	if err := cmdA.Start(); err != nil {
		t.Fatalf("start A: %v", err)
	}

	// Wait for A's request to be definitively inside the stall wait before
	// spawning B. The stalled channel closes the moment A's goroutine enters
	// <-stallCh, so this is a precise synchronisation point with no sleep.
	select {
	case <-stalled:
		// A's request is now blocked on the stall channel — safe to spawn B.
	case <-time.After(2 * time.Second):
		t.Fatal("helper A did not enter the stall within 2s")
	}

	// Spawn B and wait for it to finish. B is not stalled (one-shot consumed by A).
	// B consumes RT_orig → gets RT_new1 → persists to shared fileStore.
	var outB bytes.Buffer
	cmdB := spawnHelper(t, "refresh-once", envB, &outB)
	if err := cmdB.Run(); err != nil {
		t.Fatalf("B: %v\n%s", err, outB.String())
	}
	resB, err := decodeHelperOutput(outB.String())
	if err != nil {
		t.Fatalf("decode B: %v", err)
	}

	// Release stall, wait for A.
	release()
	if err := cmdA.Wait(); err != nil {
		t.Logf("A exit: %v (decoded result will confirm OK)", err)
	}

	resA, err := decodeHelperOutput(outA.String())
	if err != nil {
		t.Fatalf("decode A: %v\nraw: %s", err, outA.String())
	}

	// With lax idempotency, A's grant returns RT_new1 idempotently —
	// no retry fires, both helpers succeed.
	if !resA.OK {
		t.Fatalf("helper A not OK: %s", resA.Error)
	}
	if resA.AccessToken == "" {
		t.Fatal("helper A returned empty access token")
	}
	if !resB.OK {
		t.Fatalf("helper B not OK: %s", resB.Error)
	}
	if resB.AccessToken == "" {
		t.Fatal("helper B returned empty access token")
	}

	// Both grants succeeded (one fresh consume, one idempotent replay).
	if got := srv.RefreshGrantCount(); got != 2 {
		t.Fatalf("RefreshGrantCount = %d, want 2 (B's fresh + A's idempotent replay)", got)
	}
	// No retry — A succeeded on first attempt.
	if got := srv.GrantCount(); got != 2 {
		t.Fatalf("GrantCount = %d, want 2 (no retry on A's path)", got)
	}
	// Family must not be revoked (idempotency window absorbed the replay).
	if srv.FamilyRevoked(seed.FamilyID) {
		t.Fatal("family was revoked, want not revoked (lax IdempotencySuccessor=5s)")
	}

	// Final store state: RT_new1 (B persisted it; A's merge is a no-op
	// since the store already carries RT_new1).
	stored, err := parentStore.LoadTokens(srv.URL())
	if err != nil {
		t.Fatalf("LoadTokens: %v", err)
	}
	if stored.RefreshToken == seed.RefreshToken {
		t.Fatal("stored RT == seed.RefreshToken; expected RT_new1 from B's rotation")
	}
}
