# auth-go refresh-tier e2e harness — design (COR-343)

**Status:** Approved direction (Scope B + `internal/testoauth`)
**Date:** 2026-05-28
**Linear:** [COR-343](https://linear.app/entirehq/issue/COR-343/auth-go-refresh-tier-e2e-harness-mock-oauth-server-cross-process-tests) · Auth project · milestone *v1 build*
**Stacked on:** [COR-314](https://linear.app/entirehq/issue/COR-314/auth-go-refresh-tier-persist-refresh-refresh-token-grant-single-flight) (PR [#10](https://github.com/entireio/auth-go/pull/10)) — branch `alex/cor-343-auth-go-refresh-tier-e2e-harness` is cut off the head of `alex/cor-314-...` and rebases onto `main` once COR-314 merges.

---

## Goal

Close the test-coverage gaps left by COR-314's unit/component tests. A
credential-management library with concurrency this subtle needs more than
bespoke `httptest` mocks per package. Specifically:

- **Real cross-process `flock` semantics.** `internal/proclock` is currently
  tested with goroutines in one process — the whole *point* of the lock is
  cross-process serialisation.
- **Cross-process logout/login vs in-flight refresh.** The race Codex's
  adversarial review flagged on PR #10 was about subprocess A's `cli logout`
  racing subprocess B's daemon refresh. Our fix-A regression test is
  in-process.
- **Composed Manager flow.** Each package has its own `httptest` mock today;
  nothing exercises `Token() → ensureFreshLogin → refresh grant → persist →
  exchange` as one composition against a single conformant server.
- **Server-side rotation reuse-detection.** We assert `invalid_grant` from
  servers we control as a fixed response — no test exercises actual
  RFC 9700 replay → family revocation.

### Non-goals

- Real-keyring tests in CI. (Tag-gated for local manual runs only.)
- Latency injection / hostile-server chaos. (Deferred unless a specific risk surfaces.)
- Integration against a real provider (entire-core, zitadel docker image).
  That coupling belongs in the consuming CLI (entire-cli); auth-go stays
  provider-agnostic.

---

## Component layout

| Path | Status | Responsibility |
|---|---|---|
| `internal/testoauth/server.go` | new | `httptest.Server` implementing `/oauth/token` (refresh, token-exchange, device-code grants) + `/oauth/device_authorization`. Internal family/rotation/reuse-detection state. |
| `internal/testoauth/family.go` | new | Refresh-family bookkeeping: rotation chain, consumed-token set, optional idempotent-successor window, family revocation on replay. |
| `internal/testoauth/jwt.go` | new | Mint test JWTs (header+payload+junk sig) with caller-specified `iss`/`aud`/`exp`/`sub`/`fid`. Reusable; produces tokens `tokens.ParseClaims` accepts. |
| `internal/testoauth/server_test.go` | new | Unit tests for the server primitive itself (so failures localise). |
| `tokenmanager/e2e_test.go` | new | Composed-flow tests against `testoauth.Server`. Single-process scenarios. |
| `tokenmanager/e2e_subprocess_test.go` | new | Cross-process tests via the standard `os.Args[0]` self-re-exec pattern. Includes `TestMain` sentinel dispatch and the helper-process bodies. |

`testoauth` lives under `internal/` deliberately — not exported, can't be
mistaken for a production fixture by downstream callers. Consumers needing
their own mock build their own (or we re-evaluate exporting later).

---

## 1. `internal/testoauth` — mock OAuth server

### Public surface

```go
// Server is a test OAuth authorization server. Wraps httptest.Server and
// maintains in-memory state for refresh families, consumed tokens, and
// device-flow sessions. Construct with NewServer; close via t.Cleanup.
type Server struct { /* unexported state */ }

// Config configures a Server. All fields are optional.
type Config struct {
    // Issuer is the iss claim minted into JWTs. Defaults to the server URL.
    Issuer string

    // LoginJWTTTL is the access_token (login JWT) lifetime.
    // Defaults to 5 minutes (short enough that tests can advance clocks
    // realistically without burning wall time).
    LoginJWTTTL time.Duration

    // RefreshTokenTTL is the wire-level expires_in on refresh responses
    // (the refresh token itself is opaque so this is informational; the
    // family's lifetime is governed by rotation/replay).
    RefreshTokenTTL time.Duration

    // IdempotencySuccessor, when non-zero, returns the already-issued
    // successor RT for a consumed RT replayed within this window — the
    // RFC 9700 hardened-rotation pattern. Defaults to 0 (strict reuse
    // detection: any replay revokes the family).
    IdempotencySuccessor time.Duration

    // Now is the server's clock; defaults to time.Now. Tests can pin it.
    Now func() time.Time
}

func NewServer(t testing.TB, cfg Config) *Server
func (s *Server) URL() string
func (s *Server) Close()

// Family-management for tests. SeedFamily creates a fresh family with a
// known refresh token and returns (initial login JWT, refresh token, fid).
// Tests use this to skip the device-code login when the goal is to
// exercise refresh paths.
func (s *Server) SeedFamily(sub string, aud []string) SeededLogin

type SeededLogin struct {
    LoginJWT     string
    RefreshToken string
    FamilyID     string
}

// Inspection helpers — tests assert on these rather than the wire.
func (s *Server) GrantCount() int               // total successful /oauth/token responses
func (s *Server) RefreshGrantCount() int        // refresh_token grants only
func (s *Server) ExchangeGrantCount() int       // token-exchange grants only
func (s *Server) FamilyRevoked(fid string) bool // true if reuse-detection fired

// Force-error injection for failure-path tests. Returns a "release"
// function to remove the override.
type FailureMode int
const (
    FailNone FailureMode = iota
    FailInvalidGrant
    FailNetworkError // server closes the connection mid-response
)
func (s *Server) ForceNextRefresh(mode FailureMode) (release func())
```

### Wire behaviour — `/oauth/token`

| `grant_type` | Handling |
|---|---|
| `refresh_token` | Resolve RT to a family. If RT is **active** → consume, mint new login JWT (TTL=LoginJWTTTL), mint successor RT, mark old RT consumed, return both. If RT is **consumed** and within `IdempotencySuccessor` window → return the already-issued successor idempotently. If **consumed** outside the window OR family already revoked → `400 invalid_grant`, **revoke the entire family** (RFC 9700 reuse detection). |
| `urn:ietf:params:oauth:grant-type:token-exchange` | Validate subject_token claims (iss matches, fid resolves to a live family, aud allowed), mint short-lived access JWT with `aud` from `resource`/`audience` param. Returns `expires_in=300`. |
| `urn:ietf:params:oauth:grant-type:device_code` | Resolve device_code; once "approved" (test-driver call), return login JWT + RT for the synthesised family. |

`/oauth/device_authorization` returns a `DeviceCode` with a short polling
interval and a test-driver method to "approve" it.

### Family bookkeeping (`family.go`)

```go
type family struct {
    id       string
    sub      string
    aud      []string
    revoked  bool

    mu       sync.Mutex
    chain    []rotationEntry // active + consumed RTs, newest last
}

type rotationEntry struct {
    refreshToken string
    consumedAt   time.Time // zero if still active
    successor    string    // empty until rotated
}
```

Concurrency: `family.mu` guards the chain; the server itself holds a
top-level `sync.Mutex` for the `families`/`rts → family` indices to keep
the implementation small.

### JWT helper (`jwt.go`)

```go
type Claims struct {
    Issuer   string
    Subject  string
    Audience []string
    FamilyID string         // fid claim
    ExpiresAt time.Time
    NotBefore time.Time
    IssuedAt  time.Time
    Extra     map[string]any // custom claims
}

// MintUnsignedJWT returns a header.payload.junk-sig string matching the
// shape tokens.ParseClaims accepts. alg is "EdDSA" (matching the
// production format); signature is intentionally invalid because
// tokens.ParseClaims is unverified-by-design.
func MintUnsignedJWT(c Claims) string
```

---

## 2. Composed-flow tests — `tokenmanager/e2e_test.go`

In-process tests using a real `testoauth.Server` (no per-package mocks).
Each test constructs a `Manager` whose `Issuer` is the server URL,
`RefreshPath` = `STSPath` = `/oauth/token`, with `AllowInsecureHTTP: true`
(the `httptest.Server` is plain HTTP on loopback) and `LockDir = t.TempDir()`.

Test list:

1. **`TestE2E_RefreshOnExpiredJWT`** — seed family, store seeded TokenSet
   under Issuer, fast-forward `m.now()` past `LoginJWTTTL`, call
   `m.TokenForResource(...)` against a resource that requires exchange,
   assert: refresh fires once (server `RefreshGrantCount == 1`), exchange
   fires (server `ExchangeGrantCount == 1`), persisted TokenSet has the
   rotated RT.

2. **`TestE2E_SilentRefreshIsTransparent`** — same setup, then advance clock
   again past the next expiry, assert second refresh fires and the cache
   correctly invalidates between refreshes.

3. **`TestE2E_RotationReuseDetection`** — seed family, do one refresh (RT
   rotates to RT2), then directly POST the original RT1 to the server
   (bypassing `tokenmanager`) → server returns `invalid_grant` AND marks
   family revoked. Now call `m.Refresh()` (which tries with RT2): server
   returns `invalid_grant` (family is dead), `m.Refresh` returns
   `ErrReauthRequired`, credential NOT deleted from store.

4. **`TestE2E_IdempotencySuccessor`** — configure `IdempotencySuccessor: 1s`,
   directly POST RT1 twice in quick succession; second call gets the same
   successor idempotently rather than revoking the family. Pins that
   `tokenmanager`'s in-process single-flight + this server-side window
   together absorb a rotation race without breakage. (Not a Manager test —
   exercises the server's contract directly.)

5. **`TestE2E_GoroutineCoalescingAgainstRealServer`** — 8 goroutines call
   `m.TokenForResource(...)` simultaneously against an expired JWT; assert
   `RefreshGrantCount == 1` and `ExchangeGrantCount` matches the resource
   count (typically 1 with cache).

---

## 3. Cross-process tests — `tokenmanager/e2e_subprocess_test.go`

Standard Go subprocess pattern. `TestMain` checks `AUTHGO_E2E_HELPER` env
var; when set, dispatches to a helper-mode body that constructs a Manager
from env-passed config (server URL, LockDir, ClientID, Issuer, seeded
TokenSet JSON, action to perform) and exits with a meaningful status.

```go
func TestMain(m *testing.M) {
    if mode := os.Getenv("AUTHGO_E2E_HELPER"); mode != "" {
        runHelper(mode)  // never returns
    }
    os.Exit(m.Run())
}

func spawnHelper(t *testing.T, mode string, env ...string) *exec.Cmd {
    cmd := exec.Command(os.Args[0], "-test.run", "TestE2E_DummyEntryPoint", "-test.v=false")
    cmd.Env = append(os.Environ(), "AUTHGO_E2E_HELPER="+mode)
    cmd.Env = append(cmd.Env, env...)
    return cmd
}
```

Helper modes (each is a small `runHelper_*` function):

- `refresh-once` — load seeded creds from env, call `m.Refresh(ctx)`, print
  resulting AccessToken to stdout, exit 0 / nonzero on error.
- `logout` — call `m.DeleteCoreToken()`, exit.
- `relogin` — `m.SaveCoreToken(newSet)`, exit.
- `refresh-blocking` — call refresh against a server endpoint that
  intentionally stalls (via a test-driver-controlled gate), to let the
  parent observe a real in-flight grant.

Test list:

1. **`TestE2ESub_CrossProcessSingleFlight`** — two helper subprocesses call
   `refresh-once` against the same server + same `LockDir` simultaneously.
   Assert exactly one `RefreshGrantCount` increment on the server. Both
   subprocesses exit 0 with the same final AccessToken in their stdout
   (one minted it, the other read it back from the store after the lock
   serialised them).

2. **`TestE2ESub_CrossProcessLogoutWinsOverInFlightRefresh`** — subprocess A
   runs `refresh-blocking` against a stalled server, parent waits for the
   stall, subprocess B runs `logout`, parent releases the stall. Assert B
   blocks until A completes (measurable by timing — B's exit time is after
   the stall release), and the final store is empty (logout wins as the
   later-acquiring writer). This is the *cross-process* version of fix A's
   in-process test.

3. **`TestE2ESub_CrossProcessReloginWinsOverInFlightRefresh`** — same shape
   with `relogin` instead of `logout`. Final store has the new user.

4. **`TestE2ESub_ProclockMutualExclusion`** — pure proclock test, no
   OAuth server. Two subprocesses repeatedly `Acquire` the same path with
   tiny holds and a shared counter file; assert `max-concurrent` never
   exceeds 1 across N rounds.

> Subprocess tests are gated by `-short`: `if testing.Short() { t.Skip(...) }`,
> so `go test -short ./...` stays fast for inner-loop development. CI runs
> without `-short`.

---

## 4. Concurrency and cleanup

- The `testoauth.Server` is goroutine-safe — its handlers run concurrently
  inside `httptest.Server`.
- Subprocesses share a `LockDir` (parent-provided `t.TempDir()`); the
  parent ensures cleanup via `t.Cleanup`.
- Helper subprocesses get their `Context` deadline from a parent-passed
  env var so the parent can bound their lifetime; helpers respect ctx
  cancellation and exit on parent's `cmd.Cancel()` if needed.

---

## 5. Errors / failure modes

The server's `ForceNextRefresh(FailInvalidGrant)` lets tests provoke a
deterministic `invalid_grant` without depending on internal state
manipulation. `FailNetworkError` closes the response mid-write to exercise
the transport-error-on-retry path that `TestDoRefresh_RotationRaceRetryTransportErrorNotReauth`
asserts in-process — now validated against a real socket.

---

## 6. Test seams + clock

`testoauth.Server` accepts `Config.Now` for clock injection — tests pin
time so JWT expiry is deterministic. The Manager's `SetNowForTest` is used
in tandem so the server's "now" and the Manager's "now" stay in sync.

---

## 7. CHANGELOG / docs

The harness is test-only — no CHANGELOG entry required. README gets a
small "Testing" subsection pointing at the e2e tests as the source-of-
truth for the Manager's composed flow.

---

## 8. Open items resolved

- **Scope:** B (mock server + composed-flow tests + cross-process tests).
- **Mock server location:** `internal/testoauth` (not exported).
- **Subprocess pattern:** Go's standard `os.Args[0]` self-re-exec with
  env-var dispatch from `TestMain`.
- **Real keyring / chaos / docker-zitadel:** out of scope; tracked separately if needed.

---

## Effort estimate

~2–3 days end to end:

- `internal/testoauth` server + family + JWT helper + its own tests: ~1.5 days
- `tokenmanager/e2e_test.go` composed-flow tests: ~0.5 day
- `tokenmanager/e2e_subprocess_test.go` + `TestMain` dispatch: ~0.5–1 day (subprocess tests are fiddly the first time)
- Review iteration: rolled into the above
