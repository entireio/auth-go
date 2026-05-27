# auth-go refresh tier — design (COR-314)

**Status:** Approved direction — ready for implementation plan
**Date:** 2026-05-27
**Linear:** [COR-314](https://linear.app/entirehq/issue/COR-314/auth-go-refresh-tier-persist-refresh-refresh-token-grant-single-flight) · Auth project · milestone *Three-tier session model*
**Consolidated design:** [Auth & Session Architecture](https://linear.app/entirehq/document/auth-and-session-architecture-consolidated-design-ed2aafdf4413)

---

## Goal

Add the **refresh tier** to auth-go so a CLI built on it silently re-mints
its login JWT from a stored refresh token, re-prompting login only when the
refresh token itself is revoked or expired (≈14d) rather than at login-JWT
expiry (≈8h).

Three sub-deliverables from the issue:

1. **Persist the refresh token** in the BYO `Store`.
2. **`refresh_token` grant** (RFC 6749 §6) — re-mint the login JWT.
3. **Single-flight + rotation-race tolerance** — one in-flight re-mint per
   process and across processes; recover gracefully from concurrent rotation.

### Non-goals

- **No server-side work.** The idempotent-successor rotation window is
  entire-core's responsibility (Security Control #3 in the consolidated
  design). This SDK only does client-side single-flight + race recovery.
- **No narrowing-grant changes.** `token-exchange` (`sts`) stays as-is.
- **No re-implementation of persistence (#1).** The reference `Store`
  already round-trips the full `TokenSet` including the refresh token
  (`tokenstore/keyring.go`, `tokenmanager.SaveCoreToken`). The issue text
  ("the reference `Store` drops it") is stale. We lock the behaviour in
  with a round-trip regression test rather than rebuilding it.

---

## Where the refresh token lives

No separate store. The refresh token is a field on `tokens.TokenSet`,
persisted in the **same** `Store` entry as the login JWT, keyed by the
`Issuer` profile string. The reference `tokenstore.Keyring` JSON-encodes
the whole set (`access_token` + `refresh_token` + `token_type` +
`expires_at` + `scope`) into one OS-keyring entry per profile (encrypted at
rest). A successful refresh writes the rotated refresh token back to that
same entry, overwriting the consumed one. BYO stores choose their own
at-rest protection; the `Store` contract only requires round-tripping the
`TokenSet`.

The cross-process lock file holds **no credentials** — it is a zero-byte
advisory `flock` file. The refresh token never touches the filesystem in
plaintext.

---

## Component layout

| Component | Status | Responsibility |
|---|---|---|
| `refresh/` | new pkg | RFC 6749 §6 `refresh_token` grant client — peer of `sts`/`deviceflow` |
| `internal/proclock/` | new pkg | Cross-process advisory lock over `golang.org/x/sys` (`flock(2)` unix / `LockFileEx` windows), build-tagged |
| `tokenmanager` | extended | New `Config` fields; `ProcessLock` interface; transparent refresh in `Token()`; exported `Refresh()`; orchestration + test seams |
| `internal/oauthhttp` | extended | Hosts the shared `client_id` validation + Basic-auth escaping lifted out of `sts` |
| `tokenstore`, `tokens` | unchanged | Persistence already round-trips the full `TokenSet` |

---

## 1. `refresh` package

Mirrors `sts.Client` in construction, timeout policy, insecure-HTTP gating,
the `now` test seam, and `internal/oauthhttp` reuse.

```go
type Client struct {
    Transport         http.RoundTripper
    BaseURL, Path     string
    UserAgent         string
    RequestTimeout    time.Duration
    AllowInsecureHTTP bool
    // unexported now-override (atomic.Pointer), set via SetNowForTest
}

func New(c *Client) (*Client, error) // validates BaseURL, Path

type Request struct {
    RefreshToken string
    ClientID     string
    Scope        string     // optional; RFC 6749 §6 allows narrowing. Omitted when empty.
    Extra        url.Values // form passthrough, e.g. client_id in the body
}

func (c *Client) Refresh(ctx context.Context, req Request) (*tokens.TokenSet, error)
```

**Wire request** (`application/x-www-form-urlencoded`):

- `grant_type=refresh_token`
- `refresh_token=<rt>`
- `client_id=<id>` (form body)
- `scope=<scope>` when non-empty
- `client_id` **also** on HTTP Basic auth (username component), matching
  `sts` — entire-core/zitadel reads client credentials from `r.BasicAuth()`
  on the token grants. Both surfaces populated, same value.

**Response** → `tokens.TokenSet{AccessToken: <new login JWT>, RefreshToken:
<rotated>, TokenType, Scope, ExpiresAt}`. `expires_in` is **optional** here
(unlike `sts.Exchange`, which rejects non-positive): the login JWT carries
its own `exp` claim, so we follow `deviceflow.PollDeviceAuth`'s tolerant
handling — absolute `ExpiresAt` derived from `expires_in` when positive,
left zero otherwise.

**Errors:** `invalid_grant` maps to exported sentinel
`refresh.ErrInvalidGrant` so `tokenmanager` can branch on it for
rotation-race recovery. Other OAuth error codes are wrapped via
`oauthhttp.ReadOAuthError` + `SanitizeDescription`, same as `sts`.
`ErrInsecureBaseURL` / `ErrAbsolutePath` re-exported from `oauthhttp`.

**Redaction:** `Request.String()`/`GoString()` elide `RefreshToken` via
`tokens.ElideSecret`.

### Shared `client_id` helper (in-scope cleanup)

The VSCHAR/`:` validation and Basic-auth `url.QueryEscape` rules currently
live privately in `sts` (`validateClientID`, the `SetBasicAuth` escaping).
Lift them into `internal/oauthhttp` so `refresh` and `sts` share one
implementation. This continues the v0.3.4 "centralise OAuth HTTP helpers"
direction rather than copy-pasting byte-level checks into a second package.
`sts` is refactored to call the shared helper; behaviour unchanged (covered
by existing `sts` tests).

---

## 2. `internal/proclock` package + `ProcessLock` interface

The consumer (`tokenmanager`) defines the interface:

```go
// tokenmanager
type ProcessLock interface {
    // Acquire blocks until the lock is held or ctx is done. The returned
    // release func is idempotent and must be called to release.
    Acquire(ctx context.Context) (release func(), err error)
}
```

Default implementation in `internal/proclock`:

```go
func New(path string) *FileLock
func (l *FileLock) Acquire(ctx context.Context) (func(), error)
```

- `flock(LOCK_EX)` on unix, `LockFileEx` on windows — build-tagged files
  (`lock_unix.go` / `lock_windows.go`) over `golang.org/x/sys`.
- **Cancellable:** `Acquire` uses non-blocking `LOCK_NB` in a poll loop with
  short backoff so it can honour `ctx` cancellation/deadline (plain blocking
  `flock` cannot be interrupted by ctx). A bounded max-wait guards against a
  wedged holder.
- **Lock path:** `filepath.Join(LockDir, sha256hex(ClientID + "\x00" +
  Issuer) + ".lock")`. Keyed on the `(ClientID, Issuer)` identity that
  scopes the credential, so unrelated CLIs sharing an issuer do not
  serialize against each other. (`tokenmanager` doesn't know the keyring
  `Service`, so `ClientID` is the CLI-identifying component it does have.)
- Lock file created lazily, mode `0600`, **never deleted** (delete-on-unlock
  races the next acquirer for the inode).

---

## 3. `tokenmanager` integration

### Config additions

```go
// RefreshPath is the token-endpoint path where grant_type=refresh_token is
// POSTed. Optional; when empty and a refresh is needed, the refresh path
// returns ErrNoRefreshPath rather than POSTing to a bogus URL. Mirrors
// STSPath / ErrNoSTSPath. Often equal to STSPath or the device-flow
// TokenPath, since servers typically multiplex grants at one /oauth/token.
RefreshPath string

// LockDir is the directory for the cross-process advisory lock file.
// Empty → os.UserCacheDir()/auth-go.
LockDir string
```

### `Token()` change

Load the **full** `TokenSet` (not just the access-token string), then:

- no entry → `ErrNotLoggedIn`
- login JWT live (`!coreTokenExpired`) → use it; existing shortcut/exchange
  path unchanged
- login JWT expired-or-near-expiry **and** `HasRefresh()` → run the refresh
  orchestration, then continue the shortcut/exchange path with the new login
  JWT
- expired **and** no refresh token → `ErrNotLoggedIn` (legacy login; current
  behaviour preserved)

The expiry check reuses the existing `coreTokenExpired` + `exchangeSkew`
(30s) so the refresh threshold and the cache threshold stay in sync.

### Exported `Refresh()`

```go
// Refresh ensures a fresh login JWT, re-minting from the stored refresh
// token if the current one is expired or near expiry. Returns the live
// login JWT (current or freshly minted). ErrNotLoggedIn if no credential is
// stored; ErrReauthRequired if the refresh token is revoked/expired.
func (m *Manager) Refresh(ctx context.Context) (string, error)
```

Lets callers warm the session at startup and surface re-login UX before the
first data call. Idempotent when already fresh (cheap store read, no grant).

---

## 4. Orchestration (Approach A — serialize-and-double-check)

`ensureFreshLogin(ctx)` is the shared core behind both `Token()`'s
auto-refresh branch and exported `Refresh()`:

```
# fast path — no locks
set = loadSet()
if absent:                      return "", ErrNotLoggedIn
if !expired(set.AccessToken):   return set.AccessToken, nil
if !set.HasRefresh():           return "", ErrNotLoggedIn

m.refreshMu.Lock()                         # in-process gate
    set = loadSet()                        # goroutine double-check
    if !expired: unlock; return token
    if !HasRefresh: unlock; return ErrNotLoggedIn

    release = processLock.Acquire(ctx)     # cross-process gate
        set = loadSet()                    # process double-check
        if !expired: release; unlock; return token
        if !HasRefresh: release; unlock; return ErrNotLoggedIn

        token, err = doRefresh(ctx, set)
    release()
m.refreshMu.Unlock()
return token, err
```

The re-read after each gate **is** the single-flight: the second waiter does
a cheap store read instead of a redundant network re-mint. A plain mutex
gives in-process coalescing with no new dependency; the same double-check
pattern repeats identically at the cross-process level.

### `doRefresh(ctx, set)` — rotation-race tolerance

```
sent = set.RefreshToken
res, err = runRefresh(ctx, sent)

if err == nil:
    persist(merge(set, res))               # §5; SaveCoreToken clears exchange cache
    return res.AccessToken, nil            # new login JWT

if errors.Is(err, refresh.ErrInvalidGrant):
    cur = loadSet()
    if cur.HasRefresh() and cur.RefreshToken != sent:
        # a non-cooperating actor rotated under us — retry ONCE with new RT
        res, err = runRefresh(ctx, cur.RefreshToken)
        if err == nil:
            persist(merge(cur, res))
            return res.AccessToken, nil
    return "", ErrReauthRequired           # genuine revoke/expiry

return "", err                             # network/5xx/other — never reauth
```

- Retry bounded to **1**.
- **No credential deletion on terminal failure.** A transient server hiccup
  misread as `invalid_grant` must not wipe the keyring; the expired
  login JWT + dead refresh token simply keep returning `ErrReauthRequired`
  until the next login overwrites them.
- `runRefresh` dispatches to the test override (if set) else builds a
  `refresh.Client` from `Issuer` + `RefreshPath`; `ErrNoRefreshPath` when
  `RefreshPath` is empty and no override is set (mirrors `runExchange` /
  `ErrNoSTSPath`).
- The process lock is held across the grant + persist, so cooperating
  processes can't rotate concurrently; the re-read on `invalid_grant` is the
  safety net for non-cooperating actors (other CLIs, browser tabs) and
  pairs with entire-core's idempotent-successor window.

---

## 5. Persistence merge semantics

```
merge(prev, res):
    out = res                              # new AccessToken, ExpiresAt, TokenType
    if res.RefreshToken == "": out.RefreshToken = prev.RefreshToken
    if res.Scope == "":        out.Scope = prev.Scope
    return out
```

Guards a **non-rotating** server (empty `refresh_token` in the response)
from wiping a still-valid refresh token. Persisted via `SaveCoreToken`,
which already clears the in-process exchange cache — so the next `Token()`
re-exchanges against the new login JWT rather than serving a stale entry
keyed to the old core hash.

---

## 6. Errors

| Sentinel | Package | Meaning |
|---|---|---|
| `ErrReauthRequired` | `tokenmanager` | refresh genuinely exhausted (revoked/expired) — distinct from never-logged-in, for UX + telemetry |
| `ErrNoRefreshPath` | `tokenmanager` | refresh needed but `Config.RefreshPath` empty |
| `ErrInvalidGrant` | `refresh` | `invalid_grant` from the grant; branched on for rotation-race recovery |
| `ErrNotLoggedIn` | `tokenmanager` | unchanged — no credential, or expired without a refresh token |

---

## 7. Test seams + strategy (TDD)

New `atomic.Pointer` seams mirroring `SetExchangeForTest`:

- `SetRefreshForTest(t, m, fn func(context.Context, refresh.Request) (*tokens.TokenSet, error))`
- `SetProcessLockForTest(t, m, lock ProcessLock)`

**`tokenmanager` unit tests** (deterministic — in-memory `Store`, fake
clock, fake refresh fn, fake `ProcessLock` recording acquire/release; no
real files or network):

- transparent refresh: expired login JWT + refresh token → re-mints,
  persists, `Token()` proceeds
- expired + no refresh token → `ErrNotLoggedIn`
- no entry → `ErrNotLoggedIn`
- happy rotation: rotated RT persisted, old RT overwritten
- **double-check coalescing:** two goroutines hit expired token, exactly one
  grant fires, both get the fresh token (assert via fake-fn call count)
- rotation-race retry: fake fn returns `invalid_grant`, store pre-rotated by
  a simulated "other process" → retry with new RT succeeds
- terminal `invalid_grant` (RT unchanged) → `ErrReauthRequired`, creds NOT
  deleted
- network error from grant → wrapped, NOT classified as reauth
- non-rotating server (empty `refresh_token` in response) → prior RT retained
- exchange cache cleared after refresh
- `RefreshPath` empty + refresh needed → `ErrNoRefreshPath`
- exported `Refresh()`: fresh token → no grant; expired → re-mints
- regression: full `TokenSet` (incl. refresh token) round-trips through
  `SaveCoreToken` → `Store` → reload (locks in sub-deliverable #1)

**`refresh` package tests** (httptest, mirroring `sts_test.go`): success +
rotation; `invalid_grant` → `ErrInvalidGrant`; other OAuth error decoding;
`RefreshToken` redaction; insecure-HTTP rejection; both client-id surfaces
present on the wire; tolerant `expires_in` handling.

**`internal/proclock` tests:** one real-file integration test — concurrent
acquirers are mutually exclusive; `Acquire` returns when `ctx` is cancelled
while blocked.

---

## 8. CHANGELOG / docs

`## Unreleased` entries (per project CLAUDE.md, same PR):

- new `refresh` package (RFC 6749 §6 grant client)
- `tokenmanager`: transparent login-JWT refresh in `Token()`; exported
  `Refresh()`; new `Config.RefreshPath` and `Config.LockDir`
- new sentinels `ErrReauthRequired`, `ErrNoRefreshPath`, `refresh.ErrInvalidGrant`
- `golang.org/x/sys` promoted from indirect to direct dependency

Update `doc.go` package list to include `refresh`.

---

## Open items resolved during design

- **Trigger:** transparent in `Token()` **and** exported `Refresh()`.
- **Grant home:** new `refresh` package (peer of `sts`/`deviceflow`).
- **File lock:** hand-rolled `flock` over `golang.org/x/sys`; no new
  third-party direct dependency.
- **Terminal error:** new `ErrReauthRequired` sentinel.
- **Lock wiring:** injectable `ProcessLock` interface, file-based default,
  path auto-derived (overridable via `Config.LockDir`), test seam swaps a fake.
- **Orchestration:** Approach A (serialize-and-double-check).
