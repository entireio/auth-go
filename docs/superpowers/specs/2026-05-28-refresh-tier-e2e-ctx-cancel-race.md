# auth-go refresh-tier e2e: ctx-cancel + cross-process race — design (COR-345)

**Status:** Approved direction (Test 1 + 2a + 2b — full scope)
**Date:** 2026-05-28
**Linear:** [COR-345](https://linear.app/entirehq/issue/COR-345) · Auth project · milestone *v1 build*
**Stacked on:** [COR-343](https://linear.app/entirehq/issue/COR-343) (PR [#12](https://github.com/entireio/auth-go/pull/12)). Branched off the head of `alex/cor-343-...` so the work builds on the harness; rebases onto main when COR-343 merges.

---

## Goal

Close the two highest-value e2e gaps left after COR-343, both involving production paths the existing harness doesn't exercise. Three new tests, all in `tokenmanager/e2e_subprocess_test.go`.

### What we are NOT testing (and why)

`doRefresh`'s "first grant fails, **retry succeeds** with the new RT" branch is **not reachable** against a well-behaved RFC 9700 server. Tracing through the server's family state machine:

- **Outside the idempotency window**, replaying a consumed RT revokes the family. The successor RT is then also dead. Retry with the new RT fails too → `ErrReauthRequired`.
- **Within the window**, the server returns the already-issued successor idempotently. The first grant succeeds; the retry path never fires.

The branch is defensive code for a server that decouples per-RT invalidation from family state — a posture RFC 9700 explicitly rules out. The existing unit test (`TestDoRefresh_RotationRaceRetriesWithNewRT`) exercises it with a fake refresh fn that arbitrarily decouples grant outcome from family state; that remains the only place to test it.

What IS testable end-to-end and what these tests assert is below.

---

## Component layout

All work in `tokenmanager/e2e_subprocess_test.go` plus one new helper mode. No changes to `internal/testoauth` or production code.

| Addition | Responsibility |
|---|---|
| `helperRefreshWithTimeout` | New helper mode (`refresh-with-timeout`): runs `m.Refresh` with a caller-controlled `context.WithTimeout`. Used by Test 1 to provoke ctx cancellation mid-grant. |
| `helperRefreshOnce` (existing) | Used by Test 2a/2b unchanged. |
| `TestE2ESub_CtxCancelReleasesLocks` | Test 1. |
| `TestE2ESub_NonCooperatingRaceStrictRevokes` | Test 2a (strict reuse-detection). |
| `TestE2ESub_NonCooperatingRaceLaxAbsorbs` | Test 2b (idempotency window). |

---

## Test 1 — `TestE2ESub_CtxCancelReleasesLocks`

**Scenario:** A CLI invocation that gets Ctrl+C'd while a refresh is in flight. The grant is mid-flight (stalled at the server); the helper's context times out; the refresh returns; the helper exits. Then a second helper attempts a fresh refresh — must succeed quickly (proves the proclock was released cleanly, not held until the 30s default-acquire timeout).

**Parent setup:**
- One `testoauth.Server` (real wall-clock — no pinned date).
- One shared `fileStore` + shared `LockDir`.
- Seed the store with `mintExpiredJWT` + a real seeded RT.
- `release := srv.StallNextRefresh()` (one-shot; defer release so the stalled goroutine is cleaned up even if the test fails).

**Helper A (`refresh-with-timeout` mode):**
- Reads config from env including `AUTHGO_E2E_CTX_TIMEOUT_MS=150`.
- Builds the Manager from env, constructs `ctx, cancel := context.WithTimeout(context.Background(), 150ms)`.
- Calls `m.Refresh(ctx)`. The grant stalls at the server; the ctx expires after 150ms; refresh returns wrapped `context.DeadlineExceeded` (or similar transport error).
- Helper writes its `helperResult` — `OK: errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context")`, plus the elapsed.
- Exits.

**Helper B (`refresh-once` mode, dispatched after A returns):**
- Standard refresh against the same store + LockDir.
- The parent releases the stall BEFORE dispatching B so the server's stall goroutine cleans up; B's grant proceeds normally.

**Parent assertions:**
- Helper A's result reports OK (the ctx error was the expected outcome) AND `ElapsedMs < 1000` (proves no 30s lock-acquire timeout fired — the cancel hit the right path).
- Helper B's result is OK with a non-empty AccessToken AND `ElapsedMs < 2000` (proves the proclock was free for B; if A had orphaned the lock, B would wait ~30s).
- `srv.RefreshGrantCount() == 1` (only B's grant succeeded; A's grant errored out from the server's perspective when the client disconnected).
- Final store state: rotated RT (B's refresh succeeded, A's didn't persist anything).

**The lock-release proof** is the timing on B's elapsed: if the proclock weren't released by A's cancellation, B would either time out at 30s or, with shorter ctx, fail with a wrapped acquire-lock error. A sub-second elapsed for B proves the cleanup path fired.

---

## Test 2a — `TestE2ESub_NonCooperatingRaceStrictRevokes`

**Scenario:** Two processes both holding `RT_orig` (because they have separate, non-cooperating `LockDir`s but share a `fileStore`) attempt to refresh. With strict reuse-detection (`IdempotencySuccessor: 0`), the loser exercises `doRefresh`'s retry-then-fail path against a real server and surfaces `ErrReauthRequired`. **Validates the retry plumbing fires against real-server semantics, even though the outcome is reauth.**

**Parent setup:**
- `testoauth.Server` with `IdempotencySuccessor: 0` (strict).
- Shared `fileStore`. **Two distinct `LockDir`s** (this is the "non-cooperating actors" condition).
- Seed store with an EXPIRED login JWT + seeded RT (so both helpers trigger refresh on their first call).
- `release := srv.StallNextRefresh()`; defer release.

**Helper A (refresh-once):**
- Standard. Acquires LockDir-A's proclock, reads RT_orig, fires grant. Grant stalls.

**Helper B (refresh-once, dispatched while A is stalled at the server):**
- Different LockDir (LockDir-B). Acquires its own proclock immediately (no contention — different lock files). Reads RT_orig from the shared fileStore. Fires grant. Hits server.
- The server is currently stalled with A's request. We need to think about ordering carefully — see below.

**Race-ordering note (important):** The stall mechanism on testoauth.Server is *before* `family.Consume`, so A's grant has not yet mutated the family state when B's grant arrives. B's grant runs through the dispatch (not stalled, since `stallNext` is one-shot — A consumed it) and consumes RT_orig first if B arrives first; OR A consumes first when we release the stall.

For determinism, we want **A to consume first, then B**:
1. Parent calls `StallNextRefresh()` — sets the one-shot stall for the NEXT refresh request.
2. Spawn A. A's request hits server, pops the stall, blocks.
3. Wait ~100ms for A to be definitively stalled (synchronization via the server's `RefreshGrantCount` not yet incrementing, plus a brief sleep).
4. Spawn B. B's request hits server. Stall is consumed (one-shot) — B is not stalled. B proceeds through normal handling: `family.Consume(RT_orig)`. The family's `chain` has RT_orig active; B consumes it, gets RT_new1.
5. Parent releases stall. A's request resumes: `family.Consume(RT_orig)`. The chain entry for RT_orig is now consumed (B did it). With `IdempotencySuccessor: 0`: outside window → revoke family → return invalid_grant.
6. A's `doRefresh`: invalid_grant → re-read store → fileStore has... whatever B persisted. If B persisted, then `cur.RefreshToken == RT_new1 != RT_orig (sent)` → retry with RT_new1. Server: family revoked → invalid_grant. Retry fails → `ErrReauthRequired`.
7. A persists nothing.

Hmm wait — if B is NOT stalled and runs through normally, B's grant succeeds (gets RT_new1). B persists. B is the winner. A becomes the loser.

But actually order of operations in the parent: parent stalls, then spawns A, then waits, then spawns B. A consumes the stall (A is stalled). B is NOT stalled (stall is one-shot, consumed by A). B's request proceeds to consume RT_orig → succeeds → mints RT_new1 → returns. B's helper persists.

NOW parent releases the stall (which it does after B finishes, in this design). A's request unblocks. A calls `family.Consume(RT_orig)` — chain entry consumed by B, outside window → revoke → invalid_grant.

A's doRefresh: re-read → finds RT_new1 in store → retry with RT_new1. Server: family revoked → invalid_grant. A returns `ErrReauthRequired`. A's helper exits with that error reported.

**Parent assertions:**
- Helper A's result: error contains "reauthentication required" (matches `ErrReauthRequired`).
- Helper B's result: OK with non-empty AccessToken.
- `srv.RefreshGrantCount() == 1` (only B's success counts).
- `srv.GrantCount() == 3` (A's initial + B's success + A's retry — both A's attempts hit the handler).
- `srv.FamilyRevoked(seed.FamilyID) == true`.
- Final store state: B's persisted RT_new1 (A persisted nothing because both its attempts failed).

This proves the retry plumbing fires (`GrantCount == 3` means A's request hit the server's `/oauth/token` handler twice, exercising doRefresh's retry-with-cur.RefreshToken arm) — even though the outcome is reauth.

---

## Test 2b — `TestE2ESub_NonCooperatingRaceLaxAbsorbs`

**Scenario:** Same race as 2a, but with `IdempotencySuccessor: 5 * time.Second` (lax). The server's idempotency window absorbs A's replay → A's first grant returns RT_new1 idempotently (no retry). Both processes end up with the same successor. **Validates the Manager's first-attempt path harmonises with the server's idempotency window.**

**Parent setup:** Same as 2a, but `IdempotencySuccessor: 5*time.Second`.

**Helper sequence:** Identical to 2a (parent stalls, A stalls, B runs through, A unblocks, A's grant sent).

**Server-side on A's grant arrival:** `family.Consume(RT_orig, now, 5s)`. RT_orig is consumed (B did it < 5s ago) → within window → return RT_new1 idempotently. **Family is NOT revoked.**

**A's `doRefresh`:** First runRefresh returns SUCCESS with RT_new1. doRefresh persists merged(set, res) — but the store already has RT_new1 (from B's persist). The merge is a no-op for the RT. A returns RT_new1's access token.

**Parent assertions:**
- Both helper results: OK with non-empty AccessTokens.
- `srv.RefreshGrantCount() == 2` (both attempts succeeded — one fresh consume, one idempotent replay).
- `srv.GrantCount() == 2` (no retry — A's request succeeded on first attempt).
- `srv.FamilyRevoked(seed.FamilyID) == false`.
- Helper A's AccessToken `==` Helper B's AccessToken? **No** — A and B each minted access JWTs from the same family, but the JWTs themselves have different `iat` timestamps (or at least, are minted by separate handler invocations). They may differ.

  However, the persisted `RefreshToken` in the shared store should be RT_new1 in both cases (B persists RT_new1; A's merge over (cur=store-at-A's-persist-time, res={AT, RT_new1}) is unchanged since the store already has RT_new1).

- Final store state: RT_new1 (idempotent winner; A's "retry" was actually its first attempt succeeding idempotently).

This validates that the Manager doesn't trip on the idempotency-window path — both processes complete without error, and the server confirms no revocation.

---

## Implementation notes

### Helper sequencing (avoiding flakes)

The race tests need helper A to be **definitively stalled** at the server before helper B is spawned, otherwise the order of consume calls is non-deterministic. Use a wait-for-stall pattern:

```go
// After spawning A, poll srv.GrantCount() in the parent: it should
// increment once when A's request hits the handler, then stay flat
// (because A is stalled BEFORE the handler increments... actually
// totalGrants increments at the TOP of the handler, before the stall).
// So we poll for grant_count >= 1 with a short timeout.
//
// Alternative: use a sync channel from the stall itself. Cleanest is
// to extend StallNextRefresh to signal when the request enters the
// stall — but that's an additional API surface change. Polling
// GrantCount with a tight loop is simpler.
```

I'll have the implementer extend `testoauth.Server` with a small helper if polling proves flaky: `StallNextRefresh` could return both `release` and a `stalled <-chan struct{}` that closes when the request enters the stall. Cleaner than polling and avoids any timing assumption.

### Env vars added

- `AUTHGO_E2E_CTX_TIMEOUT_MS` — for `refresh-with-timeout` helper, sets the ctx timeout in ms. Default unset → use Background ctx.

### `helperRefreshWithTimeout` mode

```go
func helperRefreshWithTimeout() helperResult {
    m, _ := newHelperManager()
    timeoutMs, _ := strconv.Atoi(os.Getenv("AUTHGO_E2E_CTX_TIMEOUT_MS"))
    if timeoutMs <= 0 { timeoutMs = 150 }
    ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
    defer cancel()
    tok, err := m.Refresh(ctx)
    return helperResult{
        OK:          err != nil && (errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context")),
        AccessToken: tok,
        Error:       fmt.Sprintf("%v", err),
    }
}
```

Add to the `runHelper` switch.

### Test ordering inside the file

Place the three new tests after the existing `TestE2ESub_*` cluster, before any non-subprocess tests (matching the file's current structure).

---

## Effort estimate

~1.5 days end to end:

- Helper mode + parent test for ctx-cancel: ~0.5 day.
- Race tests (2a + 2b): ~0.5 day — most cost is getting the helper sequencing reliable.
- Optional `StallNextRefresh` returning a `stalled` channel: ~30 min if polling is flaky in practice.
- Verification (`-count=200` race) + commit + PR: ~0.25 day.

---

## Open items resolved

- **Scope:** Test 1 + 2a + 2b (full).
- **Retry-succeeds branch:** acknowledged as not reachable end-to-end; left to the existing unit test.
- **Helper sequencing:** poll `GrantCount` first; extend `StallNextRefresh` with a signal channel only if polling is flaky.
