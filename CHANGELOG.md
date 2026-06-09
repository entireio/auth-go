# Changelog

## Unreleased

## v0.5.0 — 2026-06-09

### Added

- New `authcode` package: an RFC 8252 OAuth 2.0 Authorization Code Grant
  client for native apps, using PKCE (RFC 7636, S256) and a loopback
  redirect. `Client.Start` binds a `127.0.0.1` listener and returns a
  `Flow` with the browser `AuthorizationURL`; `Flow.Wait` blocks for the
  redirect and returns the authorization code; `Flow.Exchange` redeems it
  at the token endpoint for a `tokens.TokenSet`. Opening the browser stays
  the caller's responsibility, as with `deviceflow`. Exposes
  `ErrAccessDenied`, `ErrInvalidGrant`, `ErrMissingCode`,
  `ErrListenerClosed`, and re-exports `ErrInsecureBaseURL` / `ErrAbsolutePath`.
  The first matching-state callback is terminal (a later forged success
  can't displace a genuine denial), and `Flow` redacts its PKCE verifier
  and CSRF state from `fmt` output like the other secret-bearing types.
- `sts.ExchangeError` — a typed error returned by `Client.Exchange` when
  the token endpoint replies with a structured RFC 6749 OAuth error.
  Exposes the parsed `Code`, `Description`, and `StatusCode` so callers
  can branch on the failure mode (e.g. `errors.As` + `Code ==
  "invalid_target"`) instead of substring-matching the message. `Error()`
  renders the same string as before, so message-matching callers are
  unaffected; non-OAuth failures (network errors, non-JSON bodies) remain
  plain wrapped errors.

### Changed

- Bumped the Go toolchain (and the `go.mod` minimum) to 1.26.4, picking
  up the standard-library security fixes GO-2026-5037 (`crypto/x509`
  hostname parsing) and GO-2026-5039 (`net/textproto`). Consumers now
  require Go ≥ 1.26.4.

## v0.4.0 — 2026-05-28

### Added

- New `refresh` package: an RFC 6749 §6 `refresh_token` grant client
  (peer of `sts`/`deviceflow`) that re-mints the login JWT from a stored
  refresh token. Exposes `refresh.ErrInvalidGrant` for rotation-race
  handling.
- `tokenmanager.Token` now transparently re-mints an expired/near-expiry
  login JWT from the stored refresh token before resolving the request,
  re-prompting login only when the refresh token itself is revoked or
  expired. New exported `tokenmanager.Manager.Refresh` lets callers warm
  the session proactively.
- Cross-process single-flight for refresh: an in-process mutex plus an
  injectable `tokenmanager.ProcessLock` (default: an advisory file lock
  over `golang.org/x/sys`), with rotation-race tolerance (on
  `invalid_grant`, the store is re-read and the refresh retried once
  against a concurrently-rotated successor before concluding re-login).
- New `tokenmanager.Config` fields `RefreshPath` (token endpoint for the
  refresh grant) and `LockDir` (advisory-lock directory; defaults under
  `os.UserCacheDir()`).
- New sentinels `tokenmanager.ErrReauthRequired` (refresh exhausted —
  distinct from `ErrNotLoggedIn`) and `tokenmanager.ErrNoRefreshPath`.

### Changed

- `golang.org/x/sys` is now a direct dependency (advisory file lock).
- `client_id` validation (`ValidateClientID` / `ValidateClientIDConsistency`)
  moved into `internal/oauthhttp` and shared by `sts` and `refresh`; no
  behavioural change to `sts`.
- Clamp a server-provided `expires_in` before converting to a
  `time.Duration` (centralised in `internal/oauthhttp.ExpiresInDuration`),
  applied across `sts`, `deviceflow`, and `refresh`. Guards against an
  int64 nanosecond overflow that an absurd value would otherwise wrap into
  a past expiry.
- `tokenmanager.SaveCoreToken` and `tokenmanager.DeleteCoreToken` now
  acquire the refresh lock (`refreshMu` in-process, the cross-process file
  lock) before mutating the store, serialising them against in-flight
  refreshes. Prevents a refresh whose grant is mid-flight from persisting
  over a concurrent logout (session resurrection) or overwriting a
  concurrent re-login. Both methods can now block up to ~30s under
  contention and may return a wrapped lock-acquire error.

## v0.3.4 — 2026-05-25

### Breaking changes

- `tokenmanager.Token` now requires `TokenRequest.Resource` to be an origin URL: absolute scheme + host, HTTPS unless loopback HTTP is explicitly enabled, and no userinfo/path/query/fragment. Opaque or non-URL resource strings that previously flowed through byte-exact are now rejected; use `Audience` for opaque audience values and `Resource` for the API origin.
- `tokenmanager.New` now holds `Config.Issuer` to the same origin-URL contract as `TokenRequest.Resource`. Issuers carrying userinfo, a path, query, or fragment are rejected at construction. Previously they were accepted and silently mis-fired the same-host shortcut, forcing every "same origin" call through the STS.
- `sts.Client.Exchange` now rejects multi-valued `Extra["client_id"]`. Different server-side form parsers picked different entries, so the wire identity was caller-invisible.

### Security

- Sanitise the AS-supplied OAuth `error` code before interpolating it into returned errors. The description was already sanitised; the code field was a parallel terminal-escape sink.
- `validateVerificationURI` rejects C1 controls (U+0080–U+009F) in addition to C0 + DEL. CSI (U+009B) is the canonical 8-bit-aware terminal-escape bypass.
- Hardened OAuth response parsing and sanitization, including oversized response rejection, trailing JSON rejection, and sanitized fallback text for non-JSON error bodies.
- Centralised OAuth HTTP helpers in `internal/oauthhttp` (origin-URL normalisation/validation, OAuth error parsing, response decoding, sanitisation) to eliminate per-package drift.
- Restricted explicit insecure HTTP opt-in to loopback hosts.
- Added `govulncheck` to the mise lint task and CI workflow.
