# Changelog

## Unreleased

### Added

Support for authorization servers that are a *dispatching front door*: the
apex serves `/authorize` and `/device_authorization` but redirects each to a
regional authorization server, which is the only host that mints tokens and
the only host that will redeem the resulting code. The client must therefore
learn the region at runtime and send the token request there.

- `authcode.Flow.Issuer()` — the RFC 9207 `iss` parameter from the loopback
  callback, or `""` when the server sent none. Reported verbatim and
  deliberately **not** validated: the package knows the origin it dialled but
  not the issuer identifier the deployment expects, and for a dispatching
  front door those legitimately differ (RFC 9207 §2.4 makes validation the
  client's job). Callers MUST check it against their own trust policy.
- `authcode.Flow.SetTokenBaseURL(baseURL)` — retargets this flow's token
  exchange at `baseURL` instead of `Client.BaseURL`. Call it between `Wait`
  and `Exchange`; `""` clears the override. `baseURL` is validated as an
  origin (HTTPS unless `AllowInsecureHTTP` and loopback), but the package
  cannot judge whether the host is trustworthy — the authorization code and
  the user's tokens travel to it.
- `deviceflow.DeviceCode.ResponseOrigin` — the origin that actually served
  the device-authorization response, after any redirects the client followed.
  Filled in by `StartDeviceAuth`, never decoded from the response body (that
  body is parsed strictly, so a server-sent field of the same name would be a
  breaking change). Equals `Client.BaseURL` when no redirect occurred.
- `deviceflow.Client.TokenBaseURL` — overrides `BaseURL` for the token
  endpoint only (`PollDeviceAuth` / `PollUntil`). Empty means "use BaseURL".
  Set it between `StartDeviceAuth` and the first poll.

### Security

- The strings this library renders back to the user from server-supplied
  data — the OAuth `error_description` via `SanitizeDescription`, and the
  device-flow `verification_uri` — now also reject the Unicode formatting
  characters that reorder or hide rendered text: bidirectional embeddings,
  overrides and isolates (U+202A–U+202E, U+2066–U+2069), the implicit marks
  LRM/RLM/ALM (U+200E, U+200F, U+061C), zero-width space (U+200B), BOM
  (U+FEFF), and LINE/PARAGRAPH SEPARATOR (U+2028, U+2029). Filtering only
  the legacy C0/DEL/C1 codes left a server able to change what the user
  reads without changing what they got — the "Trojan Source" class — which
  is precisely what those two checks exist to prevent, the second of them
  on a URL the user is asked to inspect and open. ZWNJ and ZWJ (U+200C,
  U+200D) are deliberately still accepted: they carry meaning in Indic,
  Perso-Arabic, and emoji text and reorder nothing.
- The rule now has one definition, `oauthhttp.IsDisplayUnsafeRune`, used by
  both call sites; the duplicated inline range check in
  `deviceflow.validateVerificationURI` is gone.

### Changed

- Bumped the Go toolchain (and the `go.mod` minimum) to 1.26.6, picking up
  the standard-library security fixes GO-2026-6218 (`net/url`), GO-2026-6090
  and GO-2026-5856 (`crypto/tls`), GO-2026-6089 and GO-2026-5026
  (`net/http`), and GO-2026-5972 (`encoding/asn1`). Consumers now require
  Go ≥ 1.26.6.

## v0.5.2 — 2026-07-07

### Added

- `tokenmanager.Manager.ForceRefresh(ctx, staleToken)` — re-mints the login
  JWT via the refresh grant even when the stored one has not expired
  locally. For reactive 401 paths: when the server rejects a token whose
  `exp` still looks live (signing-key rotation, revocation ahead of
  expiry), `Refresh`'s fast path would return the same rejected token.
  Under the usual refresh + process locks the store is re-read first: if it
  already holds a different, locally-live token, a cooperating peer
  re-minted while we waited and that token is returned with no grant
  (anti-stampede — concurrent reactions to the same 401 coalesce onto one
  rotation). `staleToken == ""` skips the peer check and forces the grant
  unconditionally. Sentinels match `Refresh` (`ErrNotLoggedIn`,
  `ErrReauthRequired`; persist failures wrap `ErrPersistFailed`).
  `Refresh`'s fast path is unchanged.

## v0.5.1 — 2026-07-07

### Fixed

- `tokenmanager` now retries persisting rotated credentials after a
  successful refresh grant (up to 3 attempts with a short backoff) instead
  of discarding them on the first `Store.SaveTokens` failure. The refresh
  grant is single-use: the server rotates and thereby consumes the previous
  refresh token, so a dropped save previously left the store holding a dead
  predecessor and guaranteed the session would fail at the next refresh
  (observed as forced re-logins after a transient keyring hiccup). The
  refresh + process locks are held across all attempts, so no peer can read
  the stale predecessor mid-retry. The backoff is context-aware; because
  the rotation is already consumed server-side, cancellation mid-backoff
  still triggers one final immediate save attempt before giving up, and
  the resulting error then wraps `ctx.Err()` alongside the store error.

### Added

- `tokenmanager.ErrPersistFailed` — a sentinel wrapped into the error
  returned when a refresh grant succeeded but persisting the rotated
  credentials failed on every retry. Callers can `errors.Is` it to detect
  the doomed-session case (the rotation was consumed server-side, so the
  session needs an interactive re-login) and distinguish it from ordinary
  transport/grant failures. In this case the access token is deliberately
  NOT returned: a working command that hides a session guaranteed to die at
  the next refresh is worse than a loud failure now.
- `tokenmanager.SetSleepForTest` — a test seam (mirroring the existing
  `SetNowForTest` / `SetRefreshForTest` idiom, requiring a `testing.TB`)
  that drives the persist-retry backoff without real wall-clock sleeps.

## v0.5.0 — 2026-06-10

### Added

- New `authcode` package: an RFC 8252 OAuth 2.0 Authorization Code Grant
  client for native apps, using PKCE (RFC 7636, S256) and a loopback
  redirect. `Client.Start` binds a `127.0.0.1` listener and returns a
  `Flow` with the browser `AuthorizationURL`; `Flow.Wait` blocks for the
  redirect and returns the authorization code; `Flow.Exchange` redeems it
  at the token endpoint for a `tokens.TokenSet`. Opening the browser stays
  the caller's responsibility, as with `deviceflow`. Exposes
  `ErrAccessDenied`, `ErrInvalidGrant`, `ErrMissingCode`,
  `ErrListenerClosed`, `ErrAuthorizeQuery` (a query on `AuthorizePath` is
  rejected rather than silently overwritten by the OAuth query), and
  re-exports `ErrInsecureBaseURL` / `ErrAbsolutePath`.
  The first matching-state callback is terminal (a later forged success
  can't displace a genuine denial), and `Flow` redacts its PKCE verifier
  and CSRF state from `fmt` output like the other secret-bearing types.
  The loopback callback's browser page ("Signed in" / "Sign-in failed")
  is styled to match entire-core's CLI login pages — Marvin logo, card
  layout, light/dark via `prefers-color-scheme` — while staying a single
  self-contained response: no scripts, no external resources.
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
