# Changelog

## Unreleased

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
