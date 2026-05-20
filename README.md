# auth-go — shareable OAuth 2.0 client library for CLIs

[![Tests](https://github.com/entireio/auth-go/actions/workflows/test.yml/badge.svg)](https://github.com/entireio/auth-go/actions/workflows/test.yml)
[![Lint](https://github.com/entireio/auth-go/actions/workflows/lint.yml/badge.svg)](https://github.com/entireio/auth-go/actions/workflows/lint.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/entireio/auth-go.svg)](https://pkg.go.dev/github.com/entireio/auth-go)

Provider-agnostic Go library for CLIs that authenticate end-users via OAuth 2.0 device flow (RFC 8628), present resource-scoped bearer tokens to data APIs, and (when the auth host and data API live on different origins) exchange tokens via RFC 8693 STS.

No global state, no env-var reads, no implicit URLs. Every endpoint, identifier, and default value is supplied by the embedding CLI through a `Config` struct.

```
go get github.com/entireio/auth-go@latest
```

## Subpackages

| Package | What it does |
|---|---|
| [`deviceflow`](./deviceflow/) | RFC 8628 OAuth 2.0 Device Authorization Grant client. Polls the token endpoint, surfaces RFC 8628 §3.5 error codes (`authorization_pending`, `slow_down`, `access_denied`, `expired_token`, `invalid_grant`) as Go sentinels with optional `error_description`. |
| [`sts`](./sts/) | RFC 8693 OAuth 2.0 Token Exchange client. Provider-agnostic — caller supplies endpoint path, `subject_token_type`, `requested_token_type`, optional `audience` / `resource` / `scope`, and any provider-specific `Extra` form fields (e.g. `client_id`). |
| [`tokens`](./tokens/) | `TokenSet` value type plus unverified JWT claim parsing. Rejects `alg:none` (RFC 7515 / RFC 7518 §3.6 known attack vector). The package never validates signatures — that's the issuing server's responsibility. Callers use `Claims` for routing decisions (which issuer, which audience) and UX (display the principal handle), not as a security boundary. |
| [`tokenstore`](./tokenstore/) | `Store` interface for token persistence + `Keyring` reference impl backed by `github.com/zalando/go-keyring`. Each CLI passes its own service name so credentials are isolated across CLIs sharing this library. Returns `ErrNotFound` for unknown profiles and `ErrMalformed` (wrapped) when a stored entry exists but can't be decoded — used by upgrade fallbacks. |
| [`tokenmanager`](./tokenmanager/) | Orchestration: stores the device-flow core token, runs RFC 8693 exchanges when needed to obtain resource-scoped bearers, caches the results until expiry, and short-circuits when no exchange is needed (same-host or core-token's `aud` already covers the resource). Most CLIs only need to interact with this package directly. |

The `internal/oauthhttp` package holds shared HTTP body-reading + JSON-decoding helpers (detects HTML responses from captive portals / proxy intercepts and surfaces them as actionable errors instead of unmarshal failures). It is unexported in the Go sense — not importable by other modules — and not part of the public API surface.

## Security

Defense-in-depth checks layered on top of server-side validation:

- **HTTPS required.** Both `sts.Client` and `deviceflow.Client` reject `http://` BaseURLs unless `AllowInsecureHTTP` is set, and that opt-in is still limited to loopback (`localhost` / `127.0.0.1` / `::1`) so production misconfigurations fail loudly.
- **`alg:none` JWTs rejected.** `tokens.ParseClaims` decodes the JWT header and refuses the unsigned shape (any case variant of `none`). Even though claim use is routing-only, this keeps an obvious attack surface closed.
- **`verification_uri` validated.** The device-code response field is what your CLI echoes and opens in the user's browser — a malicious AS pointing it at a phishing page would be a credential-harvesting vector. The library rejects non-https (loopback http excepted), embedded `user:pass@host` userinfo, and control characters in the URI.
- **Resource origins validated.** `tokenmanager.Token` requires `TokenRequest.Resource` to be an origin URL: absolute scheme + host, HTTPS unless loopback HTTP is explicitly enabled, and no userinfo/path/query/fragment. This prevents cache fragmentation and accidental STS requests for surprising resource strings.
- **OAuth responses are bounded and strict.** Success and error bodies are capped at `MaxResponseBytes`; oversized responses are rejected, HTML/captive-portal responses get actionable errors, and JSON success bodies with trailing data are refused.
- **STS wire shape is explicit.** `tokenmanager` defaults `subject_token_type` to the RFC 8693 access-token URN and exposes `Config.SubjectTokenType` for STS endpoints that require the structural JWT URN.

## Quick start

```go
import (
    "github.com/entireio/auth-go/deviceflow"
    "github.com/entireio/auth-go/sts"
    "github.com/entireio/auth-go/tokenmanager"
    "github.com/entireio/auth-go/tokenstore"
)

const (
    issuer   = "https://auth.example.com"  // auth host base URL
    clientID = "my-cli"                    // public OAuth client_id
)

store := tokenstore.NewKeyring("my-cli")  // service name = your CLI's name

// One Manager per CLI process. Construct from your CLI's identity.
mgr, err := tokenmanager.New(tokenmanager.Config{
    Issuer:   issuer,
    ClientID: clientID,
    STSPath:  "/oauth/token",  // RFC 8693 endpoint; usually the OAuth token endpoint
    Store:    store,
    Scope:    "cli",
    // Optional: defaults to sts.SubjectTokenTypeAccessToken. If your STS
    // requires the structural JWT URN instead, uncomment:
    // SubjectTokenType: sts.SubjectTokenTypeJWT,
})
if err != nil { /* misconfiguration */ }
```

### Login

```go
dfc := &deviceflow.Client{
    BaseURL:        issuer,
    ClientID:       clientID,
    Scope:          "cli",
    DeviceCodePath: "/oauth/device/code",
    TokenPath:      "/oauth/token",
}

dc, err := dfc.StartDeviceAuth(ctx)
// show dc.UserCode + dc.VerificationURI to user, then drive the poll loop:
ts, err := dfc.PollUntil(ctx, dc)
if err != nil { /* surface RFC 8628 §3.5 sentinel as needed */ }

if err := mgr.SaveCoreToken(ts.AccessToken); err != nil { /* keyring failed */ }
```

`PollUntil` is the helper most embedders want. It honours `dc.Interval`,
applies the RFC 8628 §3.5 `+5s` bump on `slow_down`, stops at the
`dc.ExpiresIn` ceiling, and returns terminal sentinels (`ErrAccessDenied`,
`ErrExpiredToken`, `ErrInvalidGrant`) unwrapped so callers can
`errors.Is`. Use `PollDeviceAuth` directly only when you need to render
per-tick state in your own UI.

### Calling a data API

```go
bearer, err := mgr.TokenForResource(ctx, "https://api.example.com")
if errors.Is(err, tokenmanager.ErrNotLoggedIn) {
    // prompt user to run `mycli login`
}
// bearer is valid for https://api.example.com
req.Header.Set("Authorization", "Bearer "+bearer)
```

The manager picks the right strategy automatically:

- Same-host (`Issuer == resource`): hands back the core token verbatim.
- JWT-`aud`-includes shortcut: same, when the core token's audience already covers the resource (e.g. multi-audience tokens).
- Otherwise: runs an RFC 8693 exchange against `Issuer + STSPath`, caches the exchanged token by `(core, resource, audience, requested_token_type, scope)` until expiry.

By default, `tokenmanager` sends `subject_token_type=urn:ietf:params:oauth:token-type:access_token` for the stored core bearer. This is the role-based RFC 8693 token type and works for STS endpoints that treat the device-flow result as an OAuth access token even when its wire format is JWT. If your STS requires the structural JWT token type, configure `SubjectTokenType: sts.SubjectTokenTypeJWT`.

### Logout

```go
if err := mgr.DeleteCoreToken(); err != nil { /* keyring failed */ }
```

Deletes the keyring entry first; only clears the in-memory exchange cache on success, so a failed delete doesn't leave the CLI thinking it's logged out while the keyring still holds the token.

## Design principles

- **No globals, no env-var reads, no implicit URLs.** Everything ships through `Config`. The library should compile and run identically inside any CLI.
- **Provider-agnostic.** `deviceflow.Client` and `sts.Client` are field-bag structs; neither knows about your provider's endpoint paths or token-type URIs. Pass them in.
- **Bearer-presenter, not bearer-validator.** This library is for CLIs that *receive* tokens from an auth server and *present* them to a resource server. JWT signature verification is intentionally not done — the resource server validates. `tokens.ParseClaims` is documented as unverified and used only for routing decisions.
- **Per-CLI keyring isolation.** Each CLI passes a unique service name to `tokenstore.NewKeyring`. OS keyrings key by `(service, account)`, so consumers naturally get separate credential stores.
- **Caller controls the wire shape.** Default values for RFC 8693 fields are explicit and overridable. `tokenmanager` defaults `requested_token_type` to the standard access-token URN and `subject_token_type` to `access_token`; callers can set `RequestedTokenType`, `SubjectTokenType`, `scope`, audience, resource, and package-specific `Extra` fields as needed.

## Embedding checklist

1. Pick a stable service name for `tokenstore.NewKeyring(...)`. **Don't change it later** — renaming orphans every existing user's stored credentials.
2. Pick a `client_id` that the auth server recognises.
3. Decide your `STSPath`: typically the OAuth token endpoint per RFC 8693 convention, or a dedicated path if your auth server exposes one.
4. Decide whether the STS expects `subject_token_type=access_token` (the `tokenmanager` default) or `jwt` (`SubjectTokenType: sts.SubjectTokenTypeJWT`).
5. Construct the `tokenmanager.Manager` once at startup; pass it to your data-API call sites.
6. For multi-environment users (regions, staging), key the keyring by issuer URL — `Manager.Issuer()` returns the configured value.

## Security

The library is the *client* side of OAuth 2.0 device flow + RFC 8693
token exchange. It receives bearers from an authorization server and
presents them to data APIs. The threat model is:

- **The auth server is trusted.** This library does not verify JWT
  signatures — that's the data API's job. `tokens.ParseClaims` is
  documented as unverified and is used for routing decisions only.
- **The data API is trusted.** The library hands it a bearer; what
  the API does with it is out of scope.
- **The transport is trusted only when TLS-protected.** Both
  `deviceflow.Client` and `sts.Client` reject `http://` BaseURLs
  unless `AllowInsecureHTTP` is set, and even then only loopback hosts
  are accepted. The `Transport` field is for observability and proxies,
  not for disabling TLS verification.
- **OS keyrings are trusted within the user's session.** The
  `tokenstore.Keyring` impl keys credentials by `(service, account)`;
  pick a stable, unique service name per CLI and treat anything the
  keyring returns as untrusted bytes (the impl already rejects
  JSON-shaped junk and empty access tokens).

Defenses in depth that the library applies regardless:

- Rejects `alg:none` JWTs and any alg containing non-alphanumeric
  characters (closes whitespace / zero-width-space bypass attempts).
- Rejects absolute `Path` / `DeviceCodePath` / `TokenPath` values
  (defeats redirect-via-config attacks against `url.ResolveReference`).
- Validates `TokenRequest.Resource` as an origin URL and normalises it
  for same-host / JWT-audience shortcut comparisons and cache keys.
- Normalises `tokenmanager.Config.Issuer` so cosmetic differences
  (trailing slash, host case, default port) can't split keyring state
  across two effective issuers.
- Sanitises server-supplied `error_description` and non-JSON error body
  text (strips control chars, caps length) before wrapping into Go
  errors — so a hostile AS can't paint terminals or balloon logs.
- Rejects oversized OAuth responses and JSON success responses with
  trailing data after the first JSON value.
- Defaults STS `subject_token_type` to `access_token`, with
  `Config.SubjectTokenType` available when an STS expects `jwt`.
- Refuses to cache exchanged tokens with non-positive `expires_in`
  (forces a fresh exchange instead of treating unknown-lifetime
  bearers as "valid forever").
- Caps cache entries' lifetime at 1h when `ExpiresAt` is unset.

If you find a security issue, please email the maintainers privately
rather than opening a public issue — coordinated disclosure gives a
window to ship a fix before the report becomes searchable.

## Non-goals

- **OIDC discovery / ID tokens.** This library is OAuth 2.0 only. If you need OIDC `/.well-known/openid-configuration` + ID-token verification, layer `coreos/go-oidc` on top.
- **PKCE / authorization code flow.** Device flow only; CLIs almost never need code flow.
- **Server-side OIDC.** If you're building an *issuer*, look at `zitadel/oidc`'s `op` package.

## Status

Used in production by [`entireio/cli`](https://github.com/entireio/cli). Issues and PRs welcome.

## License

MIT — see [LICENSE](./LICENSE).
