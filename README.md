# auth — shareable OAuth 2.0 client library for internal CLIs

Provider-agnostic Go library for CLIs that authenticate end-users via OAuth 2.0 device flow (RFC 8628), present resource-scoped bearer tokens to data APIs, and (when the auth host and data API live on different origins) exchange tokens via RFC 8693 STS.

The library has no global state, no env-var reads, and no implicit URLs. Every endpoint, identifier, and default value is supplied by the embedding CLI through a `Config` struct. That keeps it usable by any CLI in the org without forking.

## Subpackages

| Package | What it does |
|---|---|
| [`deviceflow`](./deviceflow/) | RFC 8628 OAuth 2.0 Device Authorization Grant client. Polls the token endpoint, surfaces RFC 8628 §3.5 error codes (`authorization_pending`, `slow_down`, `access_denied`, `expired_token`, `invalid_grant`) as Go sentinels with optional `error_description`. |
| [`sts`](./sts/) | RFC 8693 OAuth 2.0 Token Exchange client. Provider-agnostic — caller supplies endpoint path, `subject_token_type`, `requested_token_type`, optional `audience` / `resource` / `scope`, and any provider-specific `Extra` form fields (e.g. `client_id`). |
| [`tokens`](./tokens/) | `TokenSet` value type plus unverified JWT claim parsing. The package never validates signatures — that's the issuing server's responsibility. CLIs use `Claims` for routing decisions (which issuer, which audience) and UX (display the principal handle), not as a security boundary. |
| [`tokenstore`](./tokenstore/) | `Store` interface for token persistence + `Keyring` reference impl backed by `github.com/zalando/go-keyring`. Each CLI passes its own service name so credentials are isolated across CLIs sharing this library. Returns `ErrNotFound` for unknown profiles and `ErrMalformed` (wrapped) when a stored entry exists but can't be decoded — used by upgrade fallbacks. |
| [`tokenmanager`](./tokenmanager/) | Orchestration: stores the device-flow core token, runs RFC 8693 exchanges when needed to obtain resource-scoped bearers, caches the results until expiry, and short-circuits when no exchange is needed (same-host or core-token's `aud` already covers the resource). Most CLIs only need to interact with this package directly. |

Internal helper:

| Package | What it does |
|---|---|
| [`internal/oauthhttp`](./internal/oauthhttp/) | Shared HTTP body-reading + JSON-decoding helpers. Detects HTML responses (captive portal / proxy intercept) and surfaces them as actionable errors instead of unmarshal failures. Not exported. |

## Quick start

The typical embedding CLI does roughly this at startup:

```go
import (
    "github.com/entireio/cli/auth/deviceflow"
    "github.com/entireio/cli/auth/tokenmanager"
    "github.com/entireio/cli/auth/tokenstore"
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
// ... show dc.UserCode + dc.VerificationURI to user, then poll ...
ts, err := dfc.PollDeviceAuth(ctx, dc.DeviceCode)
if err != nil { /* surface RFC 8628 §3.5 sentinel as needed */ }

if err := mgr.SaveCoreToken(ts.AccessToken); err != nil { /* keyring failed */ }
```

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

### Logout

```go
if err := mgr.DeleteCoreToken(); err != nil { /* keyring failed */ }
```

Deletes the keyring entry first; only clears the in-memory exchange cache on success, so a failed delete doesn't leave the CLI thinking it's logged out while the keyring still holds the token.

## Design principles

- **No globals, no env-var reads, no implicit URLs.** Everything ships through `Config`. The library should compile and run identically inside any CLI.
- **Provider-agnostic.** `deviceflow.Client` and `sts.Client` are field-bag structs; neither knows about your provider's endpoint paths or token-type URIs. Pass them in.
- **Bearer-presenter, not bearer-validator.** This library is for CLIs that *receive* tokens from an auth server and *present* them to a resource server. JWT signature verification is intentionally not done — the resource server validates. `tokens.ParseClaims` is documented as unverified and used only for routing decisions.
- **Per-CLI keyring isolation.** Each CLI passes a unique service name to `tokenstore.NewKeyring`. OS keyrings key by `(service, account)`, so different CLIs naturally get separate credential stores.
- **Caller controls the wire shape.** Default values (RFC 8693 `requested_token_type`, `scope`, audience-empty) live in the embedding CLI's wiring, not in this library.

## Embedding checklist for a new CLI

1. Pick a stable service name for `tokenstore.NewKeyring(...)`. **Don't change it later** — renaming orphans every existing user's stored credentials.
2. Pick a `client_id` that the auth server recognises.
3. Decide your `STSPath`: typically the OAuth token endpoint per RFC 8693 convention, or a dedicated path if your auth server exposes one.
4. Construct the `tokenmanager.Manager` once at startup; pass it to your data-API call sites.
5. For multi-environment users (regions, staging), key the keyring by issuer URL — `Manager.Issuer()` returns the configured value.

## Non-goals

- **OIDC discovery / ID tokens.** This library is OAuth 2.0 only. If you need OIDC `/.well-known/openid-configuration` + ID-token verification, layer `coreos/go-oidc` on top.
- **PKCE / authorization code flow.** Device flow only; CLIs almost never need code flow.
- **Server-side OIDC.** If you're building an *issuer*, look at `zitadel/oidc`'s `op` package.

## Status

Used in production by [`entireio/cli`](https://github.com/entireio/cli). Open to additional internal CLI consumers — file an issue if you hit a gap.
