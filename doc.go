// Package auth is the umbrella for github.com/entireio/auth-go, a
// shareable OAuth 2.0 client library for CLIs.
//
// All real code lives in the subpackages:
//
//   - deviceflow   — RFC 8628 OAuth 2.0 Device Authorization Grant client
//   - authcode     — RFC 8252 OAuth 2.0 Authorization Code Grant client
//     (PKCE + loopback redirect)
//   - sts          — RFC 8693 Token Exchange client
//   - refresh      — RFC 6749 §6 refresh_token grant client
//   - tokens       — TokenSet plus unverified JWT claim parsing
//   - tokenstore   — pluggable persistence interface with reference impls
//   - tokenmanager — orchestrates core-token storage + STS exchanges,
//     with caching and a JWT-audience shortcut
//
// The library is designed to talk RFC 8628, RFC 8252, and RFC 8693 to any
// compliant OAuth 2.0 server. It contains no provider-specific behaviour; endpoint
// paths, client IDs, and token-type URIs are caller-supplied. Anything a
// caller learns about the server beyond what the server tells it in a
// public HTTP response is out of scope for this package.
package auth
