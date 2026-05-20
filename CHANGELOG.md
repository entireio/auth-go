# Changelog

## Unreleased

### Breaking changes

- `tokenmanager` now defaults RFC 8693 `subject_token_type` to `urn:ietf:params:oauth:token-type:access_token` instead of `urn:ietf:params:oauth:token-type:jwt`. This better describes the stored device-flow bearer as an OAuth access token, even when its wire format is JWT. Embedders whose STS endpoint requires the JWT URN should set `tokenmanager.Config.SubjectTokenType` to `sts.SubjectTokenTypeJWT`.
- `tokenmanager.Token` now requires `TokenRequest.Resource` to be an origin URL: absolute scheme + host, HTTPS unless loopback HTTP is explicitly enabled, and no userinfo/path/query/fragment. Opaque or non-URL resource strings that previously flowed through byte-exact are now rejected; use `Audience` for opaque audience values and `Resource` for the API origin.

### Security

- Hardened OAuth response parsing and sanitization, including oversized response rejection, trailing JSON rejection, and sanitized fallback text for non-JSON error bodies.
- Restricted explicit insecure HTTP opt-in to loopback hosts.
- Added `govulncheck` to the mise lint task and CI workflow.
