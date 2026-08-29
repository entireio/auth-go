package oauthhttp

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// maxRedirects mirrors net/http's default redirect cap. Supplying a
// CheckRedirect func replaces the default policy wholesale — including
// its 10-hop ceiling — so the ceiling has to be reimposed here or a
// same-origin redirect loop would spin until the caller's context fires.
const maxRedirects = 10

// ErrUnexpectedRedirect is returned when a request that carries a
// credential in its body is redirected to a different origin.
//
// The OAuth token grants (token exchange, refresh, device-code
// redemption, authorization-code redemption) POST the user's bearer —
// subject_token, refresh_token, device_code, or code + PKCE
// code_verifier — in the request body. net/http replays that body
// verbatim on a 307/308 redirect, and its cross-origin protections do
// not extend to bodies: only sensitive *headers* are stripped. Left to
// the default policy, a redirect therefore delivers the credential to
// whatever origin the response names, plaintext http:// included —
// which would also route around the AllowInsecureHTTP guard, since that
// is only applied to the configured base URL.
//
// This is the same threat ErrAbsolutePath closes on the configuration
// side; a redirect is simply the server-side way to reach it. Callers
// can match with errors.Is via the re-exported sentinel in each flow
// package.
var ErrUnexpectedRedirect = errors.New("refusing to follow cross-origin redirect on a credential-bearing OAuth request")

// HTTPClient builds the *http.Client used for one OAuth request.
//
// Always returns a freshly-allocated *http.Client so this library's
// requests are isolated from mutations to http.DefaultClient (any
// process-wide Timeout or Transport swap by another package would
// otherwise be inherited). The underlying Transport is the
// caller-supplied transport when non-nil, or http.DefaultTransport
// otherwise — sharing a Transport is intentional (it owns the
// connection pool) and safe (Transport.RoundTrip is concurrent-safe).
//
// Per-request timeouts must be driven by ctx.WithTimeout in the
// caller, not by *http.Client.Timeout — the body-read happens after
// client.Do returns, and Client.Timeout would cancel that read.
//
// Redirects follow net/http's default policy. Use this only for
// requests that carry no credential in the body; see
// CredentialHTTPClient for the rest.
func HTTPClient(transport http.RoundTripper) *http.Client {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &http.Client{Transport: transport}
}

// CredentialHTTPClient is HTTPClient plus a redirect policy that
// refuses to leave the origin the request was aimed at.
//
// Same-origin redirects (a path rewrite, a trailing-slash
// normalisation) are still followed: the body goes back to the host the
// caller already chose to trust. Anything that changes scheme, host, or
// effective port fails with ErrUnexpectedRedirect before the redirected
// request is issued, so the credential is never put on the wire toward
// the new origin.
//
// Deployments whose token endpoint genuinely lives on another origin —
// a dispatching front door in front of regional authorization servers —
// are served by the explicit, caller-validated retarget hooks
// (deviceflow.Client.TokenBaseURL, authcode.Flow.SetTokenBaseURL) rather
// than by an unvalidated redirect.
func CredentialHTTPClient(transport http.RoundTripper) *http.Client {
	c := HTTPClient(transport)
	c.CheckRedirect = refuseCrossOriginRedirect
	return c
}

// refuseCrossOriginRedirect is the CheckRedirect policy installed by
// CredentialHTTPClient. via[0] is the original request, so every hop is
// compared against the origin the caller configured rather than against
// its immediate predecessor — otherwise a chain of individually
// "same-origin-ish" hops could walk away from it.
func refuseCrossOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	origin := originOf(via[0].URL)
	target := originOf(req.URL)
	if origin != target {
		return fmt.Errorf("%w: %s -> %s", ErrUnexpectedRedirect, origin, target)
	}
	return nil
}

// originOf renders u's scheme://host in the normalised form
// NormalizeOriginURL produces, so a redirect that only restates the
// default port (https://host -> https://host:443) is not mistaken for
// an origin change.
func originOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	return NormalizeOriginURL(u.Scheme + "://" + u.Host)
}
