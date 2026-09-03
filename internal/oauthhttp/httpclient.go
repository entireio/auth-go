package oauthhttp

import (
	"fmt"
	"net/http"
	"strings"
)

// maxOAuthRedirects matches net/http's own default cap, so replacing
// CheckRedirect does not also change how many same-host hops are tolerated.
const maxOAuthRedirects = 10

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
// SECURITY: every client this returns refuses a cross-host redirect (see
// RejectCrossHostRedirect). All four flows build their client here and each
// posts a credential in the body, so the policy belongs at this one
// construction point rather than at each caller.
func HTTPClient(transport http.RoundTripper) *http.Client {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: RejectCrossHostRedirect,
	}
}

// HTTPClientFollowingCrossHostRedirects builds a client WITHOUT the
// cross-host redirect guard, for a request whose body carries no
// credential and whose cross-host redirect is load-bearing.
//
// Exactly one request qualifies: RFC 8628's device-authorization POST, whose
// cross-host 307 is how regional routing works, and whose body is client_id
// plus scope — no secret (a confidential client's secret rides in Basic auth,
// which net/http strips on a host change). TestStartDeviceAuth_BodyCarriesNoCredential
// pins that key set, since the exemption rests on it.
//
// Do NOT reach for this anywhere else: check what the body carries first.
// What following a redirect still costs is documented where a caller can act
// on it, on DeviceCode.ResponseOrigin and Client.TokenBaseURL.
//
// Built by subtraction so this stays "HTTPClient minus the guard" — anything
// the guarded constructor grows later is inherited, not silently missed.
func HTTPClientFollowingCrossHostRedirects(transport http.RoundTripper) *http.Client {
	c := HTTPClient(transport)
	c.CheckRedirect = nil
	return c
}

// RejectCrossHostRedirect is the CheckRedirect policy for every OAuth
// request this library makes. It stops a redirect chain from leaving
// the host the request was originally sent to.
//
// SECURITY: net/http strips sensitive *headers* on a cross-host redirect
// (shouldCopyHeaderOnRedirect) but replays the *body* on 307/308 — and the
// body is where every OAuth credential lives (subject_token, refresh_token,
// authorization code + PKCE verifier, device_code). So a POST body gets none
// of the protection a bearer header gets, and an open redirect in front of a
// legitimate token endpoint would hand those credentials to a third host,
// whose own access_token would then be returned as if genuine.
//
// Compared against via[0], the host the caller chose, not the previous hop:
// otherwise a chain could walk away one host at a time. Host only, so a
// same-host http→https upgrade still follows; a port change is a different
// endpoint and is refused. Not configurable — that option would be set by
// whoever benefits from it, and no token endpoint needs one.
func RejectCrossHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxOAuthRedirects {
		return fmt.Errorf("stopped after %d redirects", maxOAuthRedirects)
	}
	if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		return fmt.Errorf("refusing redirect to a different host (%s -> %s): an OAuth request body carries credentials and must not leave its origin",
			via[0].URL.Host, req.URL.Host)
	}
	return nil
}
