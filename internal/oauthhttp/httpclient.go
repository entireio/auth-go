package oauthhttp

import (
	"fmt"
	"net/http"
	"strings"
)

// maxOAuthRedirects matches net/http's own default redirect cap, so
// replacing the default CheckRedirect does not also change how many
// same-host hops are tolerated.
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
// SECURITY: every client this returns refuses a cross-host redirect
// (see RejectCrossHostRedirect). This is the one construction point
// for all four OAuth flows in this library — sts, refresh, authcode,
// deviceflow — and each of them puts a credential in a POST form
// body, so the policy belongs here rather than at each caller.
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
// There is exactly one such request in this library: RFC 8628's
// device-authorization POST, which an apex front door 307s at the
// regional core that will actually serve the flow, and whose response
// origin is how the client learns which region to poll. Its body is
// client_id plus scope — a public identifier and a request parameter,
// neither of which is a secret — and a confidential client's secret
// rides in Basic auth, which net/http already strips when the host
// changes.
//
// Do NOT reach for this anywhere else. If a new call site seems to
// need it, check what its body carries first: every other OAuth
// request in this library posts a credential, and for those the
// redirect must be refused. What following one still costs is
// documented where the caller can act on it, on DeviceCode.ResponseOrigin
// and Client.TokenBaseURL.
//
// Built by subtraction from HTTPClient rather than beside it, so this
// stays "HTTPClient minus the guard": anything the guarded constructor
// grows later is inherited instead of silently missed here, which is
// the one place a silent miss is least affordable.
func HTTPClientFollowingCrossHostRedirects(transport http.RoundTripper) *http.Client {
	c := HTTPClient(transport)
	c.CheckRedirect = nil
	return c
}

// RejectCrossHostRedirect is the CheckRedirect policy for every OAuth
// request this library makes. It stops a redirect chain from leaving
// the host the request was originally sent to.
//
// SECURITY: net/http strips sensitive *headers* when a redirect
// crosses to a different host (shouldCopyHeaderOnRedirect), but it
// replays the request *body* unconditionally on 307/308 — and the
// body is where every OAuth credential lives: sts's subject_token
// (the user's login JWT), refresh's refresh_token, authcode's
// authorization code and PKCE verifier, deviceflow's device_code. A
// POST body therefore gets none of the protection a bearer header
// gets, so without this policy an open redirect or a misconfigured
// proxy in front of a legitimate token endpoint is enough to hand
// those credentials to a third host. The response is trusted too: a
// redirect target that answers with its own access_token would have
// it returned to the caller as if the real authorization server had
// issued it.
//
// Comparison is against via[0], the host the caller chose, not the
// previous hop — otherwise a chain could walk away one host at a
// time. Only the host is compared, so a same-host http→https upgrade
// still follows (by then the body has already gone out in clear, and
// refusing would not put it back); a change of port is treated as a
// different endpoint and refused.
//
// Deliberately not configurable. An option to permit cross-host
// redirects here would be set by exactly the party that benefits from
// it, and no authorization server needs one: RFC 8693 and RFC 6749
// token endpoints answer at the URL the client was configured with.
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
