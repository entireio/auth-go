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

// HTTPClientFollowingCrossHostRedirects builds a client that opts out of the
// HOST restriction — and only that. mandatoryRedirectPolicy still applies, so
// a plaintext hop is refused here too: the device-authorization RESPONSE
// carries a redeemable device_code even though its request body is public, and
// an observer who captures one can attempt redemption once the user authorizes.
//
// Exactly one request qualifies: RFC 8628's device-authorization POST, whose
// cross-host 307 is how regional routing works, and whose body is client_id
// plus scope. deviceflow.Client has no ClientSecret field and sets no Basic
// auth, so it carries no client credential at all;
// TestStartDeviceAuth_BodyCarriesNoCredential pins that key set.
//
// Do NOT reach for this anywhere else: check what the body carries first.
// What following a cross-host redirect still costs is documented where a
// caller can act on it, on DeviceCode.ResponseOrigin and Client.TokenBaseURL.
func HTTPClientFollowingCrossHostRedirects(transport http.RoundTripper) *http.Client {
	c := HTTPClient(transport)
	c.CheckRedirect = mandatoryRedirectPolicy
	return c
}

// mandatoryRedirectPolicy is the floor under every OAuth redirect decision in
// this library: the hop cap, and a refusal to leave HTTPS once a chain has
// reached it. RejectCrossHostRedirect layers the host restriction on top; the
// device-authorization client uses this alone.
//
// SECURITY: net/http permits a scheme change across a redirect, so an https
// endpoint answering 307/308 with an http Location would put the replayed body
// — every OAuth credential lives there — on the wire in clear. Initial-URL
// validation and AllowInsecureHTTP say nothing about later hops, and enabling
// that option for local development must not license a downgrade.
//
// Anchored on the PREVIOUS hop, not via[0]: an http→https→http chain starts
// insecure, so anchoring on the first request would take http as the baseline
// and permit the final downgrade. The message names only the scheme, since a
// redirect URL can carry a code in its query and this text reaches logs.
func mandatoryRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= maxOAuthRedirects {
		return fmt.Errorf("stopped after %d redirects", maxOAuthRedirects)
	}
	if len(via) == 0 {
		return nil
	}
	if prev := via[len(via)-1]; prev.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect from https to %s: an OAuth request carries credentials and must not cross a plaintext hop", req.URL.Scheme)
	}
	return nil
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
// The HOST is compared against via[0], the host the caller chose, not the
// previous hop: otherwise a chain could walk away one host at a time. Host
// only, so a same-host http→https upgrade still follows; a port change is a
// different endpoint and is refused. The SCHEME rule is
// mandatoryRedirectPolicy's, which anchors on the previous hop instead — see
// there for why the two differ. Not configurable — that option would be set by
// whoever benefits from it, and no token endpoint needs one.
func RejectCrossHostRedirect(req *http.Request, via []*http.Request) error {
	if err := mandatoryRedirectPolicy(req, via); err != nil {
		return err
	}
	if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		return fmt.Errorf("refusing redirect to a different host (%s -> %s): an OAuth request body carries credentials and must not leave its origin",
			via[0].URL.Host, req.URL.Host)
	}
	return nil
}
