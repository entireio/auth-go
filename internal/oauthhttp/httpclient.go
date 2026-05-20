package oauthhttp

import "net/http"

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
func HTTPClient(transport http.RoundTripper) *http.Client {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &http.Client{Transport: transport}
}
