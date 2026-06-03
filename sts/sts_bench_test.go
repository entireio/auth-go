package sts

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/entireio/auth-go/internal/oauthhttp"
)

// benchExchangeRequest mirrors a realistic Exchange call: a JWT subject
// token, the RFC 8693 standard fields, and one client_id mirror in
// Extra (the wire-pattern entire-core uses).
func benchExchangeRequest() ExchangeRequest {
	return ExchangeRequest{
		SubjectToken:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJzdWIiOiJ1c2VyMTIzIiwiaXNzIjoiaHR0cHM6Ly9hcyIsImF1ZCI6ImNsaWVudCIsImV4cCI6MTcwMDAwMDAwMH0.sig",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		Audience:           "https://api.example.com",
		Scope:              "openid profile email",
		ClientID:           "cli-app",
		Extra:              url.Values{"client_id": []string{"cli-app"}},
	}
}

// sinkString defeats escape analysis in the form benches — without an
// observable sink, the resulting string may be elided.
var sinkString string

func BenchmarkBuildFormEncode(b *testing.B) {
	req := benchExchangeRequest()
	b.ReportAllocs()
	for b.Loop() {
		form := buildForm(req)
		sinkString = oauthhttp.EncodeForm(form)
	}
}

// sinkClient prevents escape-analysis from eliding the *http.Client
// allocation in BenchmarkHTTPClient — without a write to a non-escaping
// sink, the discarded pointer never escapes and the struct stays on the
// stack, hiding the per-call allocation we're measuring.
var sinkClient *http.Client

func BenchmarkHTTPClient(b *testing.B) {
	c := &Client{}
	b.ReportAllocs()
	for b.Loop() {
		sinkClient = c.httpClient()
	}
}

// BenchmarkExchange_EndToEnd drives a real HTTPS round-trip against an
// httptest server with HTTP/2 enabled. The TLS handshake on first call
// is amortized over b.N once keep-alive kicks in, so this measures the
// hot-path: request-build, write, response-read, JSON decode.
func BenchmarkExchange_EndToEnd(b *testing.B) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{` +
			`"access_token":"at_eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",` +
			`"issued_token_type":"urn:ietf:params:oauth:token-type:access_token",` +
			`"token_type":"Bearer",` +
			`"expires_in":3600,` +
			`"refresh_token":"rt_abc123def456",` +
			`"scope":"openid profile email"` +
			`}`))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	c := &Client{
		Transport: tr,
		BaseURL:   srv.URL,
		Path:      "/token",
	}

	// Warm the connection so the first iteration doesn't pay TLS+ALPN.
	if _, err := c.Exchange(context.Background(), benchExchangeRequest()); err != nil {
		b.Fatal(err)
	}

	req := benchExchangeRequest()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := c.Exchange(context.Background(), req); err != nil {
			b.Fatal(err)
		}
	}
}
