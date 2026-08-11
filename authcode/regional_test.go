package authcode

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// Tests for the RFC 9207 issuer surfaced off the loopback callback and the
// per-flow token-endpoint retargeting it enables.

func TestWait_RecordsCallbackIssuer(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
	f, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if got := f.Issuer(); got != "" {
		t.Errorf("Issuer() before Wait = %q, want empty", got)
	}

	resp := hitCallback(t, f.RedirectURI, url.Values{
		"code":  {"code-1"},
		"state": {authParams(t, f).Get("state")},
		"iss":   {"https://us.auth.example.com"},
	})
	_ = resp.Body.Close()

	if _, err := f.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if got := f.Issuer(); got != "https://us.auth.example.com" {
		t.Errorf("Issuer() = %q, want https://us.auth.example.com", got)
	}
}

func TestWait_IssuerEmptyWhenServerSendsNone(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
	f, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	resp := hitCallback(t, f.RedirectURI, url.Values{
		"code":  {"code-1"},
		"state": {authParams(t, f).Get("state")},
	})
	_ = resp.Body.Close()

	if _, err := f.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if got := f.Issuer(); got != "" {
		t.Errorf("Issuer() = %q, want empty", got)
	}
}

// TestSetTokenBaseURL_RetargetsExchange models the dispatching front door:
// the authorization endpoint lives on the apex, which serves no token
// endpoint at all, and the code is only redeemable at the regional host
// named by the callback's iss.
func TestSetTokenBaseURL_RetargetsExchange(t *testing.T) {
	t.Parallel()

	regional := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != testTokenPath {
			t.Errorf("regional path = %q, want %q", r.URL.Path, testTokenPath)
		}
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, `{"access_token":"at-regional","token_type":"Bearer","expires_in":3600}`)
	}))
	t.Cleanup(regional.Close)

	// The apex 404s every token request — reaching it is the failure this
	// test guards against.
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "apex serves no token endpoint", http.StatusNotFound)
	})

	f, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	resp := hitCallback(t, f.RedirectURI, url.Values{
		"code":  {"code-1"},
		"state": {authParams(t, f).Get("state")},
		"iss":   {regional.URL},
	})
	_ = resp.Body.Close()

	code, err := f.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if err := f.SetTokenBaseURL(f.Issuer()); err != nil {
		t.Fatalf("SetTokenBaseURL(%q) error = %v", f.Issuer(), err)
	}

	ts, err := f.Exchange(context.Background(), code)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if ts.AccessToken != "at-regional" {
		t.Fatalf("AccessToken = %q, want at-regional", ts.AccessToken)
	}
}

func TestSetTokenBaseURL_EmptyClearsOverride(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, `{"access_token":"at-base","token_type":"Bearer"}`)
	})
	f, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	if err := f.SetTokenBaseURL("https://elsewhere.example"); err != nil {
		t.Fatalf("SetTokenBaseURL() error = %v", err)
	}
	if err := f.SetTokenBaseURL(""); err != nil {
		t.Fatalf(`SetTokenBaseURL("") error = %v`, err)
	}
	if got := f.tokenBase(); got != c.BaseURL {
		t.Fatalf("tokenBase() = %q, want %q", got, c.BaseURL)
	}

	ts, err := f.Exchange(context.Background(), "code-1")
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if ts.AccessToken != "at-base" {
		t.Fatalf("AccessToken = %q, want at-base", ts.AccessToken)
	}
}

func TestSetTokenBaseURL_RejectsUnusableOrigins(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name              string
		in                string
		allowInsecureHTTP bool
	}{
		{"no host", "https://", true},
		{"not a URL", "us.auth.example.com", true},
		{"unsupported scheme", "ftp://us.auth.example.com", true},
		{"userinfo", "https://tok@us.auth.example.com", true},
		{"path", "https://us.auth.example.com/oauth", true},
		{"plain http rejected by default", "http://us.auth.example.com", false},
		{"non-loopback http rejected even when insecure http is allowed", "http://us.auth.example.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Start needs AllowInsecureHTTP: the test server is http://
			// loopback. The flag is flipped to the case's value afterwards so
			// the retarget check is what's under test.
			c := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
			f, err := c.Start(context.Background())
			if err != nil {
				t.Fatalf("Start() error = %v", err)
			}
			t.Cleanup(func() { _ = f.Close() })
			c.AllowInsecureHTTP = tc.allowInsecureHTTP

			if err := f.SetTokenBaseURL(tc.in); err == nil {
				t.Fatalf("SetTokenBaseURL(%q) = nil, want error", tc.in)
			}
			if got := f.tokenBase(); got != c.BaseURL {
				t.Fatalf("tokenBase() = %q, want the untouched BaseURL %q", got, c.BaseURL)
			}
		})
	}
}
