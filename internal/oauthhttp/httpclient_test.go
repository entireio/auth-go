package oauthhttp

import (
	"net/http"
	"net/url"
	"testing"
)

// TestHTTPClientSetsRedirectPolicy pins that the shared constructor — the one
// seam sts, refresh, authcode and deviceflow all build their client from —
// installs the cross-host guard. A client handed out without it is the whole
// vulnerability, and it is invisible until a server actually redirects.
//
// It exercises the wired policy rather than asserting it is non-nil: a client
// carrying a permissive CheckRedirect passes the nil check and leaks anyway,
// which is the regression worth catching.
func TestHTTPClientSetsRedirectPolicy(t *testing.T) {
	t.Parallel()
	c := HTTPClient(nil)
	if c.CheckRedirect == nil {
		t.Fatal("HTTPClient must install a CheckRedirect policy")
	}
	offHost := &http.Request{URL: mustParseURL(t, "https://attacker.example/oauth/token")}
	via := []*http.Request{{URL: mustParseURL(t, "https://core.example/oauth/token")}}
	if err := c.CheckRedirect(offHost, via); err == nil {
		t.Error("HTTPClient's policy must refuse a cross-host redirect")
	}
}

// TestHTTPClientFollowingCrossHostRedirectsOptsOut pins the opt-out
// constructor as the exact inverse: same client, guard removed. Built by
// subtraction from HTTPClient, so this also catches the two drifting apart.
func TestHTTPClientFollowingCrossHostRedirectsOptsOut(t *testing.T) {
	t.Parallel()
	if HTTPClientFollowingCrossHostRedirects(nil).CheckRedirect != nil {
		t.Error("the opt-out constructor must not install a redirect policy")
	}
	if HTTPClientFollowingCrossHostRedirects(nil).Transport != HTTPClient(nil).Transport {
		t.Error("the opt-out constructor must differ from HTTPClient only in CheckRedirect")
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestRejectCrossHostRedirect(t *testing.T) {
	t.Parallel()

	req := func(rawURL string) *http.Request {
		u, err := url.Parse(rawURL)
		if err != nil {
			t.Fatalf("parse %q: %v", rawURL, err)
		}
		return &http.Request{URL: u}
	}
	chain := func(urls ...string) []*http.Request {
		out := make([]*http.Request, 0, len(urls))
		for _, u := range urls {
			out = append(out, req(u))
		}
		return out
	}

	cases := []struct {
		name    string
		next    string
		via     []*http.Request
		wantErr bool
	}{
		{name: "first request", next: "https://core.example/oauth/token"},
		{
			name: "same host, path normalised",
			next: "https://core.example/oauth/token/",
			via:  chain("https://core.example/oauth/token"),
		},
		{
			name: "same host, scheme upgraded to https",
			next: "https://core.example/oauth/token",
			via:  chain("http://core.example/oauth/token"),
		},
		{
			name: "same host, different case",
			next: "https://CORE.example/oauth/token",
			via:  chain("https://core.example/oauth/token"),
		},
		{
			name:    "different host",
			next:    "https://attacker.example/oauth/token",
			via:     chain("https://core.example/oauth/token"),
			wantErr: true,
		},
		{
			name:    "different port is a different endpoint",
			next:    "https://core.example:8443/oauth/token",
			via:     chain("https://core.example/oauth/token"),
			wantErr: true,
		},
		{
			name: "hop cap",
			next: "https://core.example/oauth/token",
			via: chain(
				"https://core.example/1", "https://core.example/2", "https://core.example/3",
				"https://core.example/4", "https://core.example/5", "https://core.example/6",
				"https://core.example/7", "https://core.example/8", "https://core.example/9",
				"https://core.example/10",
			),
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := RejectCrossHostRedirect(req(tc.next), tc.via)
			if tc.wantErr && err == nil {
				t.Error("want refusal, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("want follow, got %v", err)
			}
		})
	}
}
