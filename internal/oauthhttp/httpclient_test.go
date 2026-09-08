package oauthhttp

import (
	"net/http"
	"net/url"
	"strings"
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

// TestHTTPClientFollowingCrossHostRedirectsKeepsTLS pins what the
// device-authorization client opts out of and what it does not. It is exempt
// from the HOST restriction, because its cross-host 307 is how regional
// routing works. It is not exempt from TLS: its response carries a redeemable
// device_code, so a plaintext hop exposes a credential even though the
// library-built request body is public.
func TestHTTPClientFollowingCrossHostRedirectsKeepsTLS(t *testing.T) {
	t.Parallel()
	c := HTTPClientFollowingCrossHostRedirects(nil)
	if c.CheckRedirect == nil {
		t.Fatal("the device-authorization client must still enforce the TLS floor")
	}
	if c.Transport != HTTPClient(nil).Transport {
		t.Error("it must differ from HTTPClient only in its redirect policy")
	}
}

// TestRedirectPolicyMatrix runs both constructors' policies over the full
// compatibility matrix, so the host exemption and the TLS floor cannot drift
// apart. "ordinary" is every credential-bearing flow; "deviceAuth" is the one
// exemption.
func TestRedirectPolicyMatrix(t *testing.T) {
	t.Parallel()

	ordinary := HTTPClient(nil).CheckRedirect
	deviceAuth := HTTPClientFollowingCrossHostRedirects(nil).CheckRedirect

	tenHops := make([]*http.Request, 10)
	for i := range tenHops {
		tenHops[i] = &http.Request{URL: mustParseURL(t, "https://core.example/oauth/token")}
	}

	cases := []struct {
		name          string
		next          string
		via           []string
		wantOrdinary  bool // true = refuse
		wantDeviceRef bool
	}{
		{name: "https to https, same host and port", next: "https://core.example:8443/t", via: []string{"https://core.example:8443/t"}},
		{name: "https to https, different host", next: "https://other.example/t", via: []string{"https://core.example/t"}, wantOrdinary: true},
		{name: "https to https, changed port", next: "https://core.example:8443/t", via: []string{"https://core.example/t"}, wantOrdinary: true},
		{name: "https to http, same host", next: "http://core.example/t", via: []string{"https://core.example/t"}, wantOrdinary: true, wantDeviceRef: true},
		{name: "https to http, different host", next: "http://other.example/t", via: []string{"https://core.example/t"}, wantOrdinary: true, wantDeviceRef: true},
		{name: "http to https, unchanged host", next: "https://core.example/t", via: []string{"http://core.example/t"}},
		{name: "loopback http to http", next: "http://127.0.0.1:8080/t", via: []string{"http://127.0.0.1:8080/t"}},
		{name: "http then https then http refuses the last hop", next: "http://core.example/t", via: []string{"http://core.example/t", "https://core.example/t"}, wantOrdinary: true, wantDeviceRef: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			via := make([]*http.Request, 0, len(tc.via))
			for _, v := range tc.via {
				via = append(via, &http.Request{URL: mustParseURL(t, v)})
			}
			next := &http.Request{URL: mustParseURL(t, tc.next)}

			if got := ordinary(next, via) != nil; got != tc.wantOrdinary {
				t.Errorf("ordinary refused=%v, want %v", got, tc.wantOrdinary)
			}
			if got := deviceAuth(next, via) != nil; got != tc.wantDeviceRef {
				t.Errorf("deviceAuth refused=%v, want %v", got, tc.wantDeviceRef)
			}
		})
	}

	t.Run("hop cap applies to both", func(t *testing.T) {
		t.Parallel()
		next := &http.Request{URL: mustParseURL(t, "https://core.example/oauth/token")}
		if ordinary(next, tenHops) == nil {
			t.Error("ordinary must refuse at the hop cap")
		}
		if deviceAuth(next, tenHops) == nil {
			t.Error("deviceAuth must refuse at the hop cap")
		}
	})
}

// TestRedirectErrorTextCarriesNoURL pins that the TLS refusal names the scheme
// it refused and nothing more: a full URL can carry a token in its query, and
// this message reaches logs and user-facing errors.
func TestRedirectErrorTextCarriesNoURL(t *testing.T) {
	t.Parallel()
	next := &http.Request{URL: mustParseURL(t, "http://core.example/oauth/token?code=SECRET-VALUE")}
	via := []*http.Request{{URL: mustParseURL(t, "https://core.example/oauth/token?code=SECRET-VALUE")}}
	err := HTTPClient(nil).CheckRedirect(next, via)
	if err == nil {
		t.Fatal("want a refusal")
	}
	if strings.Contains(err.Error(), "SECRET-VALUE") {
		t.Errorf("refusal text must not carry URL components: %q", err)
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
