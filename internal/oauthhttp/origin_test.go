package oauthhttp

import "testing"

func TestNormalizeOriginURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", "https://api.example.com", "https://api.example.com"},
		{"trailing slash", "https://api.example.com/", "https://api.example.com"},
		{"upper scheme", "HTTPS://api.example.com", "https://api.example.com"},
		{"upper host", "https://API.Example.COM", "https://api.example.com"},
		{"default https port", "https://api.example.com:443", "https://api.example.com"},
		{"default http port", "http://api.example.com:80/", "http://api.example.com"},
		{"non-default port preserved", "https://api.example.com:8443", "https://api.example.com:8443"},
		{"path preserved (sans trailing slash)", "https://api.example.com/v2/", "https://api.example.com/v2"},
		{"non-URL audience passes through", "urn:example:cli", "urn:example:cli"},
		{"bare string passes through", "some-audience", "some-audience"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeOriginURL(tc.in); got != tc.want {
				t.Errorf("NormalizeOriginURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidateOriginURL(t *testing.T) {
	t.Parallel()
	got, err := ValidateOriginURL("https://API.example.com:443/", false, "Resource")
	if err != nil {
		t.Fatalf("ValidateOriginURL: %v", err)
	}
	if got != "https://api.example.com" {
		t.Fatalf("ValidateOriginURL = %q, want normalised origin", got)
	}

	bad := []string{
		"api.example.com",
		"http://api.example.com",
		"https://user:pass@api.example.com",
		"https://api.example.com/path",
		"https://api.example.com//",
		"https://api.example.com?x=1",
		"https://api.example.com#frag",
	}
	for _, raw := range bad {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if _, err := ValidateOriginURL(raw, false, "Resource"); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestValidateOriginURL_AllowsLoopbackHTTPWhenExplicitlyEnabled(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw  string
		want string
	}{
		{"http://127.0.0.1:8080/", "http://127.0.0.1:8080"},
		{"http://LOCALHOST:8080/", "http://localhost:8080"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			got, err := ValidateOriginURL(tc.raw, true, "Resource")
			if err != nil {
				t.Fatalf("ValidateOriginURL(loopback): %v", err)
			}
			if got != tc.want {
				t.Fatalf("ValidateOriginURL(loopback) = %q, want %q", got, tc.want)
			}
		})
	}
}
