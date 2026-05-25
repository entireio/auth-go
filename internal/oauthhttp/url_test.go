package oauthhttp

import (
	"errors"
	"strings"
	"testing"
)

// TestResolveURL_RejectsAbsolutePath pins the redirect defence: an
// absolute or scheme-relative reference would replace BaseURL's host
// via url.ResolveReference, sending the request — and any bearer it
// carries — to whatever host the caller's configuration source
// supplied. The library refuses.
func TestResolveURL_RejectsAbsolutePath(t *testing.T) {
	t.Parallel()
	cases := []string{
		"https://attacker.example.com/path",
		"http://attacker.example.com/path",
		"//attacker.example.com/path",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			_, err := ResolveURL("https://auth.example.com", p, false)
			if err == nil {
				t.Fatalf("ResolveURL(%q) returned nil error, want ErrAbsolutePath", p)
			}
			if !errors.Is(err, ErrAbsolutePath) {
				t.Fatalf("err = %v, want ErrAbsolutePath", err)
			}
		})
	}
}

// TestResolveURL_RejectsInsecureHTTP pins that http:// BaseURLs are
// rejected unless the caller explicitly opts in. Production must
// never opt in.
func TestResolveURL_RejectsInsecureHTTP(t *testing.T) {
	t.Parallel()
	_, err := ResolveURL("http://auth.example.com", "/path", false)
	if !errors.Is(err, ErrInsecureBaseURL) {
		t.Fatalf("err = %v, want ErrInsecureBaseURL", err)
	}
	// Opt-in still only permits loopback hosts.
	_, err = ResolveURL("http://auth.example.com", "/path", true)
	if !errors.Is(err, ErrInsecureBaseURL) {
		t.Fatalf("err = %v, want ErrInsecureBaseURL for non-loopback http", err)
	}

	got, err := ResolveURL("http://127.0.0.1:8080", "/path", true)
	if err != nil {
		t.Fatalf("ResolveURL(loopback http, allowInsecure) err = %v", err)
	}
	if !strings.HasPrefix(got, "http://127.0.0.1:8080/") {
		t.Fatalf("got = %q, want http://127.0.0.1:8080/...", got)
	}
}

// TestResolveURL_RejectsUnsupportedScheme pins that anything that's
// not http or https is refused at the source.
func TestResolveURL_RejectsUnsupportedScheme(t *testing.T) {
	t.Parallel()
	for _, scheme := range []string{"ftp", "file", "gopher", "javascript"} {
		t.Run(scheme, func(t *testing.T) {
			t.Parallel()
			if _, err := ResolveURL(scheme+"://example.com", "/path", true); err == nil {
				t.Fatalf("ResolveURL(scheme=%s) returned nil error", scheme)
			}
		})
	}
}

// TestResolveURL_HappyPath sanity check: ordinary relative paths
// resolve as expected, with both rooted and unrooted forms.
func TestResolveURL_HappyPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		base, path, want string
	}{
		{"https://auth.example.com", "/oauth/token", "https://auth.example.com/oauth/token"},
		{"https://auth.example.com/", "oauth/token", "https://auth.example.com/oauth/token"},
		{"https://auth.example.com/api", "token", "https://auth.example.com/token"},
	}
	for _, tc := range cases {
		t.Run(tc.base+"+"+tc.path, func(t *testing.T) {
			t.Parallel()
			got, err := ResolveURL(tc.base, tc.path, false)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != tc.want {
				t.Fatalf("ResolveURL(%q,%q) = %q, want %q", tc.base, tc.path, got, tc.want)
			}
		})
	}
}
