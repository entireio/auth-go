package oauthhttp_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/entireio/auth-go/internal/oauthhttp"
)

// post sends a form body through hc and reports what the final handler
// saw, so a test can assert whether the credential travelled.
func post(t *testing.T, hc *http.Client, endpoint string, form url.Values) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if resp != nil && err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	return resp, err
}

// A 307 replays the request body verbatim. If the redirect is followed
// across origins the credential in that body reaches the new origin, so
// CredentialHTTPClient must refuse before issuing the redirected request.
func TestCredentialHTTPClient_RefusesCrossOriginRedirect(t *testing.T) {
	t.Parallel()

	var elsewhereSaw string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		elsewhereSaw = r.PostFormValue("refresh_token")
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()

	// Rewrite the redirect target to "localhost" so it is a different
	// origin from the 127.0.0.1 the request was aimed at, while still
	// resolving on the test machine.
	target, err := url.Parse(elsewhere.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	target.Host = "localhost:" + target.Port()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.String()+"/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	_, err = post(t, oauthhttp.CredentialHTTPClient(nil), origin.URL+"/token",
		url.Values{"refresh_token": {"fake-refresh-token-for-test"}})
	if !errors.Is(err, oauthhttp.ErrUnexpectedRedirect) {
		t.Fatalf("want ErrUnexpectedRedirect, got %v", err)
	}
	if elsewhereSaw != "" {
		t.Fatalf("credential reached the redirect target: %q", elsewhereSaw)
	}
}

// A redirect from https to plaintext http is an origin change, so the
// same guard covers it. Without the guard the body would be re-POSTed in
// the clear, routing around the AllowInsecureHTTP policy the flow
// packages apply to their configured base URL.
func TestCredentialHTTPClient_RefusesDowngradeToPlaintext(t *testing.T) {
	t.Parallel()

	var plaintextSaw string
	plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		plaintextSaw = r.PostFormValue("subject_token")
		w.WriteHeader(http.StatusOK)
	}))
	defer plaintext.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plaintext.URL+"/downgraded", http.StatusTemporaryRedirect)
	}))
	defer secure.Close()

	hc := oauthhttp.CredentialHTTPClient(secure.Client().Transport)
	_, err := post(t, hc, secure.URL+"/token",
		url.Values{"subject_token": {"fake-subject-token-for-test"}})
	if !errors.Is(err, oauthhttp.ErrUnexpectedRedirect) {
		t.Fatalf("want ErrUnexpectedRedirect, got %v", err)
	}
	if plaintextSaw != "" {
		t.Fatalf("credential reached the plaintext origin: %q", plaintextSaw)
	}
}

// Same-origin redirects stay legal: a path rewrite or trailing-slash
// normalisation returns the body to the host the caller already trusts.
func TestCredentialHTTPClient_AllowsSameOriginRedirect(t *testing.T) {
	t.Parallel()

	var finalSaw string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			http.Redirect(w, r, srv.URL+"/token/", http.StatusTemporaryRedirect)
			return
		}
		_ = r.ParseForm()
		finalSaw = r.PostFormValue("subject_token")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := post(t, oauthhttp.CredentialHTTPClient(nil), srv.URL+"/token",
		url.Values{"subject_token": {"fake-subject-token-for-test"}})
	if err != nil {
		t.Fatalf("same-origin redirect should be followed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if finalSaw != "fake-subject-token-for-test" {
		t.Fatalf("final handler saw %q, want the posted body", finalSaw)
	}
}

// Replacing net/http's CheckRedirect replaces its hop ceiling too, so
// the policy has to reimpose one or a same-origin loop never terminates.
func TestCredentialHTTPClient_BoundsSameOriginRedirectLoop(t *testing.T) {
	t.Parallel()

	hops := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, srv.URL+"/loop", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	_, err := post(t, oauthhttp.CredentialHTTPClient(nil), srv.URL+"/loop", url.Values{})
	if err == nil {
		t.Fatal("want an error from the redirect ceiling, got nil")
	}
	if hops > 20 {
		t.Fatalf("redirect loop was not bounded: %d hops", hops)
	}
}

// The device-authorization request carries no credential and is
// deliberately still allowed to follow a front door's redirect.
func TestHTTPClient_StillFollowsRedirects(t *testing.T) {
	t.Parallel()

	reached := false
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/dispatched", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	if _, err := post(t, oauthhttp.HTTPClient(nil), origin.URL+"/device", url.Values{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reached {
		t.Fatal("permissive client did not follow the redirect")
	}
}
