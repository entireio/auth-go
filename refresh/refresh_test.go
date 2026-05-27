package refresh_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/entireio/auth-go/refresh"
)

func newServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestRefresh_SuccessRotates(t *testing.T) {
	t.Parallel()
	var gotForm url.Values
	var gotAuthUser string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		gotAuthUser, _, _ = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-login-jwt","refresh_token":"rt-2","token_type":"Bearer","expires_in":28800,"scope":"cli"}`))
	})

	c := &refresh.Client{BaseURL: srv.URL, Path: "/oauth/token", AllowInsecureHTTP: true}
	ts, err := c.Refresh(context.Background(), refresh.Request{
		RefreshToken: "rt-1",
		ClientID:     "my-cli",
		Extra:        url.Values{"client_id": {"my-cli"}},
	})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if ts.AccessToken != "new-login-jwt" || ts.RefreshToken != "rt-2" {
		t.Fatalf("tokens = %q / %q, want new-login-jwt / rt-2", ts.AccessToken, ts.RefreshToken)
	}
	if ts.ExpiresAt.IsZero() {
		t.Fatal("ExpiresAt is zero, want derived from expires_in")
	}
	if gotForm.Get("grant_type") != "refresh_token" {
		t.Fatalf("grant_type = %q", gotForm.Get("grant_type"))
	}
	if gotForm.Get("refresh_token") != "rt-1" {
		t.Fatalf("refresh_token = %q", gotForm.Get("refresh_token"))
	}
	if gotAuthUser != "my-cli" {
		t.Fatalf("basic-auth user = %q, want my-cli", gotAuthUser)
	}
	if gotForm.Get("client_id") != "my-cli" {
		t.Fatalf("form client_id = %q, want my-cli", gotForm.Get("client_id"))
	}
	if ts.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q, want Bearer", ts.TokenType)
	}
	if ts.Scope != "cli" {
		t.Fatalf("Scope = %q, want cli", ts.Scope)
	}
}

func TestRefresh_InvalidGrantSentinel(t *testing.T) {
	t.Parallel()
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"token revoked"}`))
	})
	c := &refresh.Client{BaseURL: srv.URL, Path: "/oauth/token", AllowInsecureHTTP: true}
	_, err := c.Refresh(context.Background(), refresh.Request{RefreshToken: "rt", ClientID: "cli"})
	if !errors.Is(err, refresh.ErrInvalidGrant) {
		t.Fatalf("err = %v, want ErrInvalidGrant", err)
	}
	if !strings.Contains(err.Error(), "token revoked") {
		t.Fatalf("err = %v, want sanitized description appended", err)
	}
}

func TestRefresh_OtherErrorWrapped(t *testing.T) {
	t.Parallel()
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	})
	c := &refresh.Client{BaseURL: srv.URL, Path: "/oauth/token", AllowInsecureHTTP: true}
	_, err := c.Refresh(context.Background(), refresh.Request{RefreshToken: "rt", ClientID: "cli"})
	if err == nil || errors.Is(err, refresh.ErrInvalidGrant) {
		t.Fatalf("err = %v, want non-invalid_grant error", err)
	}
	if !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("err = %v, want code surfaced", err)
	}
}

func TestRefresh_TolerantExpiresIn(t *testing.T) {
	t.Parallel()
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"jwt","token_type":"Bearer"}`))
	})
	c := &refresh.Client{BaseURL: srv.URL, Path: "/oauth/token", AllowInsecureHTTP: true}
	ts, err := c.Refresh(context.Background(), refresh.Request{RefreshToken: "rt", ClientID: "cli"})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !ts.ExpiresAt.IsZero() {
		t.Fatalf("ExpiresAt = %v, want zero when expires_in omitted", ts.ExpiresAt)
	}
}

func TestRefresh_MissingAccessToken(t *testing.T) {
	t.Parallel()
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"Bearer"}`))
	})
	c := &refresh.Client{BaseURL: srv.URL, Path: "/oauth/token", AllowInsecureHTTP: true}
	if _, err := c.Refresh(context.Background(), refresh.Request{RefreshToken: "rt", ClientID: "cli"}); err == nil {
		t.Fatal("expected error for 200 with no access_token")
	}
}

func TestRefresh_RejectsInsecureBaseURL(t *testing.T) {
	t.Parallel()
	c := &refresh.Client{BaseURL: "http://auth.example.com", Path: "/oauth/token"}
	_, err := c.Refresh(context.Background(), refresh.Request{RefreshToken: "rt", ClientID: "cli"})
	if !errors.Is(err, refresh.ErrInsecureBaseURL) {
		t.Fatalf("err = %v, want ErrInsecureBaseURL", err)
	}
}

func TestRefresh_ValidatesRequest(t *testing.T) {
	t.Parallel()
	c := &refresh.Client{BaseURL: "https://auth.example.com", Path: "/oauth/token"}
	if _, err := c.Refresh(context.Background(), refresh.Request{ClientID: "cli"}); err == nil {
		t.Fatal("expected error for empty RefreshToken")
	}
}

func TestRequest_RedactsRefreshToken(t *testing.T) {
	t.Parallel()
	r := refresh.Request{RefreshToken: "super-secret", ClientID: "cli"}
	if strings.Contains(r.String(), "super-secret") {
		t.Fatalf("String() leaked refresh token: %s", r.String())
	}
}

func TestNew_RequiresFields(t *testing.T) {
	t.Parallel()
	if _, err := refresh.New(&refresh.Client{Path: "/p"}); err == nil {
		t.Fatal("want error for empty BaseURL")
	}
	if _, err := refresh.New(&refresh.Client{BaseURL: "https://x"}); err == nil {
		t.Fatal("want error for empty Path")
	}
}

func TestRefresh_PublicClientOmitsBasicAuth(t *testing.T) {
	t.Parallel()
	var hadAuthHeader bool
	var formClientID string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _, hadAuthHeader = r.BasicAuth()
		_ = r.ParseForm()
		formClientID = r.PostForm.Get("client_id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"jwt","expires_in":3600}`))
	})
	c := &refresh.Client{BaseURL: srv.URL, Path: "/oauth/token", AllowInsecureHTTP: true}
	if _, err := c.Refresh(context.Background(), refresh.Request{RefreshToken: "rt"}); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if hadAuthHeader {
		t.Error("public client (empty ClientID) must not send an Authorization: Basic header")
	}
	if formClientID != "" {
		t.Errorf("form client_id = %q, want empty for a public client with no ClientID", formClientID)
	}
}

func TestRefresh_NowSeamDerivesExpiry(t *testing.T) {
	t.Parallel()
	fixed := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"jwt","expires_in":3600}`))
	})
	c := &refresh.Client{BaseURL: srv.URL, Path: "/oauth/token", AllowInsecureHTTP: true}
	refresh.SetNowForTest(t, c, func() time.Time { return fixed })
	ts, err := c.Refresh(context.Background(), refresh.Request{RefreshToken: "rt", ClientID: "cli"})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !ts.ExpiresAt.Equal(fixed.Add(time.Hour)) {
		t.Fatalf("ExpiresAt = %v, want %v", ts.ExpiresAt, fixed.Add(time.Hour))
	}
}
