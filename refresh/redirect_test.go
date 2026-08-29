package refresh_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/entireio/auth-go/refresh"
)

// The refresh grant POSTs the refresh token in the request body, which
// net/http replays on a 307. A redirect must not carry it off the issuer.
func TestRefresh_RefusesCrossOriginRedirect(t *testing.T) {
	t.Parallel()

	var elsewhereSaw string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		elsewhereSaw = r.PostFormValue("refresh_token")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"unexpected","token_type":"Bearer","expires_in":300}`))
	}))
	defer elsewhere.Close()

	target, err := url.Parse(elsewhere.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	target.Host = "localhost:" + target.Port()

	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.String()+"/token", http.StatusTemporaryRedirect)
	}))
	defer issuer.Close()

	c := &refresh.Client{BaseURL: issuer.URL, Path: "/oauth/token", AllowInsecureHTTP: true}
	got, err := c.Refresh(context.Background(), refresh.Request{
		RefreshToken: "fake-refresh-token-for-test",
		ClientID:     "test-client",
	})
	if !errors.Is(err, refresh.ErrUnexpectedRedirect) {
		t.Fatalf("want ErrUnexpectedRedirect, got token=%v err=%v", got, err)
	}
	if elsewhereSaw != "" {
		t.Fatalf("refresh token reached the redirect target: %q", elsewhereSaw)
	}
}
