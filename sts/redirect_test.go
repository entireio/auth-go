package sts_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/entireio/auth-go/sts"
)

// A token exchange POSTs the user's core bearer as subject_token. net/http
// replays a POST body on a 307, so an authorization server that answers with
// a redirect would otherwise hand that bearer to the origin it names.
func TestExchange_RefusesCrossOriginRedirect(t *testing.T) {
	t.Parallel()

	var elsewhereSaw string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		elsewhereSaw = r.PostFormValue("subject_token")
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

	c := &sts.Client{BaseURL: issuer.URL, Path: "/oauth/token", AllowInsecureHTTP: true}
	got, err := c.Exchange(context.Background(), sts.ExchangeRequest{
		SubjectToken:       "fake-subject-token-for-test",
		SubjectTokenType:   sts.SubjectTokenTypeAccessToken,
		RequestedTokenType: sts.SubjectTokenTypeAccessToken,
		ClientID:           "test-client",
	})
	if !errors.Is(err, sts.ErrUnexpectedRedirect) {
		t.Fatalf("want ErrUnexpectedRedirect, got token=%v err=%v", got, err)
	}
	if elsewhereSaw != "" {
		t.Fatalf("subject token reached the redirect target: %q", elsewhereSaw)
	}
}
