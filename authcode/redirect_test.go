package authcode_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/entireio/auth-go/authcode"
)

// Redeeming the authorization code POSTs both the code and the PKCE
// verifier, and net/http replays that body on a 307. Together they are
// enough to complete the login, so a redirect must not carry them to
// another origin.
func TestExchange_RefusesCrossOriginRedirect(t *testing.T) {
	t.Parallel()

	var sawCode, sawVerifier string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		sawCode = r.PostFormValue("code")
		sawVerifier = r.PostFormValue("code_verifier")
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

	c := &authcode.Client{
		BaseURL: issuer.URL, ClientID: "test-client",
		AuthorizePath: "/authorize", TokenPath: "/oauth/token",
		AllowInsecureHTTP: true,
	}
	flow, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = flow.Close() }()

	got, err := flow.Exchange(context.Background(), "fake-authorization-code-for-test")
	if !errors.Is(err, authcode.ErrUnexpectedRedirect) {
		t.Fatalf("want ErrUnexpectedRedirect, got token=%v err=%v", got, err)
	}
	if sawCode != "" || sawVerifier != "" {
		t.Fatalf("code/verifier reached the redirect target: code=%q verifier-len=%d", sawCode, len(sawVerifier))
	}
}
