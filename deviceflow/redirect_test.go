package deviceflow_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/entireio/auth-go/deviceflow"
)

// crossOriginRedirector returns a server that 307s every request to
// otherURL, rewritten to the "localhost" alias so the target is a
// different origin from the 127.0.0.1 the client was aimed at.
func crossOriginRedirector(t *testing.T, otherURL string) *httptest.Server {
	t.Helper()
	target, err := url.Parse(otherURL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	target.Host = "localhost:" + target.Port()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.String()+r.URL.Path, http.StatusTemporaryRedirect)
	}))
}

// Polling POSTs the device code, which net/http replays on a 307. The
// device code is redeemable for the user's tokens, so a redirect must not
// carry it to another origin.
func TestPollDeviceAuth_RefusesCrossOriginRedirect(t *testing.T) {
	t.Parallel()

	var elsewhereSaw string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		elsewhereSaw = r.PostFormValue("device_code")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"unexpected","token_type":"Bearer","expires_in":300}`))
	}))
	defer elsewhere.Close()

	issuer := crossOriginRedirector(t, elsewhere.URL)
	defer issuer.Close()

	c := &deviceflow.Client{
		BaseURL: issuer.URL, ClientID: "test-client",
		DeviceCodePath: "/device_authorization", TokenPath: "/oauth/token",
		AllowInsecureHTTP: true,
	}
	got, err := c.PollDeviceAuth(context.Background(), "fake-device-code-for-test")
	if !errors.Is(err, deviceflow.ErrUnexpectedRedirect) {
		t.Fatalf("want ErrUnexpectedRedirect, got token=%v err=%v", got, err)
	}
	if elsewhereSaw != "" {
		t.Fatalf("device code reached the redirect target: %q", elsewhereSaw)
	}
}

// The device-authorization request carries no credential, and a
// dispatching front door legitimately redirects it onward. That must keep
// working, with ResponseOrigin reporting where it landed.
func TestStartDeviceAuth_StillFollowsRedirect(t *testing.T) {
	t.Parallel()

	regional := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_code":"fake-device-code-for-test","user_code":"ABCD-EFGH",` +
			`"verification_uri":"https://auth.example.com/device","expires_in":600,"interval":5}`))
	}))
	defer regional.Close()

	frontDoor := crossOriginRedirector(t, regional.URL)
	defer frontDoor.Close()

	c := &deviceflow.Client{
		BaseURL: frontDoor.URL, ClientID: "test-client",
		DeviceCodePath: "/device_authorization", TokenPath: "/oauth/token",
		AllowInsecureHTTP: true,
	}
	dc, err := c.StartDeviceAuth(context.Background())
	if err != nil {
		t.Fatalf("front-door dispatch should still be followed: %v", err)
	}
	if dc.UserCode != "ABCD-EFGH" {
		t.Fatalf("user code = %q", dc.UserCode)
	}
	if dc.ResponseOrigin == "" {
		t.Fatal("ResponseOrigin should report the origin that served the response")
	}
}
