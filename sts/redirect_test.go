package sts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestExchangeRefusesCrossHostRedirect is a two-server reproduction: the token
// endpoint answers 307, and without the policy net/http replays the POST body
// — carrying subject_token — at the redirect target. Headers are stripped on a
// cross-host redirect; the body never was.
//
// The leak is asserted before the error, deliberately: a t.Fatal on the error
// would abort first, so a regression would report only "no error" and never
// that the token reached the attacker.
func TestExchangeRefusesCrossHostRedirect(t *testing.T) {
	t.Parallel()

	const secretSubjectToken = "the-users-real-login-jwt"

	// Written from the attacker handler's goroutine, read from the test's.
	// The handler must never run at all while the guard holds; atomic so a
	// regression surfaces as a failed assertion rather than a data race.
	var attackerSawToken atomic.Bool
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil && r.PostForm.Get("subject_token") == secretSubjectToken {
			attackerSawToken.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, `{"access_token":"attacker-minted","token_type":"Bearer","expires_in":900}`)
	}))
	t.Cleanup(attacker.Close)

	// newTestClient gives this the package's per-server transport rather than
	// http.DefaultTransport, which matters here: httptest.Server.Close calls
	// http.DefaultTransport.CloseIdleConnections, so a shared pool lets any
	// parallel test's teardown reach into this one's connections.
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// Stands in for an open redirect or a misconfigured proxy in front
		// of an otherwise legitimate authorization server.
		http.Redirect(w, r, attacker.URL+testTokenPath, http.StatusTemporaryRedirect)
	})
	ts, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       secretSubjectToken,
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: SubjectTokenTypeAccessToken,
		Audience:           c.BaseURL,
		ClientID:           "test-client",
	})

	if attackerSawToken.Load() {
		t.Errorf("subject_token reached %s, a host the caller never targeted", attacker.URL)
	}
	if err == nil {
		t.Fatalf("want a refused cross-host redirect, got token set %v", ts)
	}
	// The attacker's access_token must not be handed back as if the real
	// authorization server had issued it.
	if ts != nil {
		t.Errorf("want no token set on a refused redirect, got %v", ts)
	}
}
