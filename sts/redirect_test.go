package sts

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// downgradeRT answers an https request with a redirect to the SAME host over
// http, and records every request it is asked to send.
//
// A recording RoundTripper rather than two httptest servers, deliberately: two
// listeners have different ports, so the host restriction would refuse the hop
// and the test would pass without exercising the TLS floor at all. Here only
// the scheme changes.
type downgradeRT struct {
	mu     sync.Mutex
	sent   []string
	status int
}

func (d *downgradeRT) RoundTrip(req *http.Request) (*http.Response, error) {
	d.mu.Lock()
	d.sent = append(d.sent, req.URL.Scheme+"://"+req.URL.Host+req.URL.Path)
	d.mu.Unlock()

	h := http.Header{}
	if req.URL.Scheme == "https" {
		h.Set("Location", "http://"+req.URL.Host+req.URL.Path)
		return &http.Response{StatusCode: d.status, Header: h, Body: http.NoBody, Request: req}, nil
	}
	// Reached only if the downgrade was followed; answer as a working endpoint
	// so a regression shows up as a leak rather than a transport error.
	h.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: http.StatusOK, Header: h, Request: req,
		Body: io.NopCloser(strings.NewReader(`{"access_token":"leaked","token_type":"Bearer","expires_in":900}`)),
	}, nil
}

func (d *downgradeRT) requests() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.sent...)
}

// TestExchangeRefusesTLSDowngrade: an https token endpoint answering 307/308
// with an http Location must not get the form body replayed in clear. The
// subject_token is a login JWT, and net/http replays a 307/308 body verbatim.
func TestExchangeRefusesTLSDowngrade(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			rt := &downgradeRT{status: status}
			// AllowInsecureHTTP stays false: the base URL is https, and the
			// downgrade must be refused on the redirect, not on the initial URL.
			c := &Client{Transport: rt, BaseURL: "https://issuer.example", Path: testTokenPath}
			ts, err := c.Exchange(context.Background(), ExchangeRequest{
				SubjectToken:       "the-users-real-login-jwt",
				SubjectTokenType:   SubjectTokenTypeJWT,
				RequestedTokenType: SubjectTokenTypeAccessToken,
				Audience:           "https://issuer.example",
				ClientID:           "test-client",
			})

			sent := rt.requests()
			if len(sent) != 1 {
				t.Errorf("transport saw %d requests (%v), want only the https one", len(sent), sent)
			}
			for _, s := range sent {
				if strings.HasPrefix(s, "http://") {
					t.Errorf("the plaintext destination received a request: %s", s)
				}
			}
			if err == nil {
				t.Fatalf("want a refused downgrade, got token set %v", ts)
			}
			if ts != nil {
				t.Errorf("want no token set on a refused downgrade, got %v", ts)
			}
		})
	}
}
