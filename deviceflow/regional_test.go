package deviceflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"sync/atomic"
	"testing"
)

// Tests for learning the responding (regional) origin off a redirected
// device-authorization request and polling that region's token endpoint.

const testDeviceCodeJSON = `{"device_code":"dev-1","user_code":"WDJB-MJHT",` +
	`"verification_uri":"https://us.auth.example.com/device","expires_in":600,"interval":5}`

func TestStartDeviceAuth_ResponseOriginIsBaseURLWithoutRedirect(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, testDeviceCodeJSON)
	})

	dc, err := c.StartDeviceAuth(context.Background())
	if err != nil {
		t.Fatalf("StartDeviceAuth() error = %v", err)
	}
	if dc.ResponseOrigin != c.BaseURL {
		t.Fatalf("ResponseOrigin = %q, want %q", dc.ResponseOrigin, c.BaseURL)
	}
}

// TestStartDeviceAuth_ResponseOriginFollowsRedirect models the apex front
// door 307-ing POST /device_authorization at a regional core. 307 preserves
// the method and body, so the regional core sees the same form post.
func TestStartDeviceAuth_ResponseOriginFollowsRedirect(t *testing.T) {
	t.Parallel()

	var gotClientID string
	regional := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("regional method = %q, want POST (307 must preserve it)", r.Method)
		}
		mustReadForm(t, r)
		gotClientID = r.PostForm.Get("client_id")
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, testDeviceCodeJSON)
	}))
	t.Cleanup(regional.Close)

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, regional.URL+testDeviceCodePath, http.StatusTemporaryRedirect)
	})

	dc, err := c.StartDeviceAuth(context.Background())
	if err != nil {
		t.Fatalf("StartDeviceAuth() error = %v", err)
	}
	if dc.ResponseOrigin != regional.URL {
		t.Fatalf("ResponseOrigin = %q, want the redirected-to origin %q", dc.ResponseOrigin, regional.URL)
	}
	if dc.DeviceCode != "dev-1" {
		t.Fatalf("DeviceCode = %q, want dev-1", dc.DeviceCode)
	}
	if gotClientID != testClientID {
		t.Fatalf("regional saw client_id = %q, want %q (body must survive the 307)", gotClientID, testClientID)
	}
}

// TestPollDeviceAuth_UsesTokenBaseURL pins the whole point of the override:
// the front door serves no token endpoint, so a poll that ignored
// TokenBaseURL would 404 instead of returning a token.
func TestPollDeviceAuth_UsesTokenBaseURL(t *testing.T) {
	t.Parallel()

	regional := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != testTokenPath {
			t.Errorf("regional path = %q, want %q", r.URL.Path, testTokenPath)
		}
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, `{"access_token":"at-regional","token_type":"Bearer","expires_in":3600}`)
	}))
	t.Cleanup(regional.Close)

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "apex serves no token endpoint", http.StatusNotFound)
	})
	c.TokenBaseURL = regional.URL

	ts, err := c.PollDeviceAuth(context.Background(), "dev-1")
	if err != nil {
		t.Fatalf("PollDeviceAuth() error = %v", err)
	}
	if ts.AccessToken != "at-regional" {
		t.Fatalf("AccessToken = %q, want at-regional", ts.AccessToken)
	}
}

func TestPollDeviceAuth_FallsBackToBaseURL(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, `{"access_token":"at-base","token_type":"Bearer"}`)
	})

	ts, err := c.PollDeviceAuth(context.Background(), "dev-1")
	if err != nil {
		t.Fatalf("PollDeviceAuth() error = %v", err)
	}
	if ts.AccessToken != "at-base" {
		t.Fatalf("AccessToken = %q, want at-base", ts.AccessToken)
	}
}

// TestPollDeviceAuth_RefusesCrossHostRedirect is the other half of the split
// TestStartDeviceAuth_ResponseOriginFollowsRedirect pins. The
// device-authorization request follows a cross-host redirect because its body
// carries no credential; the poll's body carries the device code, which
// redeems for the user's tokens, so its redirect must be refused. One
// permissive client shared by both calls is the bug this guards against.
func TestPollDeviceAuth_RefusesCrossHostRedirect(t *testing.T) {
	t.Parallel()

	const deviceCode = "dev-1"

	var attackerSawDeviceCode atomic.Bool
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil && r.PostForm.Get("device_code") == deviceCode {
			attackerSawDeviceCode.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, `{"access_token":"attacker-minted","token_type":"Bearer","expires_in":900}`)
	}))
	t.Cleanup(attacker.Close)

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+testTokenPath, http.StatusTemporaryRedirect)
	})

	ts, err := c.PollDeviceAuth(context.Background(), deviceCode)

	if attackerSawDeviceCode.Load() {
		t.Errorf("device_code reached %s, a host the caller never targeted", attacker.URL)
	}
	if err == nil {
		t.Fatalf("want a refused cross-host redirect, got token set %v", ts)
	}
	if ts != nil {
		t.Errorf("want no token set on a refused redirect, got %v", ts)
	}
}

// TestStartDeviceAuth_BodyCarriesNoCredential is the tripwire under the
// redirect exemption above. deviceAuthHTTPClient follows a cross-host
// redirect, and the only thing that makes that acceptable is that this
// request's body carries nothing secret: client_id is a public identifier,
// scope is a request parameter, and a confidential client's secret rides in
// Basic auth, which net/http strips when the host changes.
//
// That is a property of the form StartDeviceAuth builds, and today it holds
// structurally — the body is a closed set the library assembles itself, with
// no caller extension point. sts.ExchangeRequest.Extra is exactly such an
// extension point on the sibling flow, so "deviceflow.Client grows Extra for
// parity" is a plausible, innocuous-looking change that would quietly turn
// the exemption into a credential leak. Asserting the key set here means that
// change arrives as a failing test next to the reason, rather than as a leak.
func TestStartDeviceAuth_BodyCarriesNoCredential(t *testing.T) {
	t.Parallel()

	var gotKeys []string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mustReadForm(t, r)
		for k := range r.PostForm {
			gotKeys = append(gotKeys, k)
		}
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, testDeviceCodeJSON)
	})
	c.Scope = "openid"

	if _, err := c.StartDeviceAuth(context.Background()); err != nil {
		t.Fatalf("StartDeviceAuth() error = %v", err)
	}

	sort.Strings(gotKeys)
	want := []string{"client_id", "scope"}
	if !slices.Equal(gotKeys, want) {
		t.Errorf("device-authorization body carries %v, want exactly %v.\n"+
			"A new field here invalidates the cross-host redirect exemption in "+
			"deviceAuthHTTPClient: re-check that it carries no credential, or "+
			"move this request onto the guarded oauthhttp.HTTPClient.", gotKeys, want)
	}
}
