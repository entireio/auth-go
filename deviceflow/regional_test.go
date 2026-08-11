package deviceflow

import (
	"context"
	"net/http"
	"net/http/httptest"
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
