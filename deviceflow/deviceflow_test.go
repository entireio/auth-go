package deviceflow

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testClientID       = "cli"
	testDeviceCodePath = "/oauth/device/code"
	testTokenPath      = "/oauth/token"
)

// freezeClock pins nowFunc for the duration of a test.
func freezeClock(t *testing.T, at time.Time) {
	t.Helper()
	prev := nowFunc
	nowFunc = func() time.Time { return at }
	t.Cleanup(func() { nowFunc = prev })
}

func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	c := &Client{
		HTTP:           srv.Client(),
		BaseURL:        srv.URL,
		ClientID:       testClientID,
		Scope:          "cli",
		DeviceCodePath: testDeviceCodePath,
		TokenPath:      testTokenPath,
	}
	return c, srv
}

func mustReadForm(t *testing.T, r *http.Request) {
	t.Helper()
	if err := r.ParseForm(); err != nil {
		t.Fatalf("parse form: %v", err)
	}
}

func TestStartDeviceAuth_Success(t *testing.T) {
	t.Parallel()

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != testDeviceCodePath {
			t.Errorf("path = %q", r.URL.Path)
		}
		mustReadForm(t, r)
		if got := r.PostForm.Get("client_id"); got != testClientID {
			t.Errorf("client_id = %q", got)
		}
		if got := r.PostForm.Get("scope"); got != "cli" {
			t.Errorf("scope = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"device_code": "dev-1",
			"user_code": "ABCD-EFGH",
			"verification_uri": "https://example.com/cli/auth",
			"verification_uri_complete": "https://example.com/cli/auth?code=ABCD-EFGH",
			"expires_in": 600,
			"interval": 5
		}`)
	})

	got, err := c.StartDeviceAuth(context.Background())
	if err != nil {
		t.Fatalf("StartDeviceAuth() error = %v", err)
	}
	if got.DeviceCode != "dev-1" || got.UserCode != "ABCD-EFGH" || got.ExpiresIn != 600 || got.Interval != 5 {
		t.Fatalf("DeviceCode = %+v", got)
	}
}

func TestStartDeviceAuth_OmitsScopeWhenEmpty(t *testing.T) {
	t.Parallel()

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mustReadForm(t, r)
		if r.PostForm.Has("scope") {
			t.Errorf("scope should not be sent when Client.Scope is empty")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"device_code":"d","user_code":"u","verification_uri":"x","expires_in":1,"interval":1}`)
	})
	c.Scope = ""

	if _, err := c.StartDeviceAuth(context.Background()); err != nil {
		t.Fatalf("StartDeviceAuth() error = %v", err)
	}
}

func TestStartDeviceAuth_RejectsUnknownFields(t *testing.T) {
	t.Parallel()

	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{
			"device_code":"d","user_code":"u","verification_uri":"x","expires_in":1,"interval":1,
			"surprise":"field"
		}`)
	})

	if _, err := c.StartDeviceAuth(context.Background()); err == nil {
		t.Fatal("StartDeviceAuth() with unknown field should fail (strict decode)")
	}
}

func TestStartDeviceAuth_NonOK(t *testing.T) {
	t.Parallel()

	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
	})

	if _, err := c.StartDeviceAuth(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("StartDeviceAuth() error = %v, want invalid_client", err)
	}
}

func TestPollDeviceAuth_Success(t *testing.T) {
	t.Parallel()

	freezeClock(t, time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC))

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mustReadForm(t, r)
		if got := r.PostForm.Get("grant_type"); got != deviceCodeGrantType {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.PostForm.Get("device_code"); got != "dev-1" {
			t.Errorf("device_code = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"access_token":"acc",
			"refresh_token":"ref",
			"token_type":"Bearer",
			"expires_in":3600,
			"scope":"cli"
		}`)
	})

	got, err := c.PollDeviceAuth(context.Background(), "dev-1")
	if err != nil {
		t.Fatalf("PollDeviceAuth() error = %v", err)
	}

	if got.AccessToken != "acc" || got.RefreshToken != "ref" || got.TokenType != "Bearer" || got.Scope != "cli" {
		t.Fatalf("TokenSet = %+v", got)
	}
	want := time.Date(2026, 5, 6, 13, 0, 0, 0, time.UTC)
	if !got.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, want)
	}
}

func TestPollDeviceAuth_TolerantToUnknownFields(t *testing.T) {
	t.Parallel()

	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"acc","extra":"ignored"}`)
	})

	got, err := c.PollDeviceAuth(context.Background(), "dev-1")
	if err != nil {
		t.Fatalf("PollDeviceAuth() error = %v", err)
	}
	if got.AccessToken != "acc" {
		t.Fatalf("AccessToken = %q", got.AccessToken)
	}
}

func TestPollDeviceAuth_ErrorCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code string
		want error
	}{
		{"authorization_pending", ErrAuthorizationPending},
		{"slow_down", ErrSlowDown},
		{"access_denied", ErrAccessDenied},
		{"expired_token", ErrExpiredToken},
		{"invalid_grant", ErrInvalidGrant},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			t.Parallel()
			c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprintf(w, `{"error":%q}`, tt.code)
			})

			_, err := c.PollDeviceAuth(context.Background(), "dev-1")
			if !errors.Is(err, tt.want) {
				t.Fatalf("PollDeviceAuth() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestPollDeviceAuth_ErrorDescription_AppendedToSentinel(t *testing.T) {
	t.Parallel()

	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"device_code unknown"}`)
	})

	_, err := c.PollDeviceAuth(context.Background(), "dev-1")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("PollDeviceAuth() error = %v, want ErrInvalidGrant chain", err)
	}
	if !strings.Contains(err.Error(), "device_code unknown") {
		t.Fatalf("error = %q, want it to include the description", err)
	}
}

func TestPollDeviceAuth_NoDescription_NoTrailingColon(t *testing.T) {
	t.Parallel()

	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	})

	_, err := c.PollDeviceAuth(context.Background(), "dev-1")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("error = %v", err)
	}
	if strings.HasSuffix(err.Error(), ": ") {
		t.Fatalf("error trailing colon-space: %q", err)
	}
}

func TestPollDeviceAuth_UnknownErrorCode(t *testing.T) {
	t.Parallel()

	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"weird_thing"}`)
	})

	_, err := c.PollDeviceAuth(context.Background(), "dev-1")
	if err == nil || !strings.Contains(err.Error(), "weird_thing") {
		t.Fatalf("PollDeviceAuth() error = %v, want unknown-code error", err)
	}
	for _, sentinel := range []error{ErrAuthorizationPending, ErrSlowDown, ErrAccessDenied, ErrExpiredToken, ErrInvalidGrant} {
		if errors.Is(err, sentinel) {
			t.Fatalf("unknown code matched sentinel %v", sentinel)
		}
	}
}

func TestPollDeviceAuth_200WithNoAccessToken(t *testing.T) {
	t.Parallel()

	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	})

	if _, err := c.PollDeviceAuth(context.Background(), "dev-1"); err == nil {
		t.Fatal("PollDeviceAuth() should fail when access_token missing")
	}
}

func TestStartDeviceAuth_HTMLBodySurfacesFriendlyError(t *testing.T) {
	t.Parallel()

	// Captive portal / firewall (Cloudflare WARP, corp proxy) returns
	// 200 OK with an HTML error page. Surface a network-actionable
	// message instead of the opaque JSON-decode complaint.
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<!DOCTYPE html><html><body>Access blocked</body></html>`)
	})

	_, err := c.StartDeviceAuth(context.Background())
	if err == nil {
		t.Fatal("StartDeviceAuth() with HTML body should error")
	}
	for _, want := range []string{"non-JSON", "VPN", "proxy", "firewall"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q hint: %s", want, err)
		}
	}
	if strings.Contains(err.Error(), "invalid character") {
		t.Errorf("raw JSON-decoder error leaked through: %s", err)
	}
}

func TestPollDeviceAuth_HTMLBodySurfacesFriendlyError(t *testing.T) {
	t.Parallel()

	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html>Access blocked by WARP</html>`)
	})

	_, err := c.PollDeviceAuth(context.Background(), "dev-1")
	if err == nil {
		t.Fatal("PollDeviceAuth() with HTML body should error")
	}
	if strings.Contains(err.Error(), "invalid character") {
		t.Errorf("raw JSON-decoder error leaked through: %s", err)
	}
}

func TestResolveURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		base    string
		path    string
		want    string
		wantErr bool
	}{
		{"https + absolute path", "https://entire.io", "/oauth/device/code", "https://entire.io/oauth/device/code", false},
		{"trailing slash + absolute path", "https://entire.io/", "/oauth/token", "https://entire.io/oauth/token", false},
		{"http allowed", "http://localhost:8180", "/api/auth/token", "http://localhost:8180/api/auth/token", false},
		{"unsupported scheme", "ftp://x", "/y", "", true},
		{"malformed base", "://", "/y", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveURL(tt.base, tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolveURL() err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("resolveURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
