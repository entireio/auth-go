package deviceflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// writeBody writes body to w from a test handler. Wraps io.WriteString
// with a t.Fatal on error so test fixtures stay readable without
// per-callsite nolint comments.
func writeBody(t *testing.T, w io.Writer, body string) {
	t.Helper()
	if _, err := io.WriteString(w, body); err != nil {
		t.Fatalf("write body: %v", err)
	}
}

const (
	testClientID       = "cli"
	testDeviceCodePath = "/oauth/device/code"
	testTokenPath      = "/oauth/token"
)

// freezeClock pins c.now() for the duration of a test. Per-Client
// rather than package-global so parallel tests with independent
// Clients don't race each other (the v0.2.0 review surfaced the old
// package-global nowFunc as a latent t.Parallel hazard).
func freezeClock(t *testing.T, c *Client, at time.Time) {
	t.Helper()
	SetNowForTest(t, c, func() time.Time { return at })
}

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	c := &Client{
		Transport:         srv.Client().Transport,
		BaseURL:           srv.URL,
		ClientID:          testClientID,
		Scope:             "cli",
		DeviceCodePath:    testDeviceCodePath,
		TokenPath:         testTokenPath,
		AllowInsecureHTTP: true, // httptest.NewServer is http://
	}
	return c
}

func mustReadForm(t *testing.T, r *http.Request) {
	t.Helper()
	if err := r.ParseForm(); err != nil {
		t.Fatalf("parse form: %v", err)
	}
}

func TestStartDeviceAuth_Success(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
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
		writeBody(t, w, `{
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

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mustReadForm(t, r)
		if r.PostForm.Has("scope") {
			t.Errorf("scope should not be sent when Client.Scope is empty")
		}
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, `{"device_code":"d","user_code":"u","verification_uri":"https://example.com/cli","expires_in":1,"interval":1}`)
	})
	c.Scope = ""

	if _, err := c.StartDeviceAuth(context.Background()); err != nil {
		t.Fatalf("StartDeviceAuth() error = %v", err)
	}
}

func TestStartDeviceAuth_RejectsUnknownFields(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, `{
			"device_code":"d","user_code":"u","verification_uri":"https://example.com/cli","expires_in":1,"interval":1,
			"surprise":"field"
		}`)
	})

	if _, err := c.StartDeviceAuth(context.Background()); err == nil {
		t.Fatal("StartDeviceAuth() with unknown field should fail (strict decode)")
	}
}

func TestStartDeviceAuth_NonOK(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeBody(t, w, `{"error":"invalid_client"}`)
	})

	if _, err := c.StartDeviceAuth(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("StartDeviceAuth() error = %v, want invalid_client", err)
	}
}

func TestPollDeviceAuth_Success(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mustReadForm(t, r)
		if got := r.PostForm.Get("grant_type"); got != deviceCodeGrantType {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.PostForm.Get("device_code"); got != "dev-1" {
			t.Errorf("device_code = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, `{
			"access_token":"acc",
			"refresh_token":"ref",
			"token_type":"Bearer",
			"expires_in":3600,
			"scope":"cli"
		}`)
	})
	freezeClock(t, c, time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC))

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

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, `{"access_token":"acc","extra":"ignored"}`)
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
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
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

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeBody(t, w, `{"error":"invalid_grant","error_description":"device_code unknown"}`)
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

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeBody(t, w, `{"error":"invalid_grant"}`)
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

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeBody(t, w, `{"error":"weird_thing"}`)
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

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, `{}`)
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
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		writeBody(t, w, `<!DOCTYPE html><html><body>Access blocked</body></html>`)
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

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		writeBody(t, w, `<html>Access blocked by WARP</html>`)
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
		name              string
		base              string
		path              string
		allowInsecureHTTP bool
		want              string
		wantErr           bool
	}{
		{"https + absolute path", "https://entire.io", "/oauth/device/code", false, "https://entire.io/oauth/device/code", false},
		{"trailing slash + absolute path", "https://entire.io/", "/oauth/token", false, "https://entire.io/oauth/token", false},
		{"http rejected by default", "http://localhost:8180", "/api/auth/token", false, "", true},
		{"http allowed with opt-in", "http://localhost:8180", "/api/auth/token", true, "http://localhost:8180/api/auth/token", false},
		{"unsupported scheme", "ftp://x", "/y", false, "", true},
		{"malformed base", "://", "/y", false, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveURL(tt.base, tt.path, tt.allowInsecureHTTP)
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolveURL() err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("resolveURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestPollDeviceAuth_RequestTimeoutFires pins the slow-loris defence:
// a handler that never finishes writing a response must surface as a
// context deadline error rather than blocking the polling loop forever.
func TestPollDeviceAuth_RequestTimeoutFires(t *testing.T) {
	t.Parallel()
	// Cleanup is LIFO and httptest.Server.Close waits for active
	// handler goroutines, so close(hung) is registered AFTER
	// newTestClient to fire first and let the handler exit before
	// srv.Close runs.
	hung := make(chan struct{})
	c := newTestClient(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-hung:
		case <-r.Context().Done():
		}
	})
	t.Cleanup(func() { close(hung) })
	c.RequestTimeout = 50 * time.Millisecond

	_, err := c.PollDeviceAuth(context.Background(), "dev-1")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("err = %v, want context deadline exceeded", err)
	}
}

// TestStartDeviceAuth_RequestTimeoutFires mirrors the poll-side test
// for the device-code endpoint.
func TestStartDeviceAuth_RequestTimeoutFires(t *testing.T) {
	t.Parallel()
	// Cleanup is LIFO and httptest.Server.Close waits for active
	// handler goroutines, so close(hung) is registered AFTER
	// newTestClient to fire first and let the handler exit before
	// srv.Close runs.
	hung := make(chan struct{})
	c := newTestClient(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-hung:
		case <-r.Context().Done():
		}
	})
	t.Cleanup(func() { close(hung) })
	c.RequestTimeout = 50 * time.Millisecond

	_, err := c.StartDeviceAuth(context.Background())
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("err = %v, want context deadline exceeded", err)
	}
}

// TestRequestTimeout_DefaultAndOverride exercises the timeout policy
// without doing IO — pure resolution of the (zero / negative /
// positive) input contract.
func TestRequestTimeout_DefaultAndOverride(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero -> default", 0, DefaultRequestTimeout},
		{"negative -> disabled", -1, 0},
		{"positive -> verbatim", 5 * time.Second, 5 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &Client{RequestTimeout: tc.in}
			if got := c.requestTimeout(); got != tc.want {
				t.Fatalf("requestTimeout() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestStartDeviceAuth_RejectsUnsafeVerificationURI pins the
// anti-phishing checks on the verification_uri returned by the AS.
// A compromised or misconfigured server must not be able to redirect
// users to an attacker-controlled login page; the URL we'd otherwise
// echo and open carries the user code.
func TestStartDeviceAuth_RejectsUnsafeVerificationURI(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		uri  string
	}{
		{"empty", ""},
		{"missing scheme", "example.com/cli"},
		{"non-https scheme", "ftp://example.com/cli"},
		{"plain http on non-loopback", "http://example.com/cli"},
		{"embedded userinfo", "https://entire.io@evil.example.com/cli"},
		{"newline injection", "https://example.com/cli\nGET /steal"},
		{"control character", "https://example.com/\x07cli"},
		{"javascript scheme", "javascript:alert(1)"},
		{"data scheme", "data:text/html,<script>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				body, _ := jsonMarshal(map[string]any{ //nolint:errcheck // map literal can't fail to marshal
					"device_code":      "d",
					"user_code":        "u",
					"verification_uri": tc.uri,
					"expires_in":       60,
					"interval":         5,
				})
				_, _ = w.Write(body) //nolint:errcheck // test handler
			})

			_, err := c.StartDeviceAuth(context.Background())
			if !errors.Is(err, ErrUnsafeVerificationURI) {
				t.Fatalf("StartDeviceAuth(verification_uri=%q) error = %v, want ErrUnsafeVerificationURI", tc.uri, err)
			}
		})
	}
}

// TestStartDeviceAuth_AcceptsSafeVerificationURI sanity check: the
// safe-shape cases must continue to pass. Pins the contract that the
// rejection logic is narrowly scoped.
func TestStartDeviceAuth_AcceptsSafeVerificationURI(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		uri  string
	}{
		{"https with path", "https://entire.io/cli/auth"},
		{"https with query", "https://entire.io/cli/auth?ref=device"},
		{"https with port", "https://auth.example.com:8443/cli"},
		{"loopback http", "http://localhost:8787/cli"},
		{"loopback ip http", "http://127.0.0.1:8787/cli"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				body, _ := jsonMarshal(map[string]any{ //nolint:errcheck // map literal can't fail to marshal
					"device_code":      "d",
					"user_code":        "u",
					"verification_uri": tc.uri,
					"expires_in":       60,
					"interval":         5,
				})
				_, _ = w.Write(body) //nolint:errcheck // test handler
			})

			if _, err := c.StartDeviceAuth(context.Background()); err != nil {
				t.Fatalf("StartDeviceAuth(verification_uri=%q) error = %v, want nil", tc.uri, err)
			}
		})
	}
}

// jsonMarshal is a tiny helper that lets us produce the wire payload
// inline without sprintf-fighting with embedded quotes.
func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

// TestPollUntil_HonoursSlowDownBump pins the RFC 8628 §3.5 polite-
// client behaviour: each slow_down adds slowDownBump to the polling
// interval. Without this, naïve callers would hammer the AS and trip
// rate limits — §5.5 of the RFC calls this out as a DoS vector.
//
// Asserts the *relative* growth of poll gaps rather than an absolute
// floor. With base interval=1s and bump=200ms the timeline is:
//
//	t=0     call 1 (slow_down) → interval := 1s + bump
//	t≈1.2s  call 2 (slow_down) → interval := 1s + 2·bump
//	t≈2.6s  call 3 (auth_pending)
//	t≈4s    call 4 (success)
//
// gap12 (≈1.4s) must be measurably longer than gap01 (≈1.2s) by close
// to slowDownBump. Tolerating slowDownBump/2 of scheduler jitter keeps
// the test deterministic on loaded CI while still proving the bump
// actually compounds (the previous absolute-floor assertion was
// satisfied by the 1s pollInterval floor alone, with t.Skip as an
// escape hatch — that meant the test couldn't fail by under-bumping).
func TestPollUntil_HonoursSlowDownBump(t *testing.T) {
	// Not parallel: mutates the package-level slowDownBump var.
	prev := slowDownBump
	slowDownBump = 200 * time.Millisecond
	t.Cleanup(func() { slowDownBump = prev })

	var calls int
	var pollTimes []time.Time

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != testTokenPath {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		calls++
		pollTimes = append(pollTimes, time.Now())
		w.Header().Set("Content-Type", "application/json")
		switch calls {
		case 1, 2:
			w.WriteHeader(http.StatusBadRequest)
			writeBody(t, w, `{"error":"slow_down"}`)
		case 3:
			w.WriteHeader(http.StatusBadRequest)
			writeBody(t, w, `{"error":"authorization_pending"}`)
		default:
			writeBody(t, w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		}
	})

	dc := &DeviceCode{
		DeviceCode: "device-x",
		Interval:   1, // pollInterval honours this verbatim
		ExpiresIn:  60,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ts, err := c.PollUntil(ctx, dc)
	if err != nil {
		t.Fatalf("PollUntil: %v", err)
	}
	if ts.AccessToken != "tok" {
		t.Fatalf("AccessToken = %q, want tok", ts.AccessToken)
	}
	if len(pollTimes) != 4 {
		t.Fatalf("got %d poll calls, want exactly 4 (slow_down × 2, auth_pending, success)", len(pollTimes))
	}

	gap01 := pollTimes[1].Sub(pollTimes[0]) // after 1× slow_down
	gap12 := pollTimes[2].Sub(pollTimes[1]) // after 2× slow_down
	delta := gap12 - gap01
	if delta < slowDownBump/2 {
		t.Errorf("expected gap12 to grow over gap01 by ~%v (the slow_down bump); got gap01=%v gap12=%v delta=%v",
			slowDownBump, gap01, gap12, delta)
	}
}

// TestPollUntil_RespectsExpiresIn pins the ceiling: once dc.ExpiresIn
// has elapsed since PollUntil started, the loop must return rather
// than polling forever.
func TestPollUntil_RespectsExpiresIn(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		writeBody(t, w, `{"error":"authorization_pending"}`)
	})

	dc := &DeviceCode{
		DeviceCode: "device-x",
		Interval:   1,
		ExpiresIn:  2, // hard ceiling — bail after 2s of polling
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_, err := c.PollUntil(ctx, dc)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected expiry error, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err = %v, want expiry error", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("PollUntil took %v, expected ≤ 5s before ExpiresIn ceiling fires", elapsed)
	}
}

// TestPollUntil_TerminalSentinelsPropagate pins that terminal error
// codes break the loop immediately rather than getting retried.
func TestPollUntil_TerminalSentinelsPropagate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code     string
		sentinel error
	}{
		{"access_denied", ErrAccessDenied},
		{"expired_token", ErrExpiredToken},
		{"invalid_grant", ErrInvalidGrant},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			t.Parallel()
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				writeBody(t, w, `{"error":"`+tc.code+`"}`)
			})
			dc := &DeviceCode{DeviceCode: "device-x", Interval: 1, ExpiresIn: 60}
			_, err := c.PollUntil(context.Background(), dc)
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("err = %v, want %v", err, tc.sentinel)
			}
		})
	}
}

// TestPollUntil_ClampsZeroExpiresIn pins that an AS omitting (or
// negating) expires_in does NOT leave the poll loop running forever
// — bugbot caught this on the v0.2.0 PR. Without the clamp the loop
// would only break via ctx cancellation, contradicting both
// PollUntil's doc and the RFC 8628 §5.5 DoS-defence rationale that
// motivated the helper.
func TestPollUntil_ClampsZeroExpiresIn(t *testing.T) {
	// Not parallel: mutates the package-level defaultPollExpiresIn.
	prev := defaultPollExpiresIn
	defaultPollExpiresIn = 1 // 1 second cap for test speed
	t.Cleanup(func() { defaultPollExpiresIn = prev })

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		writeBody(t, w, `{"error":"authorization_pending"}`)
	})

	dc := &DeviceCode{
		DeviceCode: "device-x",
		Interval:   1,
		ExpiresIn:  0, // hostile/buggy AS omitted expires_in
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_, err := c.PollUntil(ctx, dc)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected default-expiry error, got nil")
	}
	if !strings.Contains(err.Error(), "default expiry") {
		t.Fatalf("err = %v, want default-expiry error", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("PollUntil took %v, expected ≤ 5s before defaulted ExpiresIn ceiling fires", elapsed)
	}
}

// TestPollUntil_ClampsZeroInterval defends against a hostile or buggy
// AS returning interval=0 — without clamping, PollUntil would hot-loop
// against the token endpoint.
func TestPollUntil_ClampsZeroInterval(t *testing.T) {
	t.Parallel()
	got := pollInterval(&DeviceCode{Interval: 0})
	if got < time.Second {
		t.Fatalf("pollInterval(Interval=0) = %v, want ≥ 1s", got)
	}
	got = pollInterval(&DeviceCode{Interval: -1})
	if got < time.Second {
		t.Fatalf("pollInterval(Interval=-1) = %v, want ≥ 1s", got)
	}
}

// TestPollInterval_ClampsLargeInterval pins the upper ceiling on
// dc.Interval. A hostile or buggy AS sending an extreme value would
// otherwise effectively park the poll loop until ExpiresIn fires, or
// on 64-bit platforms eventually overflow time.Duration's nanosecond
// range when multiplied by time.Second. The clamp keeps the poll
// cadence sane regardless of wire input.
func TestPollInterval_ClampsLargeInterval(t *testing.T) {
	t.Parallel()
	cases := []int{3601, 86_400, 1 << 30, math.MaxInt32}
	for _, in := range cases {
		t.Run(strconv.Itoa(in), func(t *testing.T) {
			t.Parallel()
			got := pollInterval(&DeviceCode{Interval: in})
			if got > time.Hour {
				t.Fatalf("pollInterval(Interval=%d) = %v, want ≤ 1h ceiling", in, got)
			}
			if got <= 0 {
				t.Fatalf("pollInterval(Interval=%d) = %v, want positive (overflow guard)", in, got)
			}
		})
	}
}

// TestStartDeviceAuth_RoutesSentinel pins the symmetric error
// behaviour: StartDeviceAuth errors should be matchable with
// errors.Is (same as PollDeviceAuth) so callers don't have to
// switch on the underlying call site.
func TestStartDeviceAuth_RoutesSentinel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code     string
		sentinel error
	}{
		{"access_denied", ErrAccessDenied},
		{"expired_token", ErrExpiredToken},
		{"invalid_grant", ErrInvalidGrant},
		{"slow_down", ErrSlowDown},
		{"authorization_pending", ErrAuthorizationPending},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			t.Parallel()
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				writeBody(t, w, `{"error":"`+tc.code+`","error_description":"server says no"}`)
			})
			_, err := c.StartDeviceAuth(context.Background())
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("StartDeviceAuth err = %v, want %v", err, tc.sentinel)
			}
			if !strings.Contains(err.Error(), "server says no") {
				t.Errorf("StartDeviceAuth err = %v, expected sanitised description surfaced", err)
			}
		})
	}
}

// TestPollDeviceAuth_SanitisesErrorDescription pins that PollDeviceAuth
// also strips control chars from server-supplied error_description so
// a hostile AS can't paint the user's terminal.
func TestPollDeviceAuth_SanitisesErrorDescription(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeBody(t, w, `{"error":"invalid_grant","error_description":"line1\r\n\u001b[31mline2"}`)
	})
	_, err := c.PollDeviceAuth(context.Background(), "dev-x")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("err = %v, want ErrInvalidGrant", err)
	}
	if strings.Contains(err.Error(), "\x1b") || strings.Contains(err.Error(), "\r") || strings.Contains(err.Error(), "\n") {
		t.Fatalf("err = %q, control characters not stripped", err.Error())
	}
}

// TestResolveURL_RejectsAbsolutePath pins the redirect defence: an
// absolute DeviceCodePath/TokenPath would replace BaseURL via
// url.ResolveReference, sending the user's device-code or access
// token to whatever host the caller's configuration source supplied.
// The library refuses.
func TestResolveURL_RejectsAbsolutePath(t *testing.T) {
	t.Parallel()
	cases := []string{
		"https://attacker.example.com/oauth/token",
		"http://attacker.example.com/oauth/token",
		"//attacker.example.com/oauth/token",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			_, err := resolveURL("https://auth.example.com", p, false)
			if err == nil {
				t.Fatalf("resolveURL(%q) returned nil error, want ErrAbsolutePath", p)
			}
			if !errors.Is(err, ErrAbsolutePath) {
				t.Fatalf("err = %v, want ErrAbsolutePath", err)
			}
		})
	}
}

// TestNew_RequiresFields pins the fail-fast contract for the
// validating constructor. Each required field, when empty, must
// surface at construction time rather than at the first request —
// the whole point of the helper. The nil-Client case is included
// because returning a typed-nil from a constructor would be the most
// embarrassing of failure modes.
func TestNew_RequiresFields(t *testing.T) {
	t.Parallel()

	base := func() *Client {
		return &Client{
			BaseURL:        "https://auth.example.com",
			ClientID:       "cli",
			DeviceCodePath: "/oauth/device/code",
			TokenPath:      "/oauth/token",
		}
	}

	t.Run("nil Client", func(t *testing.T) {
		t.Parallel()
		if _, err := New(nil); err == nil {
			t.Fatal("New(nil) = nil, want error")
		}
	})

	missing := []struct {
		name   string
		mutate func(*Client)
		want   string
	}{
		{"empty BaseURL", func(c *Client) { c.BaseURL = "" }, "BaseURL"},
		{"empty ClientID", func(c *Client) { c.ClientID = "" }, "ClientID"},
		{"empty DeviceCodePath", func(c *Client) { c.DeviceCodePath = "" }, "DeviceCodePath"},
		{"empty TokenPath", func(c *Client) { c.TokenPath = "" }, "TokenPath"},
	}
	for _, tc := range missing {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := base()
			tc.mutate(c)
			_, err := New(c)
			if err == nil {
				t.Fatalf("New(%s missing) = nil, want error", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, should mention %q", err, tc.want)
			}
		})
	}

	t.Run("complete returns same pointer", func(t *testing.T) {
		t.Parallel()
		c := base()
		got, err := New(c)
		if err != nil {
			t.Fatalf("New(complete) = %v, want nil", err)
		}
		if got != c {
			t.Fatal("New returned a different pointer; should return its input on success")
		}
	})
}

// TestDeviceCode_StringRedactsSecrets pins the DeviceCode Stringer's
// threat model: DeviceCode (poll-redemption secret) and
// VerificationURIComplete (auto-fills the consent form → effectively
// one-click consent during the auth window) are redacted. UserCode
// is preserved because the user has to read it aloud, and plain
// VerificationURI is preserved because the user has to navigate to
// it. A regression that flips any of these would either spill a
// secret or break the UX.
func TestDeviceCode_StringRedactsSecrets(t *testing.T) {
	t.Parallel()

	dc := DeviceCode{
		DeviceCode:              "device-poll-secret-1234567890",
		UserCode:                "WDJB-MJHT",
		VerificationURI:         "https://auth.example.com/device",
		VerificationURIComplete: "https://auth.example.com/device?user_code=WDJB-MJHT",
		ExpiresIn:               600,
		Interval:                5,
	}

	got := dc.String()
	if strings.Contains(got, "device-poll-secret-1234567890") {
		t.Fatalf("String() leaked DeviceCode: %q", got)
	}
	if strings.Contains(got, "user_code=WDJB-MJHT") {
		t.Fatalf("String() leaked VerificationURIComplete: %q", got)
	}
	if !strings.Contains(got, `UserCode:"WDJB-MJHT"`) {
		t.Fatalf("String() should show UserCode verbatim (user reads it aloud): %q", got)
	}
	if !strings.Contains(got, `VerificationURI:"https://auth.example.com/device"`) {
		t.Fatalf("String() should show plain VerificationURI verbatim: %q", got)
	}
	// And %#v must redact via GoString.
	if v := fmt.Sprintf("%#v", dc); strings.Contains(v, "device-poll-secret-1234567890") {
		t.Fatalf("%%#v leaked DeviceCode: %q", v)
	}
}

// TestValidateVerificationURI_RejectsOversized pins the 2048-byte
// cap against terminal-overflow phishing — a benign prefix followed
// by enough padding to scroll a hostile suffix off-screen. The cap
// is generous; real production verification URLs are well under
// 200 chars.
func TestValidateVerificationURI_RejectsOversized(t *testing.T) {
	t.Parallel()

	long := "https://auth.example.com/device?x=" + strings.Repeat("a", maxVerificationURILen)
	if len(long) <= maxVerificationURILen {
		t.Fatalf("test fixture too short: %d <= %d", len(long), maxVerificationURILen)
	}
	err := validateVerificationURI(long, false)
	if !errors.Is(err, ErrUnsafeVerificationURI) {
		t.Fatalf("validateVerificationURI(oversized) = %v, want ErrUnsafeVerificationURI", err)
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Fatalf("err = %v, should mention length", err)
	}

	// Boundary: exactly maxVerificationURILen is accepted (the check
	// is `len > max`, not `len >= max`).
	atMax := "https://auth.example.com/?" + strings.Repeat("a", maxVerificationURILen-len("https://auth.example.com/?"))
	if len(atMax) != maxVerificationURILen {
		t.Fatalf("test fixture not exactly maxVerificationURILen: got %d, want %d", len(atMax), maxVerificationURILen)
	}
	if err := validateVerificationURI(atMax, false); err != nil {
		t.Fatalf("validateVerificationURI(exactly maxVerificationURILen) = %v, want nil", err)
	}
}

// TestValidateVerificationURI_RejectsNonASCIIHost pins the
// raw-Unicode hostname rejection (the cheap defence against
// confusable-script attacks). Documented limitation: this catches
// raw-Unicode only; Punycode-encoded confusables (xn--pple-43d.com)
// pass because the wire layer is ASCII-clean — full homograph
// defence belongs in the browser, not in this library.
func TestValidateVerificationURI_RejectsNonASCIIHost(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		uri  string
	}{
		{"cyrillic a", "https://аpple.com/device"}, // U+0430
		{"cyrillic full", "https://привет.example/device"},
		{"emoji host", "https://\U0001F600.example/device"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateVerificationURI(tc.uri, false)
			if !errors.Is(err, ErrUnsafeVerificationURI) {
				t.Fatalf("validateVerificationURI(%q) = %v, want ErrUnsafeVerificationURI", tc.uri, err)
			}
			if !strings.Contains(err.Error(), "non-ASCII host") {
				t.Fatalf("err = %v, should mention non-ASCII host", err)
			}
		})
	}

	// Sanity: Punycode-encoded form is accepted (this is the
	// documented escape hatch and the wire-layer expectation).
	if err := validateVerificationURI("https://xn--pple-43d.com/device", false); err != nil {
		t.Fatalf("validateVerificationURI(Punycode) = %v, want nil (documented limitation)", err)
	}
}
