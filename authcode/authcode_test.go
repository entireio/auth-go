package authcode

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testClientID      = "cli"
	testAuthorizePath = "/authorize"
	testTokenPath     = "/oauth/token"
	testScope         = "cli offline_access"
)

func writeBody(t *testing.T, w io.Writer, body string) {
	t.Helper()
	if _, err := io.WriteString(w, body); err != nil {
		t.Fatalf("write body: %v", err)
	}
}

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	return &Client{
		Transport:         srv.Client().Transport,
		BaseURL:           srv.URL,
		ClientID:          testClientID,
		Scope:             testScope,
		AuthorizePath:     testAuthorizePath,
		TokenPath:         testTokenPath,
		AllowInsecureHTTP: true, // httptest.NewServer is http://
	}
}

// hitCallback simulates the browser being redirected back to the loopback
// listener. resultCh is buffered, so calling this before Wait is safe.
func hitCallback(t *testing.T, redirectURI string, params url.Values) *http.Response {
	t.Helper()
	resp, err := http.Get(redirectURI + "?" + params.Encode()) //nolint:noctx,bodyclose // test helper; caller closes
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	return resp
}

// authParams parses the query off a Flow's AuthorizationURL.
func authParams(t *testing.T, f *Flow) url.Values {
	t.Helper()
	u, err := url.Parse(f.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse AuthorizationURL: %v", err)
	}
	return u.Query()
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestStart_BuildsAuthorizationURL(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
	f, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	q := authParams(t, f)
	if got := q.Get("response_type"); got != "code" {
		t.Errorf("response_type = %q, want code", got)
	}
	if got := q.Get("client_id"); got != testClientID {
		t.Errorf("client_id = %q, want %q", got, testClientID)
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	if q.Get("code_challenge") == "" {
		t.Error("code_challenge is empty")
	}
	if q.Get("state") == "" {
		t.Error("state is empty")
	}
	if got := q.Get("scope"); got != testScope {
		t.Errorf("scope = %q, want %q", got, testScope)
	}
	if got := q.Get("redirect_uri"); got != f.RedirectURI {
		t.Errorf("redirect_uri = %q, want %q", got, f.RedirectURI)
	}
	if !strings.HasPrefix(f.RedirectURI, "http://127.0.0.1:") || !strings.HasSuffix(f.RedirectURI, callbackPath) {
		t.Errorf("RedirectURI = %q, want http://127.0.0.1:<port>%s", f.RedirectURI, callbackPath)
	}
}

func TestStart_OmitsScopeWhenEmpty(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
	c.Scope = ""
	f, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	if authParams(t, f).Has("scope") {
		t.Error("scope should not be set when Client.Scope is empty")
	}
}

func TestFlow_HappyPath(t *testing.T) {
	t.Parallel()

	var (
		mu          sync.Mutex
		gotVerifier string
		gotForm     url.Values
	)
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != testTokenPath {
			t.Errorf("token request path = %q", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		mu.Lock()
		gotVerifier = r.PostForm.Get("code_verifier")
		gotForm = r.PostForm
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, `{"access_token":"at-1","refresh_token":"rt-1","token_type":"Bearer","expires_in":3600,"scope":"cli offline_access"}`)
	})

	f, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	q := authParams(t, f)
	resp := hitCallback(t, f.RedirectURI, url.Values{
		"code":  {"auth-code-123"},
		"state": {q.Get("state")},
	})
	_ = resp.Body.Close()

	code, err := f.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if code != "auth-code-123" {
		t.Fatalf("code = %q, want auth-code-123", code)
	}

	ts, err := f.Exchange(context.Background(), code)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if ts.AccessToken != "at-1" || ts.RefreshToken != "rt-1" {
		t.Fatalf("TokenSet = %+v", ts)
	}

	mu.Lock()
	defer mu.Unlock()
	if pkceChallenge(gotVerifier) != q.Get("code_challenge") {
		t.Error("token exchange code_verifier does not hash to the authorize code_challenge")
	}
	if got := gotForm.Get("grant_type"); got != authCodeGrantType {
		t.Errorf("grant_type = %q, want %q", got, authCodeGrantType)
	}
	if got := gotForm.Get("redirect_uri"); got != f.RedirectURI {
		t.Errorf("redirect_uri = %q, want %q", got, f.RedirectURI)
	}
	if got := gotForm.Get("code"); got != "auth-code-123" {
		t.Errorf("code = %q, want auth-code-123", got)
	}
}

func TestExchange_SetsAbsoluteExpiry(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, `{"access_token":"at","token_type":"Bearer","expires_in":3600}`)
	})
	frozen := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	SetNowForTest(t, c, func() time.Time { return frozen })

	f, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	ts, err := f.Exchange(context.Background(), "code")
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if want := frozen.Add(time.Hour); !ts.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %s, want %s", ts.ExpiresAt, want)
	}
}

func TestWait_StateMismatchIgnoredThenSuccess(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
	f, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// A forged/stray callback with the wrong state is rejected (400) and
	// must NOT abort the still-pending login.
	bad := hitCallback(t, f.RedirectURI, url.Values{"code": {"x"}, "state": {"wrong"}})
	if bad.StatusCode != http.StatusBadRequest {
		t.Errorf("bad-state status = %d, want 400", bad.StatusCode)
	}
	_ = bad.Body.Close()

	q := authParams(t, f)
	good := hitCallback(t, f.RedirectURI, url.Values{"code": {"real-code"}, "state": {q.Get("state")}})
	_ = good.Body.Close()

	code, err := f.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if code != "real-code" {
		t.Fatalf("code = %q, want real-code", code)
	}
}

func TestWait_AccessDenied(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
	f, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	q := authParams(t, f)
	resp := hitCallback(t, f.RedirectURI, url.Values{
		"error":             {"access_denied"},
		"error_description": {"user declined"},
		"state":             {q.Get("state")},
	})
	_ = resp.Body.Close()

	if _, err := f.Wait(context.Background()); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("Wait() error = %v, want ErrAccessDenied", err)
	}
}

func TestWait_MissingCode(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
	f, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	q := authParams(t, f)
	resp := hitCallback(t, f.RedirectURI, url.Values{"state": {q.Get("state")}})
	_ = resp.Body.Close()

	if _, err := f.Wait(context.Background()); !errors.Is(err, ErrMissingCode) {
		t.Fatalf("Wait() error = %v, want ErrMissingCode", err)
	}
}

func TestWait_Timeout(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
	c.CallbackTimeout = 50 * time.Millisecond
	f, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	_, err = f.Wait(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait() error = %v, want context.DeadlineExceeded", err)
	}
}

func TestWait_ContextCancelled(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
	c.CallbackTimeout = -1 // rely solely on the caller's context
	f, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait() error = %v, want context.Canceled", err)
	}
}

func TestExchange_InvalidGrant(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		writeBody(t, w, `{"error":"invalid_grant","error_description":"code already redeemed"}`)
	})
	f, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	if _, err := f.Exchange(context.Background(), "stale"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("Exchange() error = %v, want ErrInvalidGrant", err)
	}
}

func TestExchange_NoAccessToken(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, `{"token_type":"Bearer"}`)
	})
	f, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	if _, err := f.Exchange(context.Background(), "code"); err == nil {
		t.Fatal("Exchange() error = nil, want missing-access-token error")
	}
}

func TestNew_Validation(t *testing.T) {
	t.Parallel()

	cases := map[string]*Client{
		"nil":           nil,
		"no base URL":   {ClientID: "c", AuthorizePath: "/a", TokenPath: "/t"},
		"no client ID":  {BaseURL: "https://e", AuthorizePath: "/a", TokenPath: "/t"},
		"no authorize":  {BaseURL: "https://e", ClientID: "c", TokenPath: "/t"},
		"no token path": {BaseURL: "https://e", ClientID: "c", AuthorizePath: "/a"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(c); err == nil {
				t.Errorf("New(%s) error = nil, want non-nil", name)
			}
		})
	}

	ok := &Client{BaseURL: "https://e", ClientID: "c", AuthorizePath: "/a", TokenPath: "/t"}
	if _, err := New(ok); err != nil {
		t.Errorf("New(valid) error = %v", err)
	}
}

func TestStart_RejectsInsecureBaseURL(t *testing.T) {
	t.Parallel()

	c := &Client{
		BaseURL:       "http://auth.example.com", // non-loopback http
		ClientID:      testClientID,
		AuthorizePath: testAuthorizePath,
		TokenPath:     testTokenPath,
	}
	if _, err := c.Start(context.Background()); !errors.Is(err, ErrInsecureBaseURL) {
		t.Fatalf("Start() error = %v, want ErrInsecureBaseURL", err)
	}
}
