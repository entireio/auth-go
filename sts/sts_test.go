package sts

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

const testTokenPath = "/sts/token"

func freezeClock(t *testing.T, at time.Time) {
	t.Helper()
	prev := nowFunc
	nowFunc = func() time.Time { return at }
	t.Cleanup(func() { nowFunc = prev })
}

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	return &Client{
		HTTP:    srv.Client(),
		BaseURL: srv.URL,
		Path:    testTokenPath,
	}
}

func mustReadForm(t *testing.T, r *http.Request) {
	t.Helper()
	if err := r.ParseForm(); err != nil {
		t.Fatalf("parse form: %v", err)
	}
}

func TestExchange_Success(t *testing.T) {
	// Not parallel: freezeClock mutates the package-level nowFunc.
	// Any other parallel test calling Exchange would race against it.
	freezeClock(t, time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC))

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mustReadForm(t, r)
		if got := r.PostForm.Get("grant_type"); got != GrantTypeTokenExchange {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.PostForm.Get("subject_token_type"); got != SubjectTokenTypeJWT {
			t.Errorf("subject_token_type = %q", got)
		}
		if got := r.PostForm.Get("requested_token_type"); got != "urn:example:token-type:thing" {
			t.Errorf("requested_token_type = %q", got)
		}
		if got := r.PostForm.Get("subject_token"); got != "sub-jwt" {
			t.Errorf("subject_token = %q", got)
		}
		if got := r.PostForm.Get("audience"); got != "audience-x" {
			t.Errorf("audience = %q", got)
		}
		if got := r.PostForm.Get("resource"); got != "owner/repo" {
			t.Errorf("resource = %q", got)
		}
		if got := r.PostForm.Get("scope"); got != "thing:do" {
			t.Errorf("scope = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, `{
			"access_token":"acc",
			"issued_token_type":"urn:example:token-type:thing",
			"token_type":"Bearer",
			"expires_in":3600,
			"refresh_token":"ref",
			"scope":"thing:do"
		}`)
	})

	got, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub-jwt",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:token-type:thing",
		Audience:           "audience-x",
		Resource:           "owner/repo",
		Scope:              "thing:do",
	})
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}

	if got.AccessToken != "acc" || got.RefreshToken != "ref" || got.TokenType != "Bearer" || got.Scope != "thing:do" {
		t.Fatalf("TokenSet = %+v", got)
	}
	want := time.Date(2026, 5, 6, 13, 0, 0, 0, time.UTC)
	if !got.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, want)
	}
}

func TestExchange_OmitsOptionalFieldsWhenEmpty(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mustReadForm(t, r)
		for _, k := range []string{"audience", "resource", "scope"} {
			if r.PostForm.Has(k) {
				t.Errorf("optional field %q should not be sent when empty", k)
			}
		}
		writeBody(t, w, `{"access_token":"acc"}`)
	})

	if _, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
	}); err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
}

func TestExchange_ExtraFieldsForwarded(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mustReadForm(t, r)
		if got := r.PostForm.Get("custom_field"); got != "custom-value" {
			t.Errorf("custom_field = %q", got)
		}
		writeBody(t, w, `{"access_token":"acc"}`)
	})

	if _, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
		Extra:              url.Values{"custom_field": {"custom-value"}},
	}); err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
}

func TestExchange_StandardFieldsOverrideExtra(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mustReadForm(t, r)
		// Caller tried to set grant_type via Extra; standard wins.
		if got := r.PostForm.Get("grant_type"); got != GrantTypeTokenExchange {
			t.Errorf("Extra should not override standard grant_type; got %q", got)
		}
		writeBody(t, w, `{"access_token":"acc"}`)
	})

	if _, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
		Extra:              url.Values{"grant_type": {"trojan"}},
	}); err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
}

func TestExchange_RejectsMissingRequiredFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  ExchangeRequest
	}{
		{"no subject token", ExchangeRequest{SubjectTokenType: SubjectTokenTypeJWT, RequestedTokenType: "urn:example:t"}},
		{"no subject token type", ExchangeRequest{SubjectToken: "sub", RequestedTokenType: "urn:example:t"}},
		{"no requested token type", ExchangeRequest{SubjectToken: "sub", SubjectTokenType: SubjectTokenTypeJWT}},
	}

	c := &Client{HTTP: http.DefaultClient, BaseURL: "https://example.test", Path: testTokenPath}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := c.Exchange(context.Background(), tt.req); err == nil {
				t.Fatal("Exchange() should fail on missing required field")
			}
		})
	}
}

func TestExchange_ServerError(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeBody(t, w, `{"error":"invalid_request","error_description":"bad subject"}`)
	})

	_, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
	})
	if err == nil {
		t.Fatal("Exchange() with 400 should fail")
	}
	if !strings.Contains(err.Error(), "invalid_request") || !strings.Contains(err.Error(), "bad subject") {
		t.Fatalf("error = %v, want both code and description", err)
	}
}

func TestExchange_ServerErrorWithoutJSON(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		writeBody(t, w, `something broke`)
	})

	_, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
	})
	if err == nil || !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "something broke") {
		t.Fatalf("error = %v, want status + body text", err)
	}
}

func TestExchange_MissingAccessToken(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, `{"token_type":"Bearer"}`)
	})

	_, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
	})
	if err == nil || !strings.Contains(err.Error(), "missing access_token") {
		t.Fatalf("error = %v, want missing access_token", err)
	}
}

func TestExchange_HTMLBodySurfacesFriendlyError(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		writeBody(t, w, `<html>Blocked by firewall</html>`)
	})

	_, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
	})
	if err == nil {
		t.Fatal("Exchange() with HTML body should error")
	}
	if !strings.Contains(err.Error(), "non-JSON") {
		t.Errorf("error missing non-JSON hint: %s", err)
	}
	if strings.Contains(err.Error(), "invalid character") {
		t.Errorf("raw JSON-decoder error leaked through: %s", err)
	}
}

func TestExchange_NoExpiry(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, `{"access_token":"acc","token_type":"Bearer"}`)
	})

	got, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
	})
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if !got.ExpiresAt.IsZero() {
		t.Fatalf("ExpiresAt = %v, want zero", got.ExpiresAt)
	}
}

// TestExchange_RequestTimeoutFires pins the slow-loris defence: a
// handler that never writes a response body must surface as a context
// deadline error rather than blocking the caller indefinitely.
//
// Cleanup order matters: t.Cleanup is LIFO, and httptest.Server.Close
// waits for in-flight handler goroutines to return. We register
// `close(hung)` AFTER newTestClient so it fires first and lets the
// handler exit before srv.Close runs.
func TestExchange_RequestTimeoutFires(t *testing.T) {
	t.Parallel()
	hung := make(chan struct{})

	c := newTestClient(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-hung:
		case <-r.Context().Done():
		}
	})
	t.Cleanup(func() { close(hung) })
	c.RequestTimeout = 50 * time.Millisecond

	_, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
	})
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
