package sts

import (
	"context"
	"errors"
	"fmt"
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

// freezeClock pins c.now() for the duration of a test. Per-Client
// rather than package-global so parallel tests with independent
// Clients don't race each other.
func freezeClock(t *testing.T, c *Client, at time.Time) {
	t.Helper()
	SetNowForTest(t, c, func() time.Time { return at })
}

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	return &Client{
		Transport:         srv.Client().Transport,
		BaseURL:           srv.URL,
		Path:              testTokenPath,
		AllowInsecureHTTP: true, // httptest.NewServer is http://
	}
}

func mustReadForm(t *testing.T, r *http.Request) {
	t.Helper()
	if err := r.ParseForm(); err != nil {
		t.Fatalf("parse form: %v", err)
	}
}

func TestExchange_Success(t *testing.T) {
	t.Parallel()

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
	freezeClock(t, c, time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC))

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
		writeBody(t, w, `{"access_token":"acc","expires_in":300}`)
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
		writeBody(t, w, `{"access_token":"acc","expires_in":300}`)
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

func TestExchange_SendsBasicAuthWhenClientIDSet(t *testing.T) {
	t.Parallel()

	// Zitadel's RFC 8693 implementation reads client credentials only
	// from Authorization: Basic for the token-exchange grant, never
	// from the form body (pkg/op/token_exchange.go: only the
	// r.BasicAuth() branch reads clientID for this grant). So when a
	// caller populates ClientID, we must send Basic Auth in addition
	// to whatever form fields they set via Extra.
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mustReadForm(t, r)
		id, secret, ok := r.BasicAuth()
		if !ok {
			t.Fatalf("expected Authorization: Basic header, got %q", r.Header.Get("Authorization"))
		}
		// RFC 6749 §2.3.1 mandates form-urlencoded credentials before they
		// go into the Basic header; spec-compliant servers decode via
		// url.QueryUnescape on the way in. "entire-cli" is identity
		// under QueryEscape — the round-trip premise is exercised in
		// TestExchange_BasicAuthRoundTripsReservedCharacters using a
		// secret that QueryEscape actually mutates.
		if id != "entire-cli" {
			t.Errorf("Basic client_id = %q, want %q", id, "entire-cli")
		}
		if secret != "" {
			t.Errorf("Basic client_secret = %q, want empty", secret)
		}
		// Form-body client_id must still flow for servers that read it
		// from the form instead — belt-and-braces.
		if got := r.PostForm.Get("client_id"); got != "entire-cli" {
			t.Errorf("form client_id = %q, want %q", got, "entire-cli")
		}
		writeBody(t, w, `{"access_token":"acc","expires_in":300}`)
	})

	if _, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
		ClientID:           "entire-cli",
		Extra:              url.Values{"client_id": {"entire-cli"}},
	}); err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
}

func TestExchange_BasicAuthRoundTripsReservedCharacters(t *testing.T) {
	t.Parallel()

	// Locks in the QueryEscape↔QueryUnescape contract that the Basic
	// Auth path depends on (RFC 6749 §2.3.1: client credentials are
	// form-urlencoded before going into the header). The standard
	// SendsBasicAuth test uses "entire-cli" — a string that is identity
	// under QueryEscape — so it would still pass if the escape call
	// were removed. This test uses a secret with characters that
	// QueryEscape mutates ('+', '/', '=', space) and asserts the value
	// the server recovers after Basic-decode + QueryUnescape matches
	// the originally-supplied bytes.
	const (
		clientID = "client-with-id"
		secret   = "p@ss w/+rd=&extra"
	)

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mustReadForm(t, r)
		id, encSecret, ok := r.BasicAuth()
		if !ok {
			t.Fatalf("expected Authorization: Basic header, got %q", r.Header.Get("Authorization"))
		}
		// Server-side spec-compliant decode: form-urlencoded values come
		// off the wire un-escaped via url.QueryUnescape.
		gotID, err := url.QueryUnescape(id)
		if err != nil {
			t.Fatalf("QueryUnescape(id): %v", err)
		}
		gotSecret, err := url.QueryUnescape(encSecret)
		if err != nil {
			t.Fatalf("QueryUnescape(secret): %v", err)
		}
		if gotID != clientID {
			t.Errorf("id round-trip: got %q, want %q", gotID, clientID)
		}
		if gotSecret != secret {
			t.Errorf("secret round-trip: got %q, want %q", gotSecret, secret)
		}
		writeBody(t, w, `{"access_token":"acc","expires_in":300}`)
	})

	if _, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
		ClientID:           clientID,
		ClientSecret:       secret,
	}); err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
}

func TestExchange_OmitsBasicAuthWhenClientIDEmpty(t *testing.T) {
	t.Parallel()

	// Public-client RFC 8693 token exchange against servers that don't
	// require client authentication on this grant: no Basic Auth
	// header at all. Sending Basic Og== (the encoded ":") would flip
	// servers that branch on header presence into credential-
	// evaluation mode and yield invalid_client — see the matching
	// "intentional fall-through" comment in sts.go's Exchange.
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mustReadForm(t, r)
		if _, _, ok := r.BasicAuth(); ok {
			t.Errorf("Authorization header should be absent when ClientID is empty, got %q", r.Header.Get("Authorization"))
		}
		writeBody(t, w, `{"access_token":"acc","expires_in":300}`)
	})

	if _, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
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
		writeBody(t, w, `{"access_token":"acc","expires_in":300}`)
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

	c := &Client{BaseURL: "https://example.test", Path: testTokenPath}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := c.Exchange(context.Background(), tt.req); err == nil {
				t.Fatal("Exchange() should fail on missing required field")
			}
		})
	}
}

// TestExchange_RejectsMalformedClientCredentials pins the validate()
// guards that prevent credentials from being silently mis-sent. Each
// case is a class of caller mistake that, without validation, would
// produce a wire shape the server would either reject opaquely or
// (worse) accept under the wrong identity.
func TestExchange_RejectsMalformedClientCredentials(t *testing.T) {
	t.Parallel()

	base := ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
	}

	withClient := func(id, secret string) ExchangeRequest {
		req := base
		req.ClientID = id
		req.ClientSecret = secret
		return req
	}
	withExtra := func(id string, extra url.Values) ExchangeRequest {
		req := base
		req.ClientID = id
		req.Extra = extra
		return req
	}

	tests := []struct {
		name     string
		req      ExchangeRequest
		errMatch string
	}{
		{
			// Most dangerous: caller supplies a secret but no id, the
			// Basic Auth branch is skipped on the empty id check, and
			// the secret is silently dropped instead of going on the
			// wire. Reject explicitly so the misconfiguration fails
			// fast.
			name:     "secret without id",
			req:      withClient("", "shh"),
			errMatch: "ClientSecret set without ClientID",
		},
		{
			// RFC 7617 §2 forbids ':' in the userid component of the
			// Basic Auth header. url.QueryEscape would turn ':' into
			// '%3A' and let it through, but a spec-compliant server
			// that QueryUnescapes on the way in gets ':' back and may
			// reject or mis-parse.
			name:     "id contains colon",
			req:      withClient("bad:id", ""),
			errMatch: "ClientID must not contain ':'",
		},
		{
			// RFC 6749 §2.3.1 restricts client_id to VSCHAR
			// (0x20–0x7E). Anything outside that range silently rides
			// the wire post-QueryEscape and surfaces as opaque
			// rejections downstream.
			name:     "id contains tab",
			req:      withClient("with\ttab", ""),
			errMatch: "ClientID contains non-printable",
		},
		{
			name:     "id contains newline",
			req:      withClient("with\nnewline", ""),
			errMatch: "ClientID contains non-printable",
		},
		{
			name:     "id contains non-ascii",
			req:      withClient("café", ""),
			errMatch: "ClientID contains non-printable",
		},
		{
			// Splitting client_id between the typed field and Extra
			// with different values produces a request where the
			// Basic header says one thing and the form body says
			// another. Whichever surface the server reads from "wins"
			// non-deterministically — fail fast.
			name:     "id disagrees with Extra[client_id]",
			req:      withExtra("a", url.Values{"client_id": {"b"}}),
			errMatch: `disagree`,
		},
		{
			// Multi-valued Extra["client_id"] is always rejected: servers
			// parsing via r.PostFormValue see only the first, servers
			// parsing via r.PostForm[...] see all, and which one wins is
			// invisible to the caller. Holds even when the typed
			// ClientID matches the first entry.
			name:     "Extra[client_id] holds multiple values",
			req:      withExtra("a", url.Values{"client_id": {"a", "b"}}),
			errMatch: `must hold at most one value`,
		},
		{
			// Same guard as above, but with the typed ClientID unset —
			// the multi-value Extra is internally inconsistent on its
			// own, before any cross-surface check kicks in.
			name:     "Extra[client_id] multi-value without typed ClientID",
			req:      withExtra("", url.Values{"client_id": {"a", "b"}}),
			errMatch: `must hold at most one value`,
		},
	}

	c := &Client{BaseURL: "https://example.test", Path: testTokenPath}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := c.Exchange(context.Background(), tt.req)
			if err == nil {
				t.Fatalf("Exchange() should fail for %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.errMatch) {
				t.Fatalf("error = %v, want to contain %q", err, tt.errMatch)
			}
		})
	}
}

// TestExchange_AcceptsValidClientCredentials confirms validate() lets
// the realistic happy-path shapes through unchanged. Counterpart to
// TestExchange_RejectsMalformedClientCredentials — together they pin
// the validation boundary in both directions.
func TestExchange_AcceptsValidClientCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  ExchangeRequest
	}{
		{
			// No credentials at all — server accepts anonymous exchange
			// or relies on the subject_token's binding. Same wire shape
			// as the historical caller (no Authorization header).
			name: "no credentials",
			req:  ExchangeRequest{},
		},
		{
			// Public client: id, empty secret. SetBasicAuth produces
			// base64("id:") which RFC 6749 §2.3.1 permits.
			name: "public client (id only)",
			req:  ExchangeRequest{ClientID: "entire-cli"},
		},
		{
			// Confidential client: id + secret.
			name: "confidential client",
			req:  ExchangeRequest{ClientID: "confidential-app", ClientSecret: "s3cret"},
		},
		{
			// Agreement between typed field and Extra is the documented
			// belt-and-braces pattern. validate() must let it through.
			name: "id agrees with Extra[client_id]",
			req: ExchangeRequest{
				ClientID: "entire-cli",
				Extra:    url.Values{"client_id": {"entire-cli"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := tt.req
			req.SubjectToken = "sub"
			req.SubjectTokenType = SubjectTokenTypeJWT
			req.RequestedTokenType = "urn:example:t"
			if err := req.validate(); err != nil {
				t.Fatalf("validate() = %v, want nil", err)
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

// TestExchange_SanitisesErrorCode pins that the server-supplied
// `error` field is sanitised before being interpolated into the
// returned error. RFC 6749 §4.1.2.1 limits the code to an ASCII
// alphabet, but the AS is the only enforcer — a buggy or hostile
// server returning embedded escape bytes must not paint the user's
// terminal via the code field even though we sanitise the description.
func TestExchange_SanitisesErrorCode(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeBody(t, w, "{\"error\":\"invalid_grant\\u009b[31m\",\"error_description\":\"clean\"}")
	})

	_, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
	})
	if err == nil {
		t.Fatal("Exchange() with sanitised-code body should still fail")
	}
	if strings.ContainsRune(err.Error(), '\u009b') || strings.ContainsRune(err.Error(), '\x1b') {
		t.Fatalf("error = %q, error code carried control bytes through", err.Error())
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("error = %q, expected sanitised code remnant to remain", err.Error())
	}
	// Sanitisation happens in the struct, not at render time, so the
	// typed Code field a caller branches on must be clean too — not just
	// the rendered message.
	var xe *ExchangeError
	if !errors.As(err, &xe) {
		t.Fatalf("error %v (%T) is not an *ExchangeError", err, err)
	}
	if strings.ContainsRune(xe.Code, '\u009b') || strings.ContainsRune(xe.Code, '\x1b') {
		t.Fatalf("Code = %q carried control bytes through", xe.Code)
	}
}

// TestExchange_ReturnsTypedExchangeError pins that a structured OAuth
// error response surfaces as *ExchangeError with the parsed code, status,
// and description — letting callers branch on the failure mode without
// substring-matching — while Error() still renders the legacy string.
func TestExchange_ReturnsTypedExchangeError(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeBody(t, w, `{"error":"invalid_target","error_description":"no mirror at this URL"}`)
	})

	_, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
	})
	var xe *ExchangeError
	if !errors.As(err, &xe) {
		t.Fatalf("error %v (%T) is not an *ExchangeError", err, err)
	}
	if xe.Code != "invalid_target" {
		t.Errorf("Code = %q, want invalid_target", xe.Code)
	}
	if xe.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want %d", xe.StatusCode, http.StatusBadRequest)
	}
	if xe.Description != "no mirror at this URL" {
		t.Errorf("Description = %q, want %q", xe.Description, "no mirror at this URL")
	}
	// Rendered message must match the pre-typed-error format byte-for-byte.
	if want := "token exchange: status 400: invalid_target: no mirror at this URL"; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

// TestExchange_ExchangeErrorWithoutDescription exercises the
// no-description branch of ExchangeError.Error(): error_description is
// OPTIONAL per RFC 6749 §5.2, so an AS may send `error` alone. The typed
// Description must be empty and the rendered message must drop the
// trailing ": <desc>" rather than render a dangling separator.
func TestExchange_ExchangeErrorWithoutDescription(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeBody(t, w, `{"error":"invalid_target"}`)
	})

	_, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
	})
	var xe *ExchangeError
	if !errors.As(err, &xe) {
		t.Fatalf("error %v (%T) is not an *ExchangeError", err, err)
	}
	if xe.Description != "" {
		t.Errorf("Description = %q, want empty", xe.Description)
	}
	if want := "token exchange: status 400: invalid_target"; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestExchange_ServerErrorWithoutJSON(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		writeBody(t, w, "something\x00 broke")
	})

	_, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
	})
	if err == nil || !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "something broke") {
		t.Fatalf("error = %v, want status + sanitised body text", err)
	}
	if strings.ContainsRune(err.Error(), '\x00') {
		t.Fatalf("error = %q, contains unsanitised NUL", err.Error())
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

// TestExchange_RejectsMissingExpiry pins the policy: exchanged tokens
// must come back with a positive expires_in. A missing or zero value
// is either misconfiguration or a hostile AS — either way we refuse
// to cache an unknown-lifetime bearer.
func TestExchange_RejectsMissingExpiry(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
	}{
		{"missing", `{"access_token":"acc","token_type":"Bearer"}`},
		{"zero", `{"access_token":"acc","token_type":"Bearer","expires_in":0}`},
		{"negative", `{"access_token":"acc","token_type":"Bearer","expires_in":-1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				writeBody(t, w, tc.body)
			})
			_, err := c.Exchange(context.Background(), ExchangeRequest{
				SubjectToken:       "sub",
				SubjectTokenType:   SubjectTokenTypeJWT,
				RequestedTokenType: "urn:example:t",
			})
			if err == nil {
				t.Fatalf("Exchange(%s expires_in) returned nil error, want non-positive expires_in", tc.name)
			}
			if !strings.Contains(err.Error(), "non-positive expires_in") {
				t.Fatalf("err = %v, want non-positive expires_in error", err)
			}
		})
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

// TestResolveURL_RejectsAbsolutePath pins the redirect defence: an
// absolute Path would replace BaseURL via url.ResolveReference,
// sending the subject_token to whatever host the caller (or its
// configuration source) supplied. The library refuses.
func TestResolveURL_RejectsAbsolutePath(t *testing.T) {
	t.Parallel()
	cases := []string{
		"https://attacker.example.com/sts",
		"http://attacker.example.com/sts",
		"//attacker.example.com/sts",
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

// TestNew_RequiresFields pins the fail-fast contract for sts.New.
// BaseURL + Path are required; Transport is optional (the package
// builds its own http.Client when nil); AllowInsecureHTTP is a
// production-disabled boolean. nil-Client is rejected so the
// constructor never returns a typed-nil.
func TestNew_RequiresFields(t *testing.T) {
	t.Parallel()

	base := func() *Client {
		return &Client{BaseURL: "https://sts.example.com", Path: "/sts/token"}
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
		{"empty Path", func(c *Client) { c.Path = "" }, "Path"},
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

// TestExchangeRequest_StringRedactsSubjectToken pins the redaction
// contract for the RFC 8693 request type: only SubjectToken (the
// user's bearer) is redacted. Other fields are configuration
// metadata and are intentionally shown verbatim — including Extra,
// which is documented as caller-responsibility for log hygiene.
func TestExchangeRequest_StringRedactsSubjectToken(t *testing.T) {
	t.Parallel()

	req := ExchangeRequest{
		SubjectToken:       "super-secret-subject-token-xyz",
		SubjectTokenType:   "urn:ietf:params:oauth:token-type:jwt",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		Audience:           "https://api.example.com",
		Resource:           "https://api.example.com",
		Scope:              "read",
		ClientID:           "entire-cli",
		ClientSecret:       "super-secret-client-secret-abc",
		Extra:              url.Values{"x-tenant": []string{"acme"}},
	}

	got := req.String()
	for _, leak := range []string{
		"super-secret-subject-token-xyz",
		"super-secret-client-secret-abc",
	} {
		if strings.Contains(got, leak) {
			t.Fatalf("String() leaked %q: %q", leak, got)
		}
	}
	if !strings.Contains(got, "<elided:30 bytes>") {
		t.Fatalf("String() missing elided placeholder: %q", got)
	}
	for _, want := range []string{
		`SubjectTokenType:"urn:ietf:params:oauth:token-type:jwt"`,
		`Audience:"https://api.example.com"`,
		`Scope:"read"`,
		`ClientID:"entire-cli"`,
		"x-tenant",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("String() should show %q: %q", want, got)
		}
	}

	// And %#v must redact both bearer-equivalents via GoString.
	v := fmt.Sprintf("%#v", req)
	for _, leak := range []string{
		"super-secret-subject-token-xyz",
		"super-secret-client-secret-abc",
	} {
		if strings.Contains(v, leak) {
			t.Fatalf("%%#v leaked %q: %q", leak, v)
		}
	}
}

// TestExchange_ClampsHugeExpiresIn pins that an absurd server-provided
// expires_in is clamped before multiplying into a time.Duration. Without the
// clamp, a value above ~9.2e9 overflows time.Duration's int64 nanosecond
// range, wrapping ExpiresAt into the past so a freshly-minted token looks
// already-expired.
func TestExchange_ClampsHugeExpiresIn(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, `{"access_token":"acc","token_type":"Bearer","expires_in":9300000000}`)
	})
	freezeClock(t, c, now)

	ts, err := c.Exchange(context.Background(), ExchangeRequest{
		SubjectToken:       "sub",
		SubjectTokenType:   SubjectTokenTypeJWT,
		RequestedTokenType: "urn:example:t",
	})
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if !ts.ExpiresAt.After(now) {
		t.Fatalf("ExpiresAt = %v, want a future time (clamped, not overflowed into the past)", ts.ExpiresAt)
	}
}
