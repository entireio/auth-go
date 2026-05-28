package testoauth_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/entireio/auth-go/internal/testoauth"
	"github.com/entireio/auth-go/tokens"
)

// postForm sends a POST with application/x-www-form-urlencoded body to url.
func postForm(t *testing.T, rawURL string, vals url.Values) *http.Response {
	t.Helper()
	resp, err := http.PostForm(rawURL, vals)
	if err != nil {
		t.Fatalf("POST %s: %v", rawURL, err)
	}
	return resp
}

// drainClose discards the response body and closes it. Use when the body
// content is not needed but errcheck requires the close error to be handled.
func drainClose(resp *http.Response) {
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
}

// decodeJSON decodes the response body into v and closes it.
func decodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode JSON %s: %v", b, err)
	}
}

// tokenResponse is the JSON shape returned by /oauth/token on success.
type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope"`
	IssuedTokenType string `json:"issued_token_type"`
}

// oauthError is the JSON shape returned on error.
type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func tokenURL(s *testoauth.Server) string { return s.URL() + "/oauth/token" }
func deviceAuthURL(s *testoauth.Server) string {
	return s.URL() + "/oauth/device_authorization"
}

func TestServer_RefreshHappyPathRotates(t *testing.T) {
	t.Parallel()
	srv := testoauth.NewServer(t, testoauth.Config{})

	seed := srv.SeedFamily("alice", []string{"https://api.example.com"})

	resp := postForm(t, tokenURL(srv), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {seed.RefreshToken},
		"client_id":     {"test-client"},
	})
	if resp.StatusCode != http.StatusOK {
		var e oauthError
		decodeJSON(t, resp, &e)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, e)
	}

	var tok tokenResponse
	decodeJSON(t, resp, &tok)

	if tok.AccessToken == "" {
		t.Fatal("access_token is empty")
	}
	if tok.RefreshToken == "" {
		t.Fatal("refresh_token is empty")
	}
	if tok.RefreshToken == seed.RefreshToken {
		t.Fatal("refresh_token was not rotated")
	}
	if tok.ExpiresIn <= 0 {
		t.Fatalf("expires_in = %d, want > 0", tok.ExpiresIn)
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", tok.TokenType)
	}

	claims, err := tokens.ParseClaims(tok.AccessToken)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if claims.Issuer != srv.URL() {
		t.Errorf("iss = %q, want %q", claims.Issuer, srv.URL())
	}
	if claims.Subject != seed.Subject {
		t.Errorf("sub = %q, want %q", claims.Subject, seed.Subject)
	}
	if srv.RefreshGrantCount() != 1 {
		t.Errorf("RefreshGrantCount = %d, want 1", srv.RefreshGrantCount())
	}
	if srv.GrantCount() < 1 {
		t.Errorf("GrantCount = %d, want >= 1", srv.GrantCount())
	}
}

func TestServer_RefreshReplayRevokes(t *testing.T) {
	t.Parallel()
	srv := testoauth.NewServer(t, testoauth.Config{})

	seed := srv.SeedFamily("bob", []string{"https://api.example.com"})
	fid := seed.FamilyID
	origRT := seed.RefreshToken

	// First refresh — succeeds.
	resp1 := postForm(t, tokenURL(srv), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {origRT},
		"client_id":     {"test-client"},
	})
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first refresh: expected 200, got %d", resp1.StatusCode)
	}
	drainClose(resp1)

	// Replay the original RT — should return invalid_grant and revoke.
	resp2 := postForm(t, tokenURL(srv), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {origRT},
		"client_id":     {"test-client"},
	})
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay: expected 400, got %d", resp2.StatusCode)
	}
	var e oauthError
	decodeJSON(t, resp2, &e)
	if e.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", e.Error)
	}
	if !srv.FamilyRevoked(fid) {
		t.Error("family should be revoked after replay")
	}
}

func TestServer_RefreshIdempotentReplay(t *testing.T) {
	t.Parallel()
	srv := testoauth.NewServer(t, testoauth.Config{
		IdempotencySuccessor: 100 * time.Millisecond,
	})

	seed := srv.SeedFamily("carol", []string{"https://api.example.com"})
	origRT := seed.RefreshToken
	fid := seed.FamilyID

	// First refresh.
	resp1 := postForm(t, tokenURL(srv), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {origRT},
		"client_id":     {"test-client"},
	})
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first refresh: expected 200, got %d", resp1.StatusCode)
	}
	var tok1 tokenResponse
	decodeJSON(t, resp1, &tok1)

	// Immediate replay of original RT within the idempotency window.
	resp2 := postForm(t, tokenURL(srv), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {origRT},
		"client_id":     {"test-client"},
	})
	if resp2.StatusCode != http.StatusOK {
		var e oauthError
		decodeJSON(t, resp2, &e)
		t.Fatalf("idempotent replay: expected 200, got %d: %v", resp2.StatusCode, e)
	}
	var tok2 tokenResponse
	decodeJSON(t, resp2, &tok2)

	if tok2.RefreshToken != tok1.RefreshToken {
		t.Errorf("idempotent replay returned different RT: %q vs %q", tok2.RefreshToken, tok1.RefreshToken)
	}
	if srv.FamilyRevoked(fid) {
		t.Error("family should NOT be revoked on idempotent replay")
	}
}

func TestServer_TokenExchangeMintsAudienceScoped(t *testing.T) {
	t.Parallel()
	srv := testoauth.NewServer(t, testoauth.Config{})

	seed := srv.SeedFamily("dave", []string{"https://api.example.com"})

	resource := "https://api.example.com"
	resp := postForm(t, tokenURL(srv), url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":        {seed.LoginJWT},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":             {resource},
		"client_id":            {"test-client"},
	})
	if resp.StatusCode != http.StatusOK {
		var e oauthError
		decodeJSON(t, resp, &e)
		t.Fatalf("token exchange: expected 200, got %d: %v", resp.StatusCode, e)
	}

	var tok tokenResponse
	decodeJSON(t, resp, &tok)

	if tok.AccessToken == "" {
		t.Fatal("access_token is empty")
	}
	if tok.IssuedTokenType == "" {
		t.Error("issued_token_type is empty")
	}
	if tok.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want > 0", tok.ExpiresIn)
	}

	claims, err := tokens.ParseClaims(tok.AccessToken)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != resource {
		t.Errorf("aud = %v, want [%q]", claims.Audience, resource)
	}
	if claims.Subject != seed.Subject {
		t.Errorf("sub = %q, want %q", claims.Subject, seed.Subject)
	}

	if srv.ExchangeGrantCount() != 1 {
		t.Errorf("ExchangeGrantCount = %d, want 1", srv.ExchangeGrantCount())
	}
}

func TestServer_TokenExchangeRejectsRevokedFamily(t *testing.T) {
	t.Parallel()
	srv := testoauth.NewServer(t, testoauth.Config{})

	seed := srv.SeedFamily("eve", []string{"https://api.example.com"})
	origRT := seed.RefreshToken

	// Consume and then replay to revoke the family.
	resp1 := postForm(t, tokenURL(srv), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {origRT},
		"client_id":     {"test-client"},
	})
	drainClose(resp1)
	// Replay to trigger revocation.
	resp2 := postForm(t, tokenURL(srv), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {origRT},
		"client_id":     {"test-client"},
	})
	drainClose(resp2)

	if !srv.FamilyRevoked(seed.FamilyID) {
		t.Fatal("family should be revoked after replay")
	}

	// Now try token exchange with the original login JWT — family is revoked.
	resp3 := postForm(t, tokenURL(srv), url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":        {seed.LoginJWT},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":             {"https://api.example.com"},
		"client_id":            {"test-client"},
	})
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on revoked family exchange, got %d", resp3.StatusCode)
	}
	var e oauthError
	decodeJSON(t, resp3, &e)
	if e.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", e.Error)
	}
}

func TestServer_DeviceFlowApprovedYieldsTokens(t *testing.T) {
	t.Parallel()
	srv := testoauth.NewServer(t, testoauth.Config{})

	// Start device authorization.
	daResp := postForm(t, deviceAuthURL(srv), url.Values{
		"client_id": {"test-client"},
		"scope":     {"openid"},
	})
	if daResp.StatusCode != http.StatusOK {
		t.Fatalf("device_authorization: expected 200, got %d", daResp.StatusCode)
	}
	var da struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	decodeJSON(t, daResp, &da)

	if da.DeviceCode == "" {
		t.Fatal("device_code is empty")
	}
	if len(da.UserCode) != 8 {
		t.Errorf("user_code = %q (len %d), want 8 chars", da.UserCode, len(da.UserCode))
	}
	if !strings.HasPrefix(da.VerificationURI, "http") {
		t.Errorf("verification_uri = %q, want http...", da.VerificationURI)
	}

	// Approve the device code.
	srv.ApproveDeviceCode(da.DeviceCode)

	// Poll for tokens.
	resp := postForm(t, tokenURL(srv), url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {"test-client"},
		"device_code": {da.DeviceCode},
	})
	if resp.StatusCode != http.StatusOK {
		var e oauthError
		decodeJSON(t, resp, &e)
		t.Fatalf("device poll: expected 200, got %d: %v", resp.StatusCode, e)
	}
	var tok tokenResponse
	decodeJSON(t, resp, &tok)

	if tok.AccessToken == "" {
		t.Fatal("access_token is empty")
	}
	if tok.RefreshToken == "" {
		t.Fatal("refresh_token is empty")
	}
	if srv.DeviceGrantCount() != 1 {
		t.Errorf("DeviceGrantCount = %d, want 1", srv.DeviceGrantCount())
	}
}

func TestServer_DeviceFlowPendingReturns400AuthorizationPending(t *testing.T) {
	t.Parallel()
	srv := testoauth.NewServer(t, testoauth.Config{})

	daResp := postForm(t, deviceAuthURL(srv), url.Values{
		"client_id": {"test-client"},
	})
	if daResp.StatusCode != http.StatusOK {
		t.Fatalf("device_authorization: expected 200, got %d", daResp.StatusCode)
	}
	var da struct {
		DeviceCode string `json:"device_code"`
	}
	decodeJSON(t, daResp, &da)

	// Poll immediately without approving.
	resp := postForm(t, tokenURL(srv), url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {"test-client"},
		"device_code": {da.DeviceCode},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("pending poll: expected 400, got %d", resp.StatusCode)
	}
	var e oauthError
	decodeJSON(t, resp, &e)
	if e.Error != "authorization_pending" {
		t.Errorf("error = %q, want authorization_pending", e.Error)
	}
}

func TestServer_UnsupportedGrantTypeReturns400(t *testing.T) {
	t.Parallel()
	srv := testoauth.NewServer(t, testoauth.Config{})

	resp := postForm(t, tokenURL(srv), url.Values{
		"grant_type": {"foo"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	var e oauthError
	decodeJSON(t, resp, &e)
	if e.Error != "unsupported_grant_type" {
		t.Errorf("error = %q, want unsupported_grant_type", e.Error)
	}
}

func TestServer_NowSeamControlsJWTExpiry(t *testing.T) {
	t.Parallel()
	fixedNow := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	ttl := 7 * time.Minute

	srv := testoauth.NewServer(t, testoauth.Config{
		Now:         func() time.Time { return fixedNow },
		LoginJWTTTL: ttl,
	})

	seed := srv.SeedFamily("frank", []string{"https://api.example.com"})

	resp := postForm(t, tokenURL(srv), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {seed.RefreshToken},
		"client_id":     {"test-client"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var tok tokenResponse
	decodeJSON(t, resp, &tok)

	claims, err := tokens.ParseClaims(tok.AccessToken)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	wantExp := fixedNow.Add(ttl).Truncate(time.Second)
	gotExp := claims.ExpiresAt.Truncate(time.Second)
	if !gotExp.Equal(wantExp) {
		t.Errorf("exp = %v, want %v (now+LoginJWTTTL)", gotExp, wantExp)
	}
}

func TestServer_ForceNextRefreshNetworkError(t *testing.T) {
	t.Parallel()
	srv := testoauth.NewServer(t, testoauth.Config{})
	seed := srv.SeedFamily("u", []string{"https://api"})

	release := srv.ForceNextRefresh(testoauth.FailNetworkError)
	t.Cleanup(release)

	// Use a real http.Client with a tight timeout so the test fails fast
	// even if the server forgets to close.
	c := &http.Client{Timeout: 2 * time.Second}
	body := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {seed.RefreshToken},
		"client_id":     {"test-cli"},
	}
	resp, err := c.Post(srv.URL()+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(body.Encode()))
	if err == nil {
		// Some responses may surface the error on body read rather than
		// Post itself, depending on when the server closed.
		_ = resp.Body.Close()
		// Probe a follow-up read of body to force the error to surface.
		// (Best-effort — typically Post itself errors when the server hijacks
		// and closes before any bytes are written.)
		t.Fatalf("expected transport error, got nil with status %d", resp.StatusCode)
	}

	// The one-shot override must be consumed: the next refresh succeeds
	// normally with the seeded RT (the previous attempt did not consume
	// it because the server closed before family.Consume ran).
	resp2, err := c.Post(srv.URL()+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(body.Encode()))
	if err != nil {
		t.Fatalf("follow-up refresh: %v", err)
	}
	drainClose(resp2)
	if resp2.StatusCode != 200 {
		t.Fatalf("follow-up refresh status = %d, want 200 (override should be one-shot)", resp2.StatusCode)
	}
}

func TestServer_ForceNextRefreshInvalidGrant(t *testing.T) {
	t.Parallel()
	srv := testoauth.NewServer(t, testoauth.Config{})

	seed := srv.SeedFamily("grace", []string{"https://api.example.com"})

	// Force next refresh to fail with invalid_grant.
	release := srv.ForceNextRefresh(testoauth.FailInvalidGrant)
	_ = release // one-shot: consumed on the request; release is a no-op after that

	// First refresh — should be forced to fail.
	resp1 := postForm(t, tokenURL(srv), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {seed.RefreshToken},
		"client_id":     {"test-client"},
	})
	if resp1.StatusCode != http.StatusBadRequest {
		t.Fatalf("forced failure: expected 400, got %d", resp1.StatusCode)
	}
	var e oauthError
	decodeJSON(t, resp1, &e)
	if e.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", e.Error)
	}

	// Second refresh (no force set) — should succeed using the same RT
	// (family not revoked by the forced failure).
	resp2 := postForm(t, tokenURL(srv), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {seed.RefreshToken},
		"client_id":     {"test-client"},
	})
	if resp2.StatusCode != http.StatusOK {
		var e2 oauthError
		decodeJSON(t, resp2, &e2)
		t.Fatalf("second refresh: expected 200, got %d: %v", resp2.StatusCode, e2)
	}
	drainClose(resp2)

	// Assert one-shot: the override was consumed, RefreshGrantCount reflects
	// the single successful grant.
	if srv.RefreshGrantCount() != 1 {
		t.Errorf("RefreshGrantCount = %d, want 1 (only second call succeeded)", srv.RefreshGrantCount())
	}
}

func TestServer_StallNextRefreshBlocksUntilRelease(t *testing.T) {
	t.Parallel()
	srv := testoauth.NewServer(t, testoauth.Config{})
	seed := srv.SeedFamily("u", nil)

	release := srv.StallNextRefresh()

	type result struct {
		status int
		err    error
		took   time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		c := &http.Client{Timeout: 5 * time.Second}
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {seed.RefreshToken}, "client_id": {"cli"}}
		resp, err := c.Post(srv.URL()+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		var st int
		if resp != nil {
			st = resp.StatusCode
			_ = resp.Body.Close()
		}
		done <- result{st, err, time.Since(start)}
	}()

	// Confirm the request is genuinely stalled (no response yet).
	select {
	case r := <-done:
		t.Fatalf("request completed before release: status=%d err=%v took=%v", r.status, r.err, r.took)
	case <-time.After(75 * time.Millisecond):
		// Expected: still stalled.
	}

	release()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("post-release error: %v", r.err)
		}
		if r.status != 200 {
			t.Fatalf("status = %d, want 200", r.status)
		}
		if r.took < 75*time.Millisecond {
			t.Errorf("took = %v, expected >75ms (the stall window)", r.took)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request did not unblock after release")
	}
}
