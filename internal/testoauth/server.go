package testoauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entireio/auth-go/tokens"
)

// FailureMode controls how ForceNextRefresh makes the refresh handler behave.
type FailureMode int

const (
	// FailNone is the default: no forced failure.
	FailNone FailureMode = iota
	// FailInvalidGrant makes the next refresh response return 400 invalid_grant
	// without consuming the refresh token.
	FailInvalidGrant
	// FailNetworkError hijacks the TCP connection and closes it before writing
	// any response, causing the client to see a transport error.
	FailNetworkError
)

// Config configures a Server. All fields are optional.
type Config struct {
	// Now is the server's clock. Defaults to time.Now.
	Now func() time.Time

	// LoginJWTTTL is the access_token (login JWT) lifetime in refresh
	// and exchange responses. Defaults to 5 * time.Minute.
	LoginJWTTTL time.Duration

	// IdempotencySuccessor is the window during which a replay of a
	// recently-consumed RT returns the already-issued successor instead
	// of revoking the family. Defaults to 0 (strict reuse-detection).
	IdempotencySuccessor time.Duration
}

func (cfg Config) now() time.Time {
	if cfg.Now != nil {
		return cfg.Now()
	}
	return time.Now()
}

func (cfg Config) loginJWTTTL() time.Duration {
	if cfg.LoginJWTTTL > 0 {
		return cfg.LoginJWTTTL
	}
	return 5 * time.Minute
}

// deviceSession holds state for one in-progress device authorization.
type deviceSession struct {
	userCode  string
	clientID  string
	scope     string
	approved  bool
	expiresAt time.Time
}

// Server is a test OAuth authorization server backed by httptest.Server.
// It implements /oauth/token (refresh_token, token-exchange, device_code
// grants) and /oauth/device_authorization.
//
// Construct with NewServer; the underlying httptest.Server is started
// immediately. Cleanup is registered via t.Cleanup.
type Server struct {
	cfg       Config
	reg       *Registry
	httpSrv   *httptest.Server
	closeOnce sync.Once

	// device sessions indexed by device_code.
	mu       sync.Mutex
	sessions map[string]*deviceSession

	// forceNext overrides the next refresh handler call. Guards by mu.
	forceNext FailureMode

	// stallActive and stallRelease implement the one-shot stall used by
	// StallNextRefresh. Both are guarded by mu.
	stallActive  bool
	stallRelease chan struct{}

	// per-category atomic counters.
	totalGrants    atomic.Int64
	refreshGrants  atomic.Int64
	exchangeGrants atomic.Int64
	deviceGrants   atomic.Int64
}

// SeededLogin is the snapshot returned by SeedFamily.
type SeededLogin struct {
	LoginJWT     string
	RefreshToken string
	FamilyID     string
	Subject      string
	Audience     []string
}

// NewServer constructs and starts the mock OAuth server. Cleanup (Close) is
// registered via t.Cleanup.
func NewServer(t testing.TB, cfg Config) *Server {
	t.Helper()
	s := &Server{
		cfg:      cfg,
		reg:      NewRegistry(),
		sessions: make(map[string]*deviceSession),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", s.handleToken)
	mux.HandleFunc("/oauth/device_authorization", s.handleDeviceAuthorization)

	s.httpSrv = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// URL returns the base URL of the httptest server (e.g. http://127.0.0.1:NNNN).
func (s *Server) URL() string { return s.httpSrv.URL }

// Close stops the httptest server. Idempotent.
func (s *Server) Close() {
	s.closeOnce.Do(s.httpSrv.Close)
}

// SeedFamily creates a fresh family and mints an initial login JWT against it.
// Useful to bypass the device-flow login in tests that target the refresh path.
func (s *Server) SeedFamily(sub string, aud []string) SeededLogin {
	f, rt := s.reg.Seed(sub, aud)
	now := s.cfg.now()
	jwt := s.mintLoginJWT(f, now)
	return SeededLogin{
		LoginJWT:     jwt,
		RefreshToken: rt,
		FamilyID:     f.ID(),
		Subject:      f.Subject(),
		Audience:     f.Audience(),
	}
}

// ApproveDeviceCode flips a pending device_code session to approved.
// Test-driver hook for the device-flow path. Panics if the device_code is
// unknown — test misuse (typo, wrong order, already-expired code) would
// otherwise cause a silent 600-second hang on the polling side.
func (s *Server) ApproveDeviceCode(deviceCode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[deviceCode]
	if !ok {
		panic(fmt.Sprintf("testoauth: ApproveDeviceCode: unknown device_code %q (%d sessions registered)", deviceCode, len(s.sessions)))
	}
	sess.approved = true
}

// GrantCount returns the total number of /oauth/token requests dispatched
// to a grant-type handler, including forced-failure injections that close
// the connection without writing a response. Excludes requests rejected
// before dispatch (wrong HTTP method, malformed form, unsupported
// grant_type).
func (s *Server) GrantCount() int {
	return int(s.totalGrants.Load())
}

// RefreshGrantCount returns the number of successful refresh_token grants.
func (s *Server) RefreshGrantCount() int {
	return int(s.refreshGrants.Load())
}

// ExchangeGrantCount returns the number of successful token-exchange grants.
func (s *Server) ExchangeGrantCount() int {
	return int(s.exchangeGrants.Load())
}

// DeviceGrantCount returns the number of successful device_code grants.
func (s *Server) DeviceGrantCount() int {
	return int(s.deviceGrants.Load())
}

// FamilyRevoked reports whether the family with the given ID has been revoked.
func (s *Server) FamilyRevoked(fid string) bool {
	f, ok := s.reg.FamilyByID(fid)
	return ok && f.Revoked()
}

// ForceNextRefresh configures a one-shot override for the next refresh handler
// call. The override is consumed on the first call after it is set. The returned
// release function clears the override early (no-op if already consumed).
//
// FailInvalidGrant: returns 400 invalid_grant without touching the RT or family.
// FailNetworkError: hijacks the TCP connection and closes it immediately so the
// client sees a transport error from http.Client.Do. The RT is not consumed.
func (s *Server) ForceNextRefresh(mode FailureMode) (release func()) {
	s.mu.Lock()
	s.forceNext = mode
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		if s.forceNext == mode {
			s.forceNext = FailNone
		}
		s.mu.Unlock()
	}
}

// StallNextRefresh causes the next /oauth/token refresh_token request to
// block in the handler until release is called, then proceed normally
// (rotation + JWT mint). Parent tests use this to keep a refresh
// in-flight across processes while exercising concurrent mutations.
// One-shot: only the next refresh stalls; subsequent refreshes go
// through immediately. Returns release; calling release while a request
// is stalled unblocks it. Calling release before any request stalls
// clears the override so no future request stalls.
//
// While stalled, the request still holds refreshMu + processLock on the
// CLIENT side (the Manager that initiated it) — that's the whole point.
// Server-side, the family is NOT consumed until release; if the parent
// abandons the stalled request without releasing, the test will hang.
func (s *Server) StallNextRefresh() (release func()) {
	ch := make(chan struct{})
	s.mu.Lock()
	s.stallActive = true
	s.stallRelease = ch
	s.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			s.stallActive = false
			s.stallRelease = nil
			s.mu.Unlock()
			close(ch)
		})
	}
}

// mintLoginJWT mints a login JWT for the given family using the server clock.
func (s *Server) mintLoginJWT(f *Family, now time.Time) string {
	ttl := s.cfg.loginJWTTTL()
	return MintUnsignedJWT(Claims{
		Issuer:    s.URL(),
		Subject:   f.Subject(),
		Audience:  f.Audience(),
		FamilyID:  f.ID(),
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	})
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// oauthErrorResponse writes an OAuth error response.
func oauthErrorResponse(w http.ResponseWriter, code, desc string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

// handleToken dispatches /oauth/token by grant_type.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthErrorResponse(w, "invalid_request", "could not parse form")
		return
	}
	grantType := r.PostForm.Get("grant_type")
	switch grantType {
	case "refresh_token":
		s.handleRefresh(w, r)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		s.handleTokenExchange(w, r)
	case "urn:ietf:params:oauth:grant-type:device_code":
		s.handleDeviceCodePoll(w, r)
	default:
		oauthErrorResponse(w, "unsupported_grant_type", "unknown grant_type: "+grantType)
	}
}

// handleRefresh implements the refresh_token grant.
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	s.totalGrants.Add(1)

	// Check for one-shot stall override (before forced-failure check).
	// Pop the stall atomically so only the very next request blocks.
	s.mu.Lock()
	var stallCh chan struct{}
	if s.stallActive {
		stallCh = s.stallRelease
		s.stallActive = false
		s.stallRelease = nil
	}
	s.mu.Unlock()
	if stallCh != nil {
		<-stallCh
	}

	// Check for forced failure override (one-shot).
	s.mu.Lock()
	forced := s.forceNext
	if forced != FailNone {
		s.forceNext = FailNone
	}
	s.mu.Unlock()

	if forced == FailInvalidGrant {
		oauthErrorResponse(w, "invalid_grant", "forced failure for test")
		return
	}
	if forced == FailNetworkError {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "server does not support hijacking", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			http.Error(w, "hijack failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_ = conn.Close()
		return
	}

	rt := r.PostForm.Get("refresh_token")
	if rt == "" {
		oauthErrorResponse(w, "invalid_request", "refresh_token is required")
		return
	}

	now := s.cfg.now()
	newRT, _, revoked := s.reg.Consume(rt, now, s.cfg.IdempotencySuccessor)
	if revoked {
		oauthErrorResponse(w, "invalid_grant", "refresh token consumed or revoked")
		return
	}

	// Look up the family to mint the new JWT.
	f, ok := s.reg.FamilyByRefreshToken(newRT)
	if !ok {
		oauthErrorResponse(w, "server_error", "could not resolve family")
		return
	}

	accessToken := s.mintLoginJWT(f, now)
	s.refreshGrants.Add(1)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"refresh_token": newRT,
		"token_type":    "Bearer",
		"expires_in":    int(s.cfg.loginJWTTTL().Seconds()),
		"scope":         strings.Join(f.Audience(), " "),
	})
}

// jwtFamilyID extracts the "fid" claim from a JWT payload without verifying
// the signature. tokens.ParseClaims does not expose fid, so we decode the
// payload segment directly.
func jwtFamilyID(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var payload struct {
		FID string `json:"fid"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		return ""
	}
	return payload.FID
}

// handleTokenExchange implements the RFC 8693 token-exchange grant.
func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	s.totalGrants.Add(1)

	subjectToken := r.PostForm.Get("subject_token")
	if subjectToken == "" {
		oauthErrorResponse(w, "invalid_request", "subject_token is required")
		return
	}

	// Validate the subject token claims.
	claims, err := tokens.ParseClaims(subjectToken)
	if err != nil {
		oauthErrorResponse(w, "invalid_grant", "invalid subject_token: "+err.Error())
		return
	}
	if claims.Issuer != s.URL() {
		oauthErrorResponse(w, "invalid_grant", "subject_token iss does not match server")
		return
	}

	fid := jwtFamilyID(subjectToken)
	if fid == "" {
		oauthErrorResponse(w, "invalid_grant", "subject_token missing fid claim")
		return
	}

	f, ok := s.reg.FamilyByID(fid)
	if !ok {
		oauthErrorResponse(w, "invalid_grant", "unknown family")
		return
	}
	if f.Revoked() {
		oauthErrorResponse(w, "invalid_grant", "family has been revoked")
		return
	}

	// Determine target audience: resource takes precedence over audience.
	resource := r.PostForm.Get("resource")
	audience := r.PostForm.Get("audience")
	var targetAud string
	if resource != "" {
		targetAud = resource
	} else if audience != "" {
		targetAud = audience
	} else {
		oauthErrorResponse(w, "invalid_target", "resource or audience is required")
		return
	}

	now := s.cfg.now()
	const exchangeTTL = 5 * time.Minute
	accessToken := MintUnsignedJWT(Claims{
		Issuer:    s.URL(),
		Subject:   claims.Subject,
		Audience:  []string{targetAud},
		IssuedAt:  now,
		ExpiresAt: now.Add(exchangeTTL),
	})

	s.exchangeGrants.Add(1)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      accessToken,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        "Bearer",
		"expires_in":        int(exchangeTTL.Seconds()),
		"scope":             r.PostForm.Get("scope"),
	})
}

// handleDeviceCodePoll implements the device_code grant poll.
func (s *Server) handleDeviceCodePoll(w http.ResponseWriter, r *http.Request) {
	s.totalGrants.Add(1)

	deviceCode := r.PostForm.Get("device_code")
	if deviceCode == "" {
		oauthErrorResponse(w, "invalid_request", "device_code is required")
		return
	}

	s.mu.Lock()
	sess, ok := s.sessions[deviceCode]
	s.mu.Unlock()

	if !ok {
		oauthErrorResponse(w, "invalid_grant", "unknown or expired device_code")
		return
	}

	now := s.cfg.now()
	if now.After(sess.expiresAt) {
		oauthErrorResponse(w, "expired_token", "device_code has expired")
		return
	}

	if !sess.approved {
		oauthErrorResponse(w, "authorization_pending", "user has not yet approved the request")
		return
	}

	// Approved: mint a family and initial login JWT.
	sub := "device-user"
	var aud []string
	if sess.scope != "" {
		aud = strings.Fields(sess.scope)
	}
	f, rt := s.reg.Seed(sub, aud)
	accessToken := s.mintLoginJWT(f, now)

	s.deviceGrants.Add(1)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"refresh_token": rt,
		"token_type":    "Bearer",
		"expires_in":    int(s.cfg.loginJWTTTL().Seconds()),
		"scope":         sess.scope,
	})
}

// handleDeviceAuthorization implements RFC 8628 §3.1 device authorization.
func (s *Server) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthErrorResponse(w, "invalid_request", "could not parse form")
		return
	}

	clientID := r.PostForm.Get("client_id")
	scope := r.PostForm.Get("scope")

	deviceCode := randBase64(24)
	userCode := randUserCode()

	now := s.cfg.now()
	sess := &deviceSession{
		userCode:  userCode,
		clientID:  clientID,
		scope:     scope,
		approved:  false,
		expiresAt: now.Add(600 * time.Second),
	}

	s.mu.Lock()
	s.sessions[deviceCode] = sess
	s.mu.Unlock()

	verificationURI := s.URL() + "/device"
	verificationURIComplete := s.URL() + "/device?user_code=" + userCode

	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURIComplete,
		"expires_in":                600,
		"interval":                  1,
	})
}

// randUserCode returns an 8-character alphanumeric user code suitable for
// display and safe for query parameters.
func randUserCode() string {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("testoauth: crypto/rand read: " + err.Error())
	}
	for i, v := range b {
		b[i] = charset[int(v)%len(charset)]
	}
	return string(b)
}
