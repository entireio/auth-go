package crossjuris

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const bearerOriginal = "Bearer original-eu-login-jwt"

// hintFor renders the structured 401 envelope pointing at origin.
func hintFor(origin string) string {
	return `{"error":"cross_juris_token_required","token_exchange_url":"` + origin + TokenPath + `","audience":"` + origin + `"}`
}

// exchangeCore is a home core whose /api accepts only the exchanged token
// and whose /oauth/token records subject_tokens and answers with
// exchangeSuccess. onReject writes the 401 the API returns for any other
// bearer.
func exchangeCore(t *testing.T, onReject func(w http.ResponseWriter, self string)) (*httptest.Server, *atomic.Int32, *recorder, *recorder) {
	t.Helper()
	exchangeHits := &atomic.Int32{}
	subjects, apiAuths := &recorder{}, &recorder{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == TokenPath {
			_ = r.ParseForm() //nolint:errcheck // test
			subjects.add(r.PostForm.Get("subject_token"))
			if user, _, _ := r.BasicAuth(); user != testClientID {
				t.Errorf("exchange Basic user = %q, want %q", user, testClientID)
			}
			if got := r.PostForm.Get("subject_token_type"); got != "urn:ietf:params:oauth:token-type:jwt" {
				t.Errorf("subject_token_type = %q", got)
			}
			if got := r.PostForm.Get("audience"); got != srv.URL {
				t.Errorf("audience = %q, want %q", got, srv.URL)
			}
			exchangeHits.Add(1)
			writeBody(t, w, exchangeSuccess)
			return
		}
		apiAuths.add(r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") == bearerExchanged {
			writeBody(t, w, `{"ok":true}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		onReject(w, srv.URL)
	}))
	t.Cleanup(srv.Close)
	return srv, exchangeHits, subjects, apiAuths
}

func bare401(t *testing.T) func(w http.ResponseWriter, _ string) {
	return func(w http.ResponseWriter, _ string) { writeBody(t, w, `{"error":"invalid token"}`) }
}

func hinted401(t *testing.T) func(w http.ResponseWriter, self string) {
	return func(w http.ResponseWriter, self string) { writeBody(t, w, hintFor(self)) }
}

// The production path: after a 421 the home core cannot verify the
// foreign-region JWT and answers a BARE 401. The Transport exchanges the
// original JWT at the home core's /oauth/token and retries.
func Test421ThenBare401Exchanges(t *testing.T) {
	t.Parallel()
	home, exchangeHits, subjects, apiAuths := exchangeCore(t, bare401(t))
	wrong := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		misdirectTo(t, w, home.URL)
	})
	wrong.peers = []string{home.URL}

	req, _ := http.NewRequest(http.MethodPost, wrong.URL()+"/api/v1/mirrors/collaborators", strings.NewReader(`{}`)) //nolint:errcheck,noctx // test
	req.Header.Set("Authorization", bearerOriginal)
	resp, err := exchangingClient(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	if exchangeHits.Load() != 1 {
		t.Fatalf("exchange hits=%d", exchangeHits.Load())
	}
	if got := subjects.snapshot(); len(got) != 1 || got[0] != "original-eu-login-jwt" {
		t.Fatalf("subject_token = %v", got)
	}
	if got := apiAuths.snapshot(); len(got) != 2 || got[0] != bearerOriginal || got[1] != bearerExchanged {
		t.Fatalf("home API auths = %v", got)
	}
}

func TestHinted401ExchangesAndRetries(t *testing.T) {
	t.Parallel()
	api, exchangeHits, _, apiAuths := exchangeCore(t, hinted401(t))

	resp := do(t, exchangingClient(t), http.MethodPost, api.URL+"/api/v1/mirrors", `{"a":1}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if exchangeHits.Load() != 1 {
		t.Fatalf("exchanges=%d", exchangeHits.Load())
	}
	if got := apiAuths.snapshot(); len(got) != 2 || got[0] != bearerUser || got[1] != bearerExchanged {
		t.Fatalf("api auths = %v", got)
	}
}

func TestBare401WithoutRedirectPassesThrough(t *testing.T) {
	t.Parallel()
	exchangeHits := atomic.Int32{}
	srv := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == TokenPath {
			exchangeHits.Add(1)
			writeBody(t, w, exchangeSuccess)
			return
		}
		c.record(r)
		w.WriteHeader(http.StatusUnauthorized)
		writeBody(t, w, `{"error":"invalid token"}`)
	})

	resp := do(t, exchangingClient(t), http.MethodGet, srv.URL()+"/api/v1/me", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if srv.hits.Load() != 1 || exchangeHits.Load() != 0 {
		t.Fatalf("hits=%d exchanges=%d", srv.hits.Load(), exchangeHits.Load())
	}
}

// Follow-only mode (no ClientID): 421s are followed, but neither 401
// shape triggers an exchange.
func TestFollowOnlyNeverExchanges(t *testing.T) {
	t.Parallel()
	home, exchangeHits, _, apiAuths := exchangeCore(t, hinted401(t))
	wrong := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		misdirectTo(t, w, home.URL)
	})
	wrong.peers = []string{home.URL}

	client := followOnlyClient(t)
	for _, target := range []string{wrong.URL() + "/api/v1/mirrors", home.URL + "/api/v1/mirrors"} {
		resp := do(t, client, http.MethodGet, target, "")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: got %d, want the home core's 401 passed through", target, resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // test
		if !strings.Contains(string(body), "cross_juris_token_required") {
			t.Errorf("%s: 401 body must survive: %q", target, body)
		}
	}
	if exchangeHits.Load() != 0 {
		t.Fatalf("follow-only transport ran %d exchanges", exchangeHits.Load())
	}
	if got := apiAuths.snapshot(); len(got) != 2 || got[0] != bearerUser || got[1] != bearerUser {
		t.Fatalf("home API auths = %v, want the original bearer only", got)
	}
}

func TestRejectsOffOriginExchangeURL(t *testing.T) {
	t.Parallel()
	attackerHits := atomic.Int32{}
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attackerHits.Add(1)
		writeBody(t, w, exchangeSuccess)
	}))
	t.Cleanup(attacker.Close)

	api := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		w.WriteHeader(http.StatusUnauthorized)
		writeBody(t, w, `{"error":"cross_juris_token_required","token_exchange_url":"`+attacker.URL+TokenPath+`","audience":"https://api.test"}`)
	})

	resp := do(t, exchangingClient(t), http.MethodGet, api.URL()+"/api/v1/me", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if attackerHits.Load() != 0 {
		t.Fatalf("attacker host received the JWT (hits=%d)", attackerHits.Load())
	}
}

func TestExchangeFailurePropagates401(t *testing.T) {
	t.Parallel()
	apiHits := atomic.Int32{}
	var api *httptest.Server
	api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == TokenPath {
			w.WriteHeader(http.StatusBadRequest)
			writeBody(t, w, `{"error":"invalid_grant"}`)
			return
		}
		apiHits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		writeBody(t, w, hintFor(api.URL))
	}))
	t.Cleanup(api.Close)

	var lines recorder
	rt := newTestTransport(t, Config{ClientID: testClientID, Logf: func(format string, args ...any) {
		lines.add(format)
	}})
	resp := do(t, &http.Client{Transport: rt}, http.MethodGet, api.URL+"/api/v1/me", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want original 401 surfaced", resp.StatusCode)
	}
	if apiHits.Load() != 1 {
		t.Fatalf("no retry when exchange fails, got %d hits", apiHits.Load())
	}
	body, _ := io.ReadAll(resp.Body) //nolint:errcheck // test
	if !strings.Contains(string(body), "cross_juris_token_required") {
		t.Errorf("original hint body must survive the failed exchange: %q", body)
	}
	if got := lines.snapshot(); len(got) != 1 || !strings.Contains(got[0], "exchange failed") {
		t.Fatalf("Logf lines = %v", got)
	}
}

func TestTokenCacheReusesExchanged(t *testing.T) {
	t.Parallel()
	api, exchangeHits, _, apiAuths := exchangeCore(t, hinted401(t))

	client := exchangingClient(t)
	for i := range 2 {
		resp := do(t, client, http.MethodGet, api.URL+"/api/v1/me", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: got %d", i, resp.StatusCode)
		}
	}
	if exchangeHits.Load() != 1 {
		t.Fatalf("exchange must run once across both requests, got %d", exchangeHits.Load())
	}
	if got := apiAuths.snapshot(); len(got) != 3 || got[2] != bearerExchanged {
		t.Fatalf("second request must present the cached token first: %v", got)
	}
}

// Regression for chained exchange: hint at the misdirected core →
// exchange → retry → 421 to home → hint at home. The home exchange must
// use the ORIGINAL login JWT, not the misdirected core's exchanged token.
func TestExchangeAfter401Then421UsesOriginalSubject(t *testing.T) {
	t.Parallel()
	home, homeExchanges, homeSubjects, homeAuths := exchangeCore(t, hinted401(t))

	misdirectedExchanges := atomic.Int32{}
	misdirectedHits := atomic.Int32{}
	var misdirected *httptest.Server
	misdirected = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownPath:
			writeFederation(t, w, []string{home.URL})
			return
		case TokenPath:
			misdirectedExchanges.Add(1)
			writeBody(t, w, `{"access_token":"misdirected-exchanged-jwt","token_type":"Bearer","expires_in":300}`)
			return
		}
		if misdirectedHits.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			writeBody(t, w, hintFor(misdirected.URL))
			return
		}
		misdirectTo(t, w, home.URL)
	}))
	t.Cleanup(misdirected.Close)

	req, _ := http.NewRequest(http.MethodPost, misdirected.URL+"/api/v1/mirrors", strings.NewReader(`{}`)) //nolint:errcheck,noctx // test
	req.Header.Set("Authorization", bearerOriginal)
	resp, err := exchangingClient(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	if misdirectedExchanges.Load() != 1 || homeExchanges.Load() != 1 {
		t.Fatalf("misdirected=%d home=%d exchanges, want 1/1", misdirectedExchanges.Load(), homeExchanges.Load())
	}
	if got := homeSubjects.snapshot(); len(got) != 1 || got[0] != "original-eu-login-jwt" {
		t.Fatalf("home exchange subject_token = %v, want the original login JWT", got)
	}
	if got := homeAuths.snapshot(); len(got) != 2 || got[0] != bearerOriginal || got[1] != bearerExchanged {
		t.Fatalf("home API auths = %v", got)
	}
}

func TestValidateExchangeURL(t *testing.T) {
	t.Parallel()
	parse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	rt := &Transport{allowInsecure: true}
	cases := []struct {
		name, raw, from string
		ok              bool
	}{
		{"same-origin https", "https://example.test/oauth/token", "https://example.test/api", true},
		{"loopback http", "http://localhost:1234/oauth/token", "http://localhost:1234/api", true},
		{"off-origin", "https://attacker.test/oauth/token", "https://example.test/api", false},
		{"non-loopback http", "http://example.test/oauth/token", "http://example.test/api", false},
		{"wrong path", "https://example.test/auth/x", "https://example.test/api", false},
		{"empty", "", "https://example.test/api", false},
	}
	for _, tc := range cases {
		err := rt.validateExchangeURL(tc.raw, parse(tc.from))
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
	strict := &Transport{}
	if err := strict.validateExchangeURL("http://localhost:1234/oauth/token", parse("http://localhost:1234/api")); err == nil {
		t.Error("loopback http must be refused without AllowInsecureHTTP")
	}
}

func TestCacheTTL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		remaining, want time.Duration
	}{
		{time.Hour, cachedTokenTTL},
		{5 * time.Minute, cachedTokenTTL},
		{3 * time.Minute, 2 * time.Minute},
		{30 * time.Second, -30 * time.Second},
	}
	for _, tc := range cases {
		if got := cacheTTL(tc.remaining); got != tc.want {
			t.Errorf("cacheTTL(%v) = %v, want %v", tc.remaining, got, tc.want)
		}
	}
}

func TestTokenCacheEviction(t *testing.T) {
	t.Parallel()
	rt := &Transport{}
	rt.storeToken("https://example.test", "tok", 0)
	if _, ok := rt.lookupToken("https://example.test"); ok {
		t.Error("zero TTL must not be cached")
	}
	rt.storeToken("https://example.test", "tok", cachedTokenTTL)
	if _, ok := rt.lookupToken("https://example.test"); !ok {
		t.Fatal("fresh token must be a hit")
	}
	rt.tokens.Store("https://example.test", cachedExchangedToken{token: "tok", exp: time.Now().Add(-time.Second)})
	if _, ok := rt.lookupToken("https://example.test"); ok {
		t.Fatal("expired entry must be evicted")
	}
}
