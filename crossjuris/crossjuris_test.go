package crossjuris

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const (
	testClientID    = "entire-cli"
	bearerUser      = "Bearer user-jwt"
	exchangeSuccess = `{"access_token":"home-exchanged-jwt","token_type":"Bearer","expires_in":300}`
	bearerExchanged = "Bearer home-exchanged-jwt"
)

// recorder collects strings captured inside handler goroutines for
// assertion in the test goroutine. HTTP completion is not a
// happens-before edge the race detector recognises.
type recorder struct {
	mu   sync.Mutex
	vals []string
}

func (r *recorder) add(v string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.vals = append(r.vals, v)
}

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.vals...)
}

// core is a scripted entire-core. It serves the federation manifest from
// peers and records the Authorization header of every other request.
type core struct {
	hits  atomic.Int32
	auths recorder
	peers []string
	srv   *httptest.Server
}

func (c *core) record(r *http.Request) {
	c.hits.Add(1)
	c.auths.add(r.Header.Get("Authorization"))
}

func (c *core) URL() string { return c.srv.URL }

func newCore(t *testing.T, handler func(c *core, w http.ResponseWriter, r *http.Request)) *core {
	t.Helper()
	c := &core{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == WellKnownPath {
			writeFederation(t, w, c.peers)
			return
		}
		handler(c, w, r)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func writeFederation(t *testing.T, w http.ResponseWriter, peers []string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	quoted := make([]string, len(peers))
	for i, p := range peers {
		quoted[i] = `"` + p + `"`
	}
	writeBody(t, w, `{"peer_auth_hosts":[`+strings.Join(quoted, ",")+`]}`)
}

func writeBody(t *testing.T, w io.Writer, body string) {
	t.Helper()
	if _, err := io.WriteString(w, body); err != nil {
		t.Errorf("write body: %v", err)
	}
}

func misdirectTo(t *testing.T, w http.ResponseWriter, homeCoreURL string) {
	t.Helper()
	w.WriteHeader(http.StatusMisdirectedRequest)
	writeBody(t, w, `{"error":"misdirected","home_core_url":"`+homeCoreURL+`","jurisdiction":"eu"}`)
}

// newTestTransport builds the Transport under test over a connection
// pool private to this test: httptest.Server.Close calls
// http.DefaultTransport.CloseIdleConnections, which would break a
// parallel test's pooled connection.
func newTestTransport(t *testing.T, cfg Config) *Transport {
	t.Helper()
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport is %T, want *http.Transport", http.DefaultTransport)
	}
	tr := base.Clone()
	t.Cleanup(tr.CloseIdleConnections)
	cfg.Base = tr
	cfg.AllowInsecureHTTP = true
	rt, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func exchangingClient(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{Transport: newTestTransport(t, Config{ClientID: testClientID})}
}

func followOnlyClient(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{Transport: newTestTransport(t, Config{})}
}

func do(t *testing.T, client *http.Client, method, target string, body string) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, target, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", bearerUser)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestNew(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{}); err != nil {
		t.Errorf("empty Config must be valid: %v", err)
	}
	if _, err := New(Config{ClientID: "bad:id"}); err == nil {
		t.Error("ClientID with ':' must be rejected")
	}
}

func TestPassThrough(t *testing.T) {
	t.Parallel()
	srv := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		writeBody(t, w, `{"ok":true}`)
	})

	resp := do(t, exchangingClient(t), http.MethodGet, srv.URL()+"/api/v1/me", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body) //nolint:errcheck // test
	if string(body) != `{"ok":true}` {
		t.Fatalf("body = %q", body)
	}
	if srv.hits.Load() != 1 {
		t.Fatalf("hits=%d", srv.hits.Load())
	}
}

func TestFollows421ToHomeCore(t *testing.T) {
	t.Parallel()
	home := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		if r.URL.Path != "/api/v1/mirrors" || r.URL.RawQuery != "x=1" {
			t.Errorf("home core got %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type not carried: %q", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusOK)
	})
	wrong := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		misdirectTo(t, w, home.URL())
	})
	wrong.peers = []string{home.URL()}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, wrong.URL()+"/api/v1/mirrors?x=1", strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", bearerUser)
	req.Header.Set("Content-Type", "application/json")
	resp, err := followOnlyClient(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if wrong.hits.Load() != 1 || home.hits.Load() != 1 {
		t.Fatalf("wrong=%d home=%d, want 1/1", wrong.hits.Load(), home.hits.Load())
	}
	if got := home.auths.snapshot(); len(got) != 1 || got[0] != bearerUser {
		t.Fatalf("home core auth = %v, want the original bearer", got)
	}
	if got := resp.Request.URL.Host; got != strings.TrimPrefix(home.URL(), "http://") {
		t.Fatalf("resp.Request.URL.Host = %q, want the home core", got)
	}
	hop, ok := FollowedHop(resp)
	if !ok || hop.From != wrong.URL() || hop.To != home.URL() || hop.Jurisdiction != "eu" {
		t.Fatalf("FollowedHop = %+v, %v; want from %s to %s (eu)", hop, ok, wrong.URL(), home.URL())
	}
}

func TestFollowedHopAbsentWithoutRedirect(t *testing.T) {
	t.Parallel()
	srv := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		w.WriteHeader(http.StatusOK)
	})
	resp := do(t, followOnlyClient(t), http.MethodGet, srv.URL()+"/api/v1/me", "")
	if _, ok := FollowedHop(resp); ok {
		t.Fatal("FollowedHop must be false when no 421 was followed")
	}
	if _, ok := FollowedHop(nil); ok {
		t.Fatal("FollowedHop(nil) must be false")
	}
}

func TestBodyReplayedOnRetry(t *testing.T) {
	t.Parallel()
	const payload = `{"provider":"github","owner":"acme","repo":"widget"}`
	home := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test
		if string(body) != payload {
			t.Errorf("home body = %q", body)
		}
		if r.ContentLength != int64(len(payload)) {
			t.Errorf("ContentLength = %d", r.ContentLength)
		}
		w.WriteHeader(http.StatusOK)
	})
	wrong := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		misdirectTo(t, w, home.URL())
	})
	wrong.peers = []string{home.URL()}

	resp := do(t, followOnlyClient(t), http.MethodPost, wrong.URL()+"/api/v1/mirrors", payload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestRejects421OffFederation(t *testing.T) {
	t.Parallel()
	home := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		w.WriteHeader(http.StatusOK)
	})
	wrong := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		misdirectTo(t, w, home.URL())
	})
	// wrong.peers stays empty.

	var lines recorder
	rt := newTestTransport(t, Config{Logf: func(format string, args ...any) {
		lines.add(fmt.Sprintf(format, args...))
	}})
	resp := do(t, &http.Client{Transport: rt}, http.MethodGet, wrong.URL()+"/api/v1/mirrors", "")
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("got %d, want 421 passthrough", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body) //nolint:errcheck // test
	if !bytes.Contains(body, []byte("home_core_url")) {
		t.Errorf("original 421 body must survive: %q", body)
	}
	if home.hits.Load() != 0 {
		t.Fatalf("off-federation home core received the JWT (hits=%d)", home.hits.Load())
	}
	if got := lines.snapshot(); len(got) != 1 || !strings.Contains(got[0], "not followed") {
		t.Fatalf("Logf lines = %v, want one refusal", got)
	}
}

func TestRejects421WithoutHomeCoreURL(t *testing.T) {
	t.Parallel()
	wrong := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		w.WriteHeader(http.StatusMisdirectedRequest)
		writeBody(t, w, `{"error":"misdirected"}`)
	})

	resp := do(t, followOnlyClient(t), http.MethodGet, wrong.URL()+"/api/v1/mirrors", "")
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestRejectsInsecureHomeCoreUnlessAllowed(t *testing.T) {
	t.Parallel()
	home := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		w.WriteHeader(http.StatusOK)
	})
	wrong := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		misdirectTo(t, w, home.URL())
	})
	wrong.peers = []string{home.URL()}

	rt := newTestTransport(t, Config{})
	rt.allowInsecure = false
	resp := do(t, &http.Client{Transport: rt}, http.MethodGet, wrong.URL()+"/api/v1/mirrors", "")
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("got %d, want 421 passthrough for an http:// home core", resp.StatusCode)
	}
	if home.hits.Load() != 0 {
		t.Fatalf("http home core received the JWT (hits=%d)", home.hits.Load())
	}
}

func TestFederationManifestCachedPerOrigin(t *testing.T) {
	t.Parallel()
	home := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		w.WriteHeader(http.StatusOK)
	})
	manifestHits := atomic.Int32{}
	wrong := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == WellKnownPath {
			manifestHits.Add(1)
			writeFederation(t, w, []string{home.URL()})
			return
		}
		misdirectTo(t, w, home.URL())
	}))
	t.Cleanup(wrong.Close)

	client := followOnlyClient(t)
	for range 3 {
		resp := do(t, client, http.MethodGet, wrong.URL+"/api/v1/mirrors", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("got %d", resp.StatusCode)
		}
	}
	if manifestHits.Load() != 1 {
		t.Fatalf("manifest fetched %d times, want 1", manifestHits.Load())
	}
}

func TestNoInfiniteLoopOn421Chain(t *testing.T) {
	t.Parallel()
	var second *core
	first := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		misdirectTo(t, w, second.URL())
	})
	second = newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		// Loopback so the budget cap, not the trust gate, ends the chain.
		misdirectTo(t, w, "http://127.0.0.1:1")
	})
	first.peers = []string{second.URL()}
	second.peers = []string{"http://127.0.0.1:1"}

	resp := do(t, followOnlyClient(t), http.MethodGet, first.URL()+"/api/v1/mirrors", "")
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("got %d, want the second 421 passed through", resp.StatusCode)
	}
	if first.hits.Load() != 1 || second.hits.Load() != 1 {
		t.Fatalf("first=%d second=%d, want 1/1 (no third hop)", first.hits.Load(), second.hits.Load())
	}
}

func TestCallerRequestNotMutated(t *testing.T) {
	t.Parallel()
	home := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		w.WriteHeader(http.StatusOK)
	})
	wrong := newCore(t, func(c *core, w http.ResponseWriter, r *http.Request) {
		c.record(r)
		misdirectTo(t, w, home.URL())
	})
	wrong.peers = []string{home.URL()}

	rt := newTestTransport(t, Config{})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, wrong.URL()+"/api/v1/mirrors", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", bearerUser)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if req.URL.String() != wrong.URL()+"/api/v1/mirrors" {
		t.Errorf("caller's URL rewritten to %s", req.URL)
	}
}

func TestIsSafeOrigin(t *testing.T) {
	t.Parallel()
	parse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	strict := &Transport{}
	lenient := &Transport{allowInsecure: true}
	cases := []struct {
		raw             string
		strict, lenient bool
	}{
		{"https://core.example", true, true},
		{"https://", false, false},
		{"http://core.example", false, false},
		{"http://localhost:8080", false, true},
		{"http://127.0.0.1:1", false, true},
		{"http://[::1]:1", false, true},
		{"ftp://core.example", false, false},
	}
	for _, tc := range cases {
		if got := strict.isSafeOrigin(parse(tc.raw)); got != tc.strict {
			t.Errorf("strict %s = %v, want %v", tc.raw, got, tc.strict)
		}
		if got := lenient.isSafeOrigin(parse(tc.raw)); got != tc.lenient {
			t.Errorf("lenient %s = %v, want %v", tc.raw, got, tc.lenient)
		}
	}
}
