package tokenstore

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/entireio/cli/auth/tokens"
	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

func TestKeyring_SaveLoad_RoundTrip(t *testing.T) {
	store := NewKeyring("test-roundtrip")

	want := tokens.TokenSet{
		AccessToken:  "access",
		RefreshToken: "refresh",
		TokenType:    "Bearer",
		ExpiresAt:    time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC),
		Scope:        "cli",
	}

	if err := store.SaveTokens("https://entire.io", want); err != nil {
		t.Fatalf("SaveTokens() error = %v", err)
	}

	got, err := store.LoadTokens("https://entire.io")
	if err != nil {
		t.Fatalf("LoadTokens() error = %v", err)
	}
	if got.AccessToken != want.AccessToken ||
		got.RefreshToken != want.RefreshToken ||
		got.TokenType != want.TokenType ||
		!got.ExpiresAt.Equal(want.ExpiresAt) ||
		got.Scope != want.Scope {
		t.Fatalf("LoadTokens() = %+v, want %+v", got, want)
	}
}

func TestKeyring_LoadTokens_NotFound(t *testing.T) {
	store := NewKeyring("test-not-found")

	_, err := store.LoadTokens("https://missing.example")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadTokens() error = %v, want ErrNotFound", err)
	}
}

func TestKeyring_SaveTokens_RejectsEmptyAccessToken(t *testing.T) {
	store := NewKeyring("test-empty")

	if err := store.SaveTokens("https://entire.io", tokens.TokenSet{}); err == nil {
		t.Fatal("SaveTokens() with empty access token should fail")
	}
	if err := store.SaveTokens("https://entire.io", tokens.TokenSet{AccessToken: "   "}); err == nil {
		t.Fatal("SaveTokens() with whitespace access token should fail")
	}
}

func TestKeyring_SaveTokens_TrimsAccessToken(t *testing.T) {
	store := NewKeyring("test-trim")

	if err := store.SaveTokens("https://entire.io", tokens.TokenSet{AccessToken: "  tok  "}); err != nil {
		t.Fatalf("SaveTokens() error = %v", err)
	}
	got, err := store.LoadTokens("https://entire.io")
	if err != nil {
		t.Fatalf("LoadTokens() error = %v", err)
	}
	if got.AccessToken != "tok" {
		t.Fatalf("AccessToken = %q, want %q", got.AccessToken, "tok")
	}
}

func TestKeyring_DeleteTokens(t *testing.T) {
	store := NewKeyring("test-delete")

	if err := store.SaveTokens("https://entire.io", tokens.TokenSet{AccessToken: "tok"}); err != nil {
		t.Fatalf("SaveTokens() error = %v", err)
	}
	if err := store.DeleteTokens("https://entire.io"); err != nil {
		t.Fatalf("DeleteTokens() error = %v", err)
	}
	if _, err := store.LoadTokens("https://entire.io"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadTokens() after delete error = %v, want ErrNotFound", err)
	}
}

func TestKeyring_DeleteTokens_MissingIsNoop(t *testing.T) {
	store := NewKeyring("test-delete-missing")

	if err := store.DeleteTokens("https://nonexistent.example"); err != nil {
		t.Fatalf("DeleteTokens() on missing entry error = %v", err)
	}
}

func TestKeyring_PreservesOtherProfiles(t *testing.T) {
	store := NewKeyring("test-preserve")

	if err := store.SaveTokens("a", tokens.TokenSet{AccessToken: "tok-a"}); err != nil {
		t.Fatalf("SaveTokens(a) error = %v", err)
	}
	if err := store.SaveTokens("b", tokens.TokenSet{AccessToken: "tok-b"}); err != nil {
		t.Fatalf("SaveTokens(b) error = %v", err)
	}

	a, err := store.LoadTokens("a")
	if err != nil || a.AccessToken != "tok-a" {
		t.Fatalf("LoadTokens(a) = %q (err %v), want tok-a", a.AccessToken, err)
	}
	b, err := store.LoadTokens("b")
	if err != nil || b.AccessToken != "tok-b" {
		t.Fatalf("LoadTokens(b) = %q (err %v), want tok-b", b.AccessToken, err)
	}
}

func TestKeyring_RoundTrip_NoExpiry(t *testing.T) {
	store := NewKeyring("test-no-expiry")

	if err := store.SaveTokens("p", tokens.TokenSet{AccessToken: "tok"}); err != nil {
		t.Fatalf("SaveTokens() error = %v", err)
	}
	got, err := store.LoadTokens("p")
	if err != nil {
		t.Fatalf("LoadTokens() error = %v", err)
	}
	if !got.ExpiresAt.IsZero() {
		t.Fatalf("ExpiresAt = %v, want zero", got.ExpiresAt)
	}
}

// TestKeyring_LoadTokens_MalformedJSONReturnsErrMalformed pins the
// contract that decode failures surface as ErrMalformed (wrapped), not
// ErrNotFound. Callers (e.g. cmd/entire/cli/auth.Store) use this to
// distinguish "no entry" from "entry exists but can't be parsed",
// which is the hook for the legacy bare-string upgrade fallback.
func TestKeyring_LoadTokens_MalformedJSONReturnsErrMalformed(t *testing.T) {
	const service = "test-malformed"
	const profile = "https://example.com"

	if err := keyring.Set(service, profile, "{not-valid-json"); err != nil {
		t.Fatalf("seed keyring: %v", err)
	}

	_, err := NewKeyring(service).LoadTokens(profile)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, must NOT be ErrNotFound (entry exists, just malformed)", err)
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed sentinel for callers to detect legacy entries", err)
	}
}

// TestKeyring_LoadTokens_BareStringReturnsErrMalformed is the contract
// the cmd-side legacy fallback depends on: a pre-shim raw access-token
// entry must surface as ErrMalformed so the shim knows to fall through
// to a bare-string read.
func TestKeyring_LoadTokens_BareStringReturnsErrMalformed(t *testing.T) {
	const service = "test-barestring"
	const profile = "https://example.com"

	if err := keyring.Set(service, profile, "ent_pre_shim_raw_token"); err != nil {
		t.Fatalf("seed keyring: %v", err)
	}

	_, err := NewKeyring(service).LoadTokens(profile)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

// TestKeyring_LoadTokens_BadExpiresAtReturnsErrMalformed covers the
// other branch in decodeTokenSet: well-formed JSON with a malformed
// expires_at also surfaces as ErrMalformed so the same fallback
// machinery applies.
func TestKeyring_LoadTokens_BadExpiresAtReturnsErrMalformed(t *testing.T) {
	const service = "test-bad-expires"
	const profile = "https://example.com"

	if err := keyring.Set(service, profile, `{"access_token":"a","expires_at":"not-a-date"}`); err != nil {
		t.Fatalf("seed keyring: %v", err)
	}

	_, err := NewKeyring(service).LoadTokens(profile)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

// TestKeyring_LoadTokens_EmptyAccessTokenReturnsErrMalformed pins the
// guard against well-formed JSON that decodes to a zero TokenSet. An
// unrelated CLI's blob keyed against the same service/profile, or a
// "{}" entry from a buggy save, would otherwise produce a TokenSet
// with empty AccessToken indistinguishable from a successful load —
// and the shim would then ship "Authorization: Bearer " on the wire.
func TestKeyring_LoadTokens_EmptyAccessTokenReturnsErrMalformed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty object", `{}`},
		{"unrelated fields only", `{"foo":"bar","count":3}`},
		{"explicit empty access_token", `{"access_token":""}`},
		{"whitespace access_token", `{"access_token":"   "}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service := "test-empty-" + tc.name
			const profile = "https://example.com"
			if err := keyring.Set(service, profile, tc.body); err != nil {
				t.Fatalf("seed keyring: %v", err)
			}
			_, err := NewKeyring(service).LoadTokens(profile)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}
