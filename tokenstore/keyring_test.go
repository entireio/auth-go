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
