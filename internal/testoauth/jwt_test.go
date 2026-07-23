package testoauth_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/entireio/auth-go/internal/testoauth"
	"github.com/entireio/auth-go/tokens"
)

func TestMintUnsignedJWT_RoundTripsThroughParseClaims(t *testing.T) {
	t.Parallel()

	want := testoauth.Claims{
		Issuer:    "https://auth.example.com",
		Subject:   "user-123",
		Audience:  []string{"https://auth.example.com", "https://api.example.com"},
		FamilyID:  "fid-abc",
		IssuedAt:  time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
		NotBefore: time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 5, 28, 20, 0, 0, 0, time.UTC),
		Extra:     map[string]any{"handle": "alex@example.com"},
	}

	jwt := testoauth.MintUnsignedJWT(want)

	got, err := tokens.ParseClaims(jwt)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if got.Issuer != want.Issuer {
		t.Errorf("Issuer = %q, want %q", got.Issuer, want.Issuer)
	}
	if got.Subject != want.Subject {
		t.Errorf("Subject = %q, want %q", got.Subject, want.Subject)
	}
	if !reflect.DeepEqual(got.Audience, want.Audience) {
		t.Errorf("Audience = %v, want %v", got.Audience, want.Audience)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, want.ExpiresAt)
	}
	if !got.NotBefore.Equal(want.NotBefore) {
		t.Errorf("NotBefore = %v, want %v", got.NotBefore, want.NotBefore)
	}
	if !got.IssuedAt.Equal(want.IssuedAt) {
		t.Errorf("IssuedAt = %v, want %v", got.IssuedAt, want.IssuedAt)
	}
	// Handle comes through the `handle` extra claim, mirroring production.
	if got.Handle != "alex@example.com" {
		t.Errorf("Handle = %q, want alex@example.com", got.Handle)
	}
}

func TestMintUnsignedJWT_SingleAudienceUsesArray(t *testing.T) {
	t.Parallel()
	jwt := testoauth.MintUnsignedJWT(testoauth.Claims{
		Issuer:    "https://x",
		Audience:  []string{"https://api"},
		ExpiresAt: time.Now().Add(time.Hour),
	})
	got, err := tokens.ParseClaims(jwt)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if len(got.Audience) != 1 || got.Audience[0] != "https://api" {
		t.Fatalf("Audience = %v, want [https://api]", got.Audience)
	}
}

func TestMintUnsignedJWT_OmittedTimesEncodeAsZeroAndParseAsZero(t *testing.T) {
	t.Parallel()
	jwt := testoauth.MintUnsignedJWT(testoauth.Claims{Issuer: "https://x"})
	got, err := tokens.ParseClaims(jwt)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if !got.ExpiresAt.IsZero() || !got.NotBefore.IsZero() || !got.IssuedAt.IsZero() {
		t.Fatalf("expected zero times, got exp=%v nbf=%v iat=%v", got.ExpiresAt, got.NotBefore, got.IssuedAt)
	}
}

func TestMintUnsignedJWT_RejectedByAlgNoneCheck(t *testing.T) {
	// Sanity: the helper must NOT use alg:none, since ParseClaims refuses it.
	// We don't test the helper directly here — we just confirm a minted JWT
	// is acceptable to ParseClaims (covered by the round-trip test). This
	// test is a guard against a future change that swaps in alg:none.
	t.Parallel()
	jwt := testoauth.MintUnsignedJWT(testoauth.Claims{Issuer: "https://x", ExpiresAt: time.Now().Add(time.Hour)})
	if _, err := tokens.ParseClaims(jwt); err != nil {
		t.Fatalf("ParseClaims rejected helper-minted JWT: %v — helper must not use alg:none", err)
	}
}
