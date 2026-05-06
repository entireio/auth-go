package tokenstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/entireio/cli/auth/tokens"
	"github.com/zalando/go-keyring"
)

// Keyring is a Store backed by the OS keyring.
//
// Each profile gets one entry under the configured Service name. The
// entry holds a JSON-encoded TokenSet so refresh tokens, expiry, and
// scope round-trip alongside the access token.
type Keyring struct {
	Service string
}

// NewKeyring returns a Keyring with the given service name. The service
// name namespaces entries in the OS keyring; pick something unique per
// CLI binary so two CLIs don't collide.
func NewKeyring(service string) *Keyring {
	return &Keyring{Service: service}
}

// SaveTokens marshals t to JSON and stores it under profile in the OS
// keyring. Empty access tokens are rejected.
func (k *Keyring) SaveTokens(profile string, t tokens.TokenSet) error {
	t.AccessToken = strings.TrimSpace(t.AccessToken)
	if t.AccessToken == "" {
		return errors.New("refusing to save TokenSet with empty access token")
	}

	encoded, err := encodeTokenSet(t)
	if err != nil {
		return err
	}

	if err := keyring.Set(k.Service, profile, encoded); err != nil {
		return fmt.Errorf("save tokens to keyring: %w", err)
	}
	return nil
}

// LoadTokens returns the TokenSet stored for profile. Returns
// ErrNotFound when the profile has nothing stored.
func (k *Keyring) LoadTokens(profile string) (tokens.TokenSet, error) {
	raw, err := keyring.Get(k.Service, profile)
	if errors.Is(err, keyring.ErrNotFound) {
		return tokens.TokenSet{}, ErrNotFound
	}
	if err != nil {
		return tokens.TokenSet{}, fmt.Errorf("load tokens from keyring: %w", err)
	}

	t, err := decodeTokenSet(raw)
	if err != nil {
		return tokens.TokenSet{}, err
	}
	return t, nil
}

// DeleteTokens removes the TokenSet for profile. A missing entry is a
// no-op.
func (k *Keyring) DeleteTokens(profile string) error {
	err := keyring.Delete(k.Service, profile)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("delete tokens from keyring: %w", err)
	}
	return nil
}

// keyringTokenSet is the on-keyring JSON shape. Time fields are
// serialised as RFC 3339 strings so the wire form survives keyring
// implementations that don't preserve byte-for-byte equality.
type keyringTokenSet struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func encodeTokenSet(t tokens.TokenSet) (string, error) {
	wire := keyringTokenSet{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		TokenType:    t.TokenType,
		Scope:        t.Scope,
	}
	if !t.ExpiresAt.IsZero() {
		wire.ExpiresAt = t.ExpiresAt.UTC().Format(time.RFC3339)
	}

	b, err := json.Marshal(wire)
	if err != nil {
		return "", fmt.Errorf("marshal TokenSet: %w", err)
	}
	return string(b), nil
}

func decodeTokenSet(raw string) (tokens.TokenSet, error) {
	var wire keyringTokenSet
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		return tokens.TokenSet{}, fmt.Errorf("unmarshal TokenSet: %w", err)
	}

	t := tokens.TokenSet{
		AccessToken:  wire.AccessToken,
		RefreshToken: wire.RefreshToken,
		TokenType:    wire.TokenType,
		Scope:        wire.Scope,
	}
	if wire.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, wire.ExpiresAt)
		if err != nil {
			return tokens.TokenSet{}, fmt.Errorf("parse expires_at: %w", err)
		}
		t.ExpiresAt = exp.UTC()
	}
	return t, nil
}
