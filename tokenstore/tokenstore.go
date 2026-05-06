// Package tokenstore is the persistence interface for tokens, plus
// reference implementations.
//
// Callers pick a Store at startup. Two impls ship with this package:
//
//   - Keyring stores one entry per profile in the OS keyring. Suitable
//     for interactive single-user CLIs.
//   - File stores entries in a JSON file on disk, with refresh tokens
//     in the OS keyring. Suitable for CLIs that need to persist
//     additional per-profile metadata (e.g. context bindings).
//
// Profile is whatever string the caller wants to key by — typically a
// base URL, a kubectl-style context name, or a principal handle.
package tokenstore

import (
	"errors"

	"github.com/entireio/cli/auth/tokens"
)

// ErrNotFound is returned when a profile has no stored tokens. Callers
// distinguish "not logged in" from genuine errors with errors.Is.
var ErrNotFound = errors.New("token not found")

// Store persists token bundles keyed by an opaque profile string.
//
// Implementations must:
//   - Return ErrNotFound (not a zero value, no error) when LoadTokens
//     is called for an unknown profile.
//   - Treat DeleteTokens of a missing profile as a no-op.
//   - Not write empty access tokens; SaveTokens should reject them.
type Store interface {
	SaveTokens(profile string, t tokens.TokenSet) error
	LoadTokens(profile string) (tokens.TokenSet, error)
	DeleteTokens(profile string) error
}
