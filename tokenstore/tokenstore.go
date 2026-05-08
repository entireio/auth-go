// Package tokenstore is the persistence interface for tokens, plus
// the Keyring reference implementation.
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

// ErrMalformed is returned (wrapped) when a stored entry exists but
// can't be decoded into a TokenSet. Used by callers that want to treat
// a malformed entry as a legacy/upgrade path (e.g. pre-shim bare-string
// entries from older binaries) without confusing it with transport
// errors from the underlying keyring.
var ErrMalformed = errors.New("malformed token entry")

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
