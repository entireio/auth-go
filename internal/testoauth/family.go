package testoauth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// rotationEntry is a single step in a refresh-token rotation chain.
// consumedAt is zero while the entry is still active. successor is empty
// until the entry has been rotated.
type rotationEntry struct {
	refreshToken string
	consumedAt   time.Time
	successor    string
}

// Family is an opaque refresh-token family. Use read accessors for external
// observation; all mutations go through Registry.
type Family struct {
	id      string
	sub     string
	aud     []string
	revoked bool

	// chain holds all rotation entries, newest last. The last entry with a
	// zero consumedAt is the currently active RT. In a valid chain there is
	// at most one such entry.
	chain []rotationEntry
}

// ID returns the family's unique identifier.
func (f *Family) ID() string { return f.id }

// Subject returns the subject claim stored at seed time.
func (f *Family) Subject() string { return f.sub }

// Audience returns the audience stored at seed time.
func (f *Family) Audience() []string { return f.aud }

// Revoked reports whether the family has been revoked by reuse-detection.
func (f *Family) Revoked() bool { return f.revoked }

// CurrentRT returns the most recent active refresh token. This is the last
// entry in the chain whose consumedAt is zero. It is a convenience for tests;
// the caller should not cache the result across Consume calls.
func (f *Family) CurrentRT() string {
	for i := len(f.chain) - 1; i >= 0; i-- {
		if f.chain[i].consumedAt.IsZero() {
			return f.chain[i].refreshToken
		}
	}
	return ""
}

// Registry is a goroutine-safe registry of refresh-token families. A single
// mutex guards both the family/RT index maps and the mutable state of every
// Family within the registry, keeping contention simple for test workloads.
type Registry struct {
	mu  sync.Mutex
	fam map[string]*Family // keyed by family ID
	rts map[string]*Family // keyed by refresh token (consumed + active)

	// mintID and mintRT are the random-byte generators for family IDs and
	// refresh tokens respectively. They are var-typed so future tests can
	// swap them for deterministic output. Default to crypto/rand.
	mintID func() string
	mintRT func() string
}

// NewRegistry returns an initialised Registry backed by crypto/rand.
func NewRegistry() *Registry {
	return &Registry{
		fam:    make(map[string]*Family),
		rts:    make(map[string]*Family),
		mintID: func() string { return randBase64(16) },
		mintRT: func() string { return randBase64(32) },
	}
}

// randBase64 returns n random bytes encoded as RawURL base64. It panics on
// read failure, which is acceptable in test-only code.
func randBase64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("testoauth: crypto/rand read: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Seed creates a fresh family with an initial active refresh token. sub and
// aud are stored for use when the server later mints login JWTs from this
// family. It returns the Family pointer and the initial RT; the caller passes
// both to the client as the starting credentials.
func (r *Registry) Seed(sub string, aud []string) (*Family, string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fid := r.mintID()
	rt := r.mintRT()

	f := &Family{
		id:  fid,
		sub: sub,
		aud: aud,
		chain: []rotationEntry{
			{refreshToken: rt},
		},
	}
	r.fam[fid] = f
	r.rts[rt] = f
	return f, rt
}

// FamilyByID looks up a family by its ID.
func (r *Registry) FamilyByID(fid string) (*Family, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.fam[fid]
	return f, ok
}

// FamilyByRefreshToken looks up the family that owns rt. Both active and
// consumed tokens remain indexed so replays can be detected and correctly
// attributed to their (possibly revoked) family.
func (r *Registry) FamilyByRefreshToken(rt string) (*Family, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.rts[rt]
	return f, ok
}

// Consume runs the rotation state machine described in the package doc.
//
// For a known rt that belongs to a live, un-revoked family:
//   - If rt is the active (un-consumed) entry: consume it, mint a successor,
//     register the successor, return (successor, false, false).
//   - If rt was already consumed within idempotencyWindow of now: return the
//     already-issued successor idempotently as (successor, true, false).
//   - Otherwise (consumed outside the window, or no successor recorded):
//     revoke the family and return ("", true, true).
//
// A family that is already revoked returns ("", true, true) immediately.
// An rt that is not registered at all returns ("", true, true) without
// touching any family.
//
// now must be monotonically non-decreasing relative to Seed time.
func (r *Registry) Consume(rt string, now time.Time, idempotencyWindow time.Duration) (newRT string, replayed bool, revoked bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	f, ok := r.rts[rt]
	if !ok {
		// Unknown token — treat identically to a revoked family.
		return "", true, true
	}

	// Already revoked: nothing further to do.
	if f.revoked {
		return "", true, true
	}

	// Locate the entry for rt in the chain.
	for i := range f.chain {
		e := &f.chain[i]
		if e.refreshToken != rt {
			continue
		}

		// Active path: consumedAt is zero → this is the live entry.
		if e.consumedAt.IsZero() {
			successor := r.mintRT()
			e.consumedAt = now
			e.successor = successor
			f.chain = append(f.chain, rotationEntry{refreshToken: successor})
			r.rts[successor] = f
			return successor, false, false
		}

		// Consumed path: check the idempotency window.
		if idempotencyWindow > 0 && now.Sub(e.consumedAt) <= idempotencyWindow && e.successor != "" {
			return e.successor, true, false
		}

		// Outside the window (or no successor recorded): revoke and signal.
		f.revoked = true
		return "", true, true
	}

	// rt is in the index but not found in the chain — shouldn't happen in a
	// valid chain, but treat defensively as revoke-shaped.
	f.revoked = true
	return "", true, true
}
