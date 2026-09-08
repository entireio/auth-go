package testoauth_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entireio/auth-go/internal/testoauth"
)

func TestRegistry_SeedRegistersFamilyAndRT(t *testing.T) {
	t.Parallel()
	r := testoauth.NewRegistry()
	f, rt := r.Seed("user-1", []string{"https://api.example.com"})
	if f.ID() == "" || rt == "" {
		t.Fatalf("Seed returned empty fields: id=%q rt=%q", f.ID(), rt)
	}
	if got, ok := r.FamilyByID(f.ID()); !ok || got != f {
		t.Errorf("FamilyByID(%q) = (%v, %v), want (%v, true)", f.ID(), got, ok, f)
	}
	if got, ok := r.FamilyByRefreshToken(rt); !ok || got != f {
		t.Errorf("FamilyByRefreshToken(%q) = (%v, %v), want (%v, true)", rt, got, ok, f)
	}
	if got := f.CurrentRT(); got != rt {
		t.Errorf("CurrentRT() = %q, want %q (the seeded RT)", got, rt)
	}
	if f.Subject() != "user-1" {
		t.Errorf("Subject() = %q, want user-1", f.Subject())
	}
	if got := f.Audience(); len(got) != 1 || got[0] != "https://api.example.com" {
		t.Errorf("Audience() = %v", got)
	}
	if f.Revoked() {
		t.Error("freshly seeded family is revoked")
	}
}

func TestRegistry_SeedYieldsUniqueIDsAndRTs(t *testing.T) {
	t.Parallel()
	r := testoauth.NewRegistry()
	seen := map[string]bool{}
	for range 64 {
		f, rt := r.Seed("u", nil)
		if seen[f.ID()] {
			t.Fatalf("duplicate family id: %q", f.ID())
		}
		if seen[rt] {
			t.Fatalf("duplicate refresh token: %q", rt)
		}
		seen[f.ID()] = true
		seen[rt] = true
	}
}

func TestRegistry_ConsumeActiveRotates(t *testing.T) {
	t.Parallel()
	r := testoauth.NewRegistry()
	f, rt := r.Seed("u", nil)
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

	newRT, replayed, revoked := r.Consume(rt, now, 0)
	if replayed || revoked {
		t.Fatalf("active consume reported replayed=%v revoked=%v, want false/false", replayed, revoked)
	}
	if newRT == "" || newRT == rt {
		t.Fatalf("newRT = %q (old=%q), want a non-empty rotated token", newRT, rt)
	}
	if got := f.CurrentRT(); got != newRT {
		t.Fatalf("CurrentRT = %q, want successor %q", got, newRT)
	}
	if fbyRT, ok := r.FamilyByRefreshToken(newRT); !ok || fbyRT != f {
		t.Fatalf("successor RT not indexed: ok=%v", ok)
	}
	// The original RT must still resolve to the same family (so a replay
	// is detectable, not "unknown").
	if fbyOld, ok := r.FamilyByRefreshToken(rt); !ok || fbyOld != f {
		t.Fatalf("consumed RT delisted: ok=%v", ok)
	}
}

func TestRegistry_ConsumeUnknownRTIsRevokeShaped(t *testing.T) {
	t.Parallel()
	r := testoauth.NewRegistry()
	_, _ = r.Seed("u", nil)
	_, replayed, revoked := r.Consume("not-a-real-rt", time.Now(), time.Second)
	if !replayed || !revoked {
		t.Fatalf("unknown RT: replayed=%v revoked=%v, want true/true", replayed, revoked)
	}
}

func TestRegistry_ConsumeRevokedFamilyStaysRevoked(t *testing.T) {
	t.Parallel()
	r := testoauth.NewRegistry()
	f, rt := r.Seed("u", nil)
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

	rt2, _, _ := r.Consume(rt, now, 0)
	// Replay the consumed rt outside the window → revoke.
	_, _, revoked := r.Consume(rt, now.Add(time.Second), 0)
	if !revoked {
		t.Fatalf("replay should have revoked family")
	}
	if !f.Revoked() {
		t.Fatalf("family.Revoked() = false after revoke")
	}
	// Subsequent Consume of any RT (including the still-active rt2) →
	// revoked branch.
	_, replayed2, revoked2 := r.Consume(rt2, now.Add(2*time.Second), 0)
	if !replayed2 || !revoked2 {
		t.Fatalf("consume on revoked family: replayed=%v revoked=%v, want true/true", replayed2, revoked2)
	}
}

func TestRegistry_IdempotentReplayWithinWindow(t *testing.T) {
	t.Parallel()
	r := testoauth.NewRegistry()
	_, rt := r.Seed("u", nil)
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

	successor, replayed1, revoked1 := r.Consume(rt, now, 200*time.Millisecond)
	if replayed1 || revoked1 {
		t.Fatalf("first consume: replayed=%v revoked=%v", replayed1, revoked1)
	}
	// Replay 50ms later within the window — should return the same successor
	// idempotently and NOT revoke.
	got, replayed2, revoked2 := r.Consume(rt, now.Add(50*time.Millisecond), 200*time.Millisecond)
	if !replayed2 {
		t.Errorf("replayed = false, want true on idempotent replay")
	}
	if revoked2 {
		t.Errorf("revoked = true within idempotency window")
	}
	if got != successor {
		t.Errorf("idempotent replay returned %q, want successor %q", got, successor)
	}
}

func TestRegistry_ReplayOutsideWindowRevokes(t *testing.T) {
	t.Parallel()
	r := testoauth.NewRegistry()
	_, rt := r.Seed("u", nil)
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

	_, _, _ = r.Consume(rt, now, 100*time.Millisecond)
	got, replayed, revoked := r.Consume(rt, now.Add(500*time.Millisecond), 100*time.Millisecond)
	if got != "" {
		t.Errorf("revoked replay returned %q, want empty", got)
	}
	if !replayed || !revoked {
		t.Errorf("replayed=%v revoked=%v, want true/true", replayed, revoked)
	}
}

func TestRegistry_ConcurrentConsumeOfSameActiveRTYieldsOneRotation(t *testing.T) {
	t.Parallel()
	r := testoauth.NewRegistry()
	_, rt := r.Seed("u", nil)
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	window := time.Hour // generous window so concurrent winners → idempotent replays, not revoke

	const n = 16
	var (
		wg          sync.WaitGroup
		ready       sync.WaitGroup
		start       = make(chan struct{})
		successors  sync.Map // rt → struct{}
		rotateCount atomic.Int32
	)
	ready.Add(n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-start
			out, replayed, revoked := r.Consume(rt, now, window)
			if revoked {
				t.Errorf("unexpected revoke under concurrent consume of active rt")
				return
			}
			if out == "" {
				t.Errorf("consume returned empty rt")
				return
			}
			successors.Store(out, struct{}{})
			if !replayed {
				rotateCount.Add(1)
			}
		}()
	}
	ready.Wait()
	close(start)
	wg.Wait()

	// Exactly one goroutine should have rotated (replayed=false). The
	// rest should have received the same successor idempotently.
	if got := rotateCount.Load(); got != 1 {
		t.Fatalf("rotateCount = %d, want exactly 1 under concurrent active consume", got)
	}
	// successors should be a singleton set — every goroutine got the same
	// successor.
	count := 0
	successors.Range(func(_, _ any) bool { count++; return true })
	if count != 1 {
		t.Fatalf("distinct successors observed = %d, want 1", count)
	}
}
