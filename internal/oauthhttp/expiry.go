package oauthhttp

import "time"

// MaxExpiresInSeconds caps a server-provided OAuth expires_in (seconds)
// before it is multiplied into a time.Duration. Without a ceiling, a value
// above ~9.2e9 overflows time.Duration's int64 nanosecond range, wrapping
// the derived expiry into the past so a freshly-issued token looks
// already-expired. 100 years is far beyond any real token lifetime and
// safely below the overflow threshold.
const MaxExpiresInSeconds = 100 * 365 * 24 * 60 * 60

// ExpiresInDuration converts a server-provided expires_in (seconds) into a
// time.Duration, clamping at MaxExpiresInSeconds to avoid int64 overflow.
// Callers still gate on expires_in > 0 where a non-positive value is
// invalid; this helper only defends the upper bound.
func ExpiresInDuration(secs int) time.Duration {
	if secs > MaxExpiresInSeconds {
		secs = MaxExpiresInSeconds
	}
	return time.Duration(secs) * time.Second
}
