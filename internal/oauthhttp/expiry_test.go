package oauthhttp

import (
	"testing"
	"time"
)

func TestExpiresInDuration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		secs int
		want time.Duration
	}{
		{"normal hour", 3600, time.Hour},
		{"zero", 0, 0},
		{"at ceiling", MaxExpiresInSeconds, time.Duration(MaxExpiresInSeconds) * time.Second},
		{"just above ceiling clamped", MaxExpiresInSeconds + 1, time.Duration(MaxExpiresInSeconds) * time.Second},
		{"overflow-range value clamped", 9_300_000_000, time.Duration(MaxExpiresInSeconds) * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ExpiresInDuration(tc.secs)
			if got != tc.want {
				t.Fatalf("ExpiresInDuration(%d) = %v, want %v", tc.secs, got, tc.want)
			}
			if got < 0 {
				t.Fatalf("ExpiresInDuration(%d) = %v, must never be negative", tc.secs, got)
			}
		})
	}
}
