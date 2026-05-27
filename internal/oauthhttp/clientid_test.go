package oauthhttp

import (
	"net/url"
	"strings"
	"testing"
)

func TestValidateClientID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		id      string
		wantErr string
	}{
		{"empty ok", "", ""},
		{"simple ok", "my-cli", ""},
		{"colon rejected", "a:b", "must not contain ':'"},
		{"space ok (VSCHAR)", "a b", ""},
		{"control char rejected", "a\x01b", "non-printable"},
		{"non-ascii rejected", "café", "non-printable"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateClientID(tc.id)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateClientID(%q) = %v, want nil", tc.id, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateClientID(%q) = %v, want substring %q", tc.id, err, tc.wantErr)
			}
		})
	}
}

func TestValidateClientIDConsistency(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		id      string
		extra   url.Values
		wantErr string
	}{
		{"nil extra ok", "id", nil, ""},
		{"matching ok", "id", url.Values{"client_id": {"id"}}, ""},
		{"disagree rejected", "id", url.Values{"client_id": {"other"}}, "disagree"},
		{"multi rejected", "", url.Values{"client_id": {"a", "b"}}, "at most one"},
		{"extra only ok", "", url.Values{"client_id": {"a"}}, ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateClientIDConsistency(tc.id, tc.extra)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("got %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}
