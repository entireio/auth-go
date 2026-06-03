package oauthhttp

import (
	"net/url"
	"sort"
	"strings"
	"testing"
)

func TestEncodeForm_EmptyIsEmpty(t *testing.T) {
	t.Parallel()
	if got := EncodeForm(nil); got != "" {
		t.Fatalf("EncodeForm(nil) = %q, want \"\"", got)
	}
	if got := EncodeForm(url.Values{}); got != "" {
		t.Fatalf("EncodeForm({}) = %q, want \"\"", got)
	}
}

// TestEncodeForm_MatchesStdlibAfterSort pins the wire-equivalence
// invariant: our output equals stdlib's once both are key-sorted. Any
// drift in escaping (RFC 3986 percent-encoding) would surface here.
func TestEncodeForm_MatchesStdlibAfterSort(t *testing.T) {
	t.Parallel()

	cases := []url.Values{
		{"grant_type": []string{"refresh_token"}, "refresh_token": []string{"rt.abc/def+ghi="}},
		{"key with space": []string{"value/with+special&chars=here"}},
		{"a": []string{"1", "2", "3"}, "b": []string{"x"}}, // multi-value
		{"unicode": []string{"héllo wörld"}},
		{"empty_val": []string{""}},
	}
	for _, in := range cases {
		got := sortedPairs(EncodeForm(in))
		want := sortedPairs(in.Encode())
		if got != want {
			t.Fatalf("EncodeForm vs stdlib differ:\n  got=%q\n want=%q", got, want)
		}
	}
}

// sortedPairs normalises an encoded form into a stable string by
// sorting on '&' boundaries — lets us compare against stdlib's sorted
// output without depending on map iteration order.
func sortedPairs(s string) string {
	if s == "" {
		return ""
	}
	pairs := strings.Split(s, "&")
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}
