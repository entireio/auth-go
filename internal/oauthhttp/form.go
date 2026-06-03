package oauthhttp

import (
	"net/url"
	"strings"
)

// EncodeForm renders values as an application/x-www-form-urlencoded
// body. Drop-in replacement for (url.Values).Encode() with two
// deliberate differences:
//
//   - No key sort. OAuth token endpoints parse the form into a map; key
//     order is not observable on the wire. Skipping the sort avoids the
//     [...]string keys allocation and the sort.Strings call on every
//     request.
//   - Single strings.Builder with pre-sized capacity. Stdlib's Encode
//     grows incrementally; we estimate the final size up front so the
//     builder takes one allocation rather than a geometric series.
//
// Values still go through url.QueryEscape (RFC 3986). Encoding is byte-
// for-byte equivalent to (url.Values).Encode() modulo key order — every
// spec-compliant server parses both identically.
func EncodeForm(values url.Values) string {
	if len(values) == 0 {
		return ""
	}

	// Capacity estimate: sum of len(k)+len(v)+2 (=&) per pair, no
	// percent-escape inflation accounted for. Tokens are base64url so
	// most values stay unescaped; the estimate is tight in practice and
	// a slight under-estimate only triggers one Builder grow.
	size := 0
	for k, vs := range values {
		for _, v := range vs {
			size += len(k) + len(v) + 2
		}
	}

	var sb strings.Builder
	sb.Grow(size)
	first := true
	for k, vs := range values {
		ek := url.QueryEscape(k)
		for _, v := range vs {
			if !first {
				sb.WriteByte('&')
			}
			first = false
			sb.WriteString(ek)
			sb.WriteByte('=')
			sb.WriteString(url.QueryEscape(v))
		}
	}
	return sb.String()
}
