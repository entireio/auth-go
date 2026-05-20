package oauthhttp

import (
	"fmt"
	"net/url"
	"strings"
)

// IsLoopbackHost reports whether host is one of the loopback hostnames this
// library permits for explicit insecure-http local development.
func IsLoopbackHost(host string) bool {
	return strings.EqualFold(host, "localhost") || host == "127.0.0.1" || host == "::1"
}

// NormalizeOriginURL canonicalises an origin URL for equality comparisons.
// Scheme and host are lower-cased, default ports are stripped, and a trailing
// slash is collapsed away. On parse failure, or when raw is not an absolute
// URL, raw is returned unchanged so non-URL audience values still compare
// byte-for-byte.
func NormalizeOriginURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)

	hostname := strings.ToLower(u.Hostname())
	port := u.Port()
	dropPort := (u.Scheme == "http" && port == "80") ||
		(u.Scheme == "https" && port == "443") ||
		port == ""

	switch {
	case dropPort && strings.Contains(hostname, ":"):
		u.Host = "[" + hostname + "]"
	case dropPort:
		u.Host = hostname
	case strings.Contains(hostname, ":"):
		u.Host = "[" + hostname + "]:" + port
	default:
		u.Host = hostname + ":" + port
	}

	u.Path = strings.TrimRight(u.Path, "/")
	return u.String()
}

// ValidateOriginURL validates that raw is an origin URL. HTTPS is required
// unless allowInsecureHTTP is true and the host is loopback. The returned value
// is normalised with NormalizeOriginURL.
func ValidateOriginURL(raw string, allowInsecureHTTP bool, field string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("%s must be an absolute URL with scheme and host, got %q", field, raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("%s must not include userinfo", field)
	}
	switch u.Scheme {
	case "https":
		// fine
	case "http":
		if !allowInsecureHTTP {
			return "", fmt.Errorf("%s must use https", field)
		}
		if !IsLoopbackHost(u.Hostname()) {
			return "", fmt.Errorf("%s http only permitted on loopback hosts", field)
		}
	default:
		return "", fmt.Errorf("%s scheme %q is not supported", field, u.Scheme)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%s must be an origin URL without query or fragment", field)
	}
	if strings.Trim(u.Path, "/") != "" {
		return "", fmt.Errorf("%s must be an origin URL without a path", field)
	}
	return NormalizeOriginURL(raw), nil
}
