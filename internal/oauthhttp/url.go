package oauthhttp

import (
	"errors"
	"fmt"
	"net/url"
)

// ErrInsecureBaseURL is returned by ResolveURL when handed an
// http:// BaseURL without allowInsecureHTTP set. OAuth flows ship
// the user's bearer (subject_token, refresh_token, access_token) on
// the wire — over plain HTTP that's a credential in the clear.
// Public packages re-export this sentinel so callers can errors.Is
// on the familiar deviceflow.ErrInsecureBaseURL / sts.ErrInsecureBaseURL.
var ErrInsecureBaseURL = errors.New("refusing to perform OAuth request over plain HTTP (set AllowInsecureHTTP only for local dev / test)")

// ErrAbsolutePath is returned by ResolveURL when the path is an
// absolute or scheme-relative URL rather than a path relative to
// BaseURL. Go's url.ResolveReference replaces BaseURL's host when
// handed an absolute reference, so accepting an absolute path
// would let any caller who can influence the configuration (env
// var, config file, server-discovery doc) redirect the request to
// an attacker — and capture whatever bearer the request carries.
var ErrAbsolutePath = errors.New("path must be a relative URL, not absolute")

// ResolveURL joins baseURL and path the way the OAuth flows want:
//
//   - baseURL must parse, must have scheme http or https.
//   - If scheme is http, allowInsecureHTTP must be true (otherwise
//     ErrInsecureBaseURL).
//   - path must parse and must be relative — neither absolute
//     (e.g. "https://other") nor scheme-relative (e.g.
//     "//other/path") references are accepted (otherwise
//     ErrAbsolutePath). Without this guard, a caller controlling
//     path could redirect the user's bearer to an attacker.
func ResolveURL(baseURL, path string, allowInsecureHTTP bool) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base URL: %w", err)
	}
	if base.Host == "" {
		return "", errors.New("base URL must include a host")
	}
	switch base.Scheme {
	case "https":
		// fine
	case "http":
		if !allowInsecureHTTP {
			return "", ErrInsecureBaseURL
		}
		if !IsLoopbackHost(base.Hostname()) {
			return "", fmt.Errorf("%w: http only permitted on loopback hosts", ErrInsecureBaseURL)
		}
	default:
		return "", fmt.Errorf("unsupported base URL scheme %q (must be http or https)", base.Scheme)
	}
	rel, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("parse path: %w", err)
	}
	// Reject both scheme-relative (e.g. "//host/path") and absolute
	// references — both override BaseURL's host via url.ResolveReference.
	if rel.IsAbs() || rel.Host != "" {
		return "", fmt.Errorf("%w: got %q", ErrAbsolutePath, path)
	}
	return base.ResolveReference(rel).String(), nil
}
