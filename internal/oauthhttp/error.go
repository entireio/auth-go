package oauthhttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// OAuthErrorResponse is the standard OAuth error response shape used by
// RFC 6749-family endpoints.
type OAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// ReadOAuthError reads a non-success OAuth response body and returns the
// parsed OAuth error object when the server sent one. If the body is not an
// OAuth JSON error, the returned error contains a bounded, sanitised fallback
// message suitable for logs and terminals.
func ReadOAuthError(resp *http.Response) (*OAuthErrorResponse, error) {
	body, err := readLimitedBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("status %d: %w", resp.StatusCode, err)
	}

	var apiErr OAuthErrorResponse
	if err := json.Unmarshal(bytes.TrimSpace(body), &apiErr); err == nil && strings.TrimSpace(apiErr.Error) != "" {
		return &apiErr, nil
	}

	text := SanitizeDescription(string(body))
	if text != "" {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, text)
	}
	return nil, fmt.Errorf("status %d", resp.StatusCode)
}

func readLimitedBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, MaxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxResponseBytes {
		return nil, ErrResponseTooLarge
	}
	return body, nil
}
