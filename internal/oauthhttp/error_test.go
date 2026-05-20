package oauthhttp

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReadOAuthError_OversizedBody(t *testing.T) {
	t.Parallel()
	resp := &http.Response{
		StatusCode: http.StatusBadGateway,
		Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", MaxResponseBytes+1))),
	}

	_, err := ReadOAuthError(resp)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
}

func TestReadOAuthError_EmptyErrorFallsBackToSanitizedText(t *testing.T) {
	t.Parallel()
	resp := &http.Response{
		StatusCode: http.StatusBadRequest,
		Body:       io.NopCloser(strings.NewReader("{\"error\":\"\",\"error_description\":\"bad\u001b[31m news\"}")),
	}

	apiErr, err := ReadOAuthError(resp)
	if apiErr != nil {
		t.Fatalf("apiErr = %+v, want nil", apiErr)
	}
	if err == nil || !strings.Contains(err.Error(), "bad[31m news") {
		t.Fatalf("err = %v, want sanitized fallback text", err)
	}
	if strings.ContainsRune(err.Error(), '\u001b') {
		t.Fatalf("err = %q, contains unsanitized escape", err.Error())
	}
}
