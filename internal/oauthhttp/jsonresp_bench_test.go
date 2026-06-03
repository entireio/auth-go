package oauthhttp

import (
	"errors"
	"strings"
	"testing"
)

// benchTokenResp mirrors what callers (sts, refresh, deviceflow) decode
// into — a flat OAuth token response.
type benchTokenResp struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	RefreshToken    string `json:"refresh_token"`
	Scope           string `json:"scope"`
}

// benchTokenBody is a realistic ~280-byte response with a JWT-shaped
// access token and an opaque refresh token.
const benchTokenBody = `{` +
	`"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJzdWIiOiJ1c2VyMTIzIiwiaXNzIjoiaHR0cHM6Ly9hcyIsImF1ZCI6ImNsaWVudCIsImV4cCI6MTcwMDAwMDAwMH0.sig",` +
	`"issued_token_type":"urn:ietf:params:oauth:token-type:access_token",` +
	`"token_type":"Bearer",` +
	`"expires_in":3600,` +
	`"refresh_token":"rt_abc123def456ghi789jkl",` +
	`"scope":"openid profile email"` +
	`}`

func BenchmarkReadAndDecodeJSON_TokenResponse(b *testing.B) {
	body := benchTokenBody
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		var out benchTokenResp
		if err := ReadAndDecodeJSON(strings.NewReader(body), &out, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadAndDecodeJSON_TokenResponseStrict(b *testing.B) {
	body := benchTokenBody
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		var out benchTokenResp
		if err := ReadAndDecodeJSON(strings.NewReader(body), &out, true); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadAndDecodeJSON_TokenResponseTrailingSpace(b *testing.B) {
	body := benchTokenBody + "    \n\t  "
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		var out benchTokenResp
		if err := ReadAndDecodeJSON(strings.NewReader(body), &out, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadAndDecodeJSON_HTMLResponse(b *testing.B) {
	body := `<!DOCTYPE html><html><body>Access denied by VPN</body></html>`
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		var out map[string]any
		if err := ReadAndDecodeJSON(strings.NewReader(body), &out, false); !errors.Is(err, ErrNonJSONResponse) {
			b.Fatalf("err=%v", err)
		}
	}
}

func BenchmarkReadAndDecodeJSON_LargeBody(b *testing.B) {
	// A 16KB JSON-shaped body with a single padding field. Models a
	// chatty AS or proxy that injects extra metadata — still well
	// under MaxResponseBytes.
	pad := strings.Repeat("x", 16*1024)
	body := `{"access_token":"x","token_type":"Bearer","expires_in":3600,"refresh_token":"y","scope":"openid","padding":"` + pad + `"}`
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		var out benchTokenResp
		if err := ReadAndDecodeJSON(strings.NewReader(body), &out, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLooksLikeHTML_JSON(b *testing.B) {
	body := []byte(benchTokenBody)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		if looksLikeHTML(body) {
			b.Fatal("false positive")
		}
	}
}

func BenchmarkLooksLikeHTML_HTML(b *testing.B) {
	body := []byte(`<!DOCTYPE html><html><body>Access denied by VPN</body></html>`)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		if !looksLikeHTML(body) {
			b.Fatal("false negative")
		}
	}
}

func BenchmarkLooksLikeHTML_LargeJSON(b *testing.B) {
	pad := strings.Repeat("x", 16*1024)
	body := []byte(`{"a":"` + pad + `"}`)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		if looksLikeHTML(body) {
			b.Fatal("false positive")
		}
	}
}
