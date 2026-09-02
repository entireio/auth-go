package crossjuris

// This file is the RFC 8693 exchange branch: everything the Transport
// does on a 401. It exists for home cores that cannot yet verify a
// sibling region's login JWT. Once every region accepts those JWTs on
// /api/v1 the branch is dead code and this file goes away, along with
// Config.ClientID, Transport.tokens and the 401 arm in send. The
// sunset signal is validated_total{kind="foreign_jurisdiction"} in
// entire-core reaching zero.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/entireio/auth-go/sts"
)

// errorCodeCrossJurisTokenRequired is the `error` value entire-core's
// auth middleware emits when it recognises a sibling-audience JWT.
const errorCodeCrossJurisTokenRequired = "cross_juris_token_required"

// cachedTokenTTL caps how long an exchanged token stays in the per-origin
// cache. Slightly shorter than the server-side foreign-session lifetime
// (5m) so the Transport never presents a token seconds from expiry.
const cachedTokenTTL = 4 * time.Minute

// tokenExpiryBuffer is subtracted from a server-advertised lifetime for
// the same reason cachedTokenTTL sits below the server's 5m.
const tokenExpiryBuffer = 1 * time.Minute

// unauthorizedHint is the structured 401 envelope.
type unauthorizedHint struct {
	Error            string `json:"error"`
	TokenExchangeURL string `json:"token_exchange_url"`
	Audience         string `json:"audience"`
}

type cachedExchangedToken struct {
	token string
	exp   time.Time
}

// recoverUnauthorized handles a 401 in one of two shapes:
//
//   - the structured hint {"error":"cross_juris_token_required",
//     "token_exchange_url":"...","audience":"..."} from a core that can
//     verify the JWT's signature but sees a sibling audience;
//   - a BARE 401 on a hop reached by following a 421. The home core
//     cannot verify a foreign-region login JWT's signature (its verifier
//     trusts only local JWKS), so it never reaches the audience check and
//     emits no hint. The origin was already vetted against the responding
//     core's federation manifest, so the hint is synthesised: its
//     /oauth/token is same-origin and its audience is its own base URL.
//
// In both cases the Transport exchanges the ORIGINAL login JWT at the
// hint's token endpoint, caches the result by origin, and retries once
// with it. Any failure surfaces the original 401 unchanged so the caller
// sees the server's bytes and the JWT never leaves the trusted origin.
func (t *Transport) recoverUnauthorized(req *http.Request, resp *http.Response, body []byte, originalAuth, origin string, budget hop) (*http.Response, error) {
	if budget.triedExchange[origin] {
		return resp, nil
	}
	hint, ok, err := readUnauthorizedHint(resp)
	if err != nil {
		t.debugf("read 401 body from %s: %v", origin, err)
		return resp, nil
	}
	if !ok {
		if !budget.afterRedirect {
			// A bare 401 on a non-redirected hop is a genuine auth failure.
			return resp, nil
		}
		hint = unauthorizedHint{
			Error:            errorCodeCrossJurisTokenRequired,
			TokenExchangeURL: origin + TokenPath,
			Audience:         origin,
		}
	}
	if err := t.validateExchangeURL(hint.TokenExchangeURL, req.URL); err != nil {
		t.debugf("401 from %s: rejecting token_exchange_url: %v", origin, err)
		return resp, nil
	}
	// Exchange the caller's original bearer, never a previously exchanged
	// one: an exchanged token already carries foreign_iss and the server
	// rejects chained cross-juris hops.
	subject, found := strings.CutPrefix(originalAuth, "Bearer ")
	if !found || subject == "" {
		return resp, nil
	}
	exchanged, ttl, err := t.exchange(req.Context(), hint, subject)
	if err != nil {
		t.debugf("401 from %s: exchange failed: %v", origin, err)
		return resp, nil
	}
	t.debugf("401 from %s: exchanged login JWT, retrying", origin)
	t.storeToken(origin, exchanged, ttl)
	budget.triedExchange[origin] = true
	_ = resp.Body.Close()
	return t.send(req, body, originalAuth, budget)
}

// readUnauthorizedHint decodes the structured 401 envelope. ok is false
// when the body is not that shape (a plain 401, an HTML proxy page); the
// body is restored either way so the caller can pass resp through.
func readUnauthorizedHint(resp *http.Response) (unauthorizedHint, bool, error) {
	raw, err := drainAndRestoreBody(resp, maxUnauthorizedBody)
	if err != nil {
		return unauthorizedHint{}, false, fmt.Errorf("read 401 body: %w", err)
	}
	var hint unauthorizedHint
	if err := json.Unmarshal(raw, &hint); err != nil {
		return unauthorizedHint{}, false, nil //nolint:nilerr // not our envelope shape, not an error
	}
	if hint.Error != errorCodeCrossJurisTokenRequired || hint.TokenExchangeURL == "" {
		return unauthorizedHint{}, false, nil
	}
	return hint, true, nil
}

// validateExchangeURL gates where the Transport will POST the user's
// login JWT. The URL must be a safe origin, same-host with the request
// that drew the 401 (a core's /oauth/token lives beside its middleware;
// an off-origin hint has no legitimate use), and its path must be
// exactly TokenPath.
func (t *Transport) validateExchangeURL(raw string, requestURL *url.URL) error {
	if raw == "" {
		return errors.New("token_exchange_url missing")
	}
	exchange, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse token_exchange_url: %w", err)
	}
	if !t.isSafeOrigin(exchange) {
		return fmt.Errorf("token_exchange_url %q is not https (or permitted http loopback)", raw)
	}
	if requestURL == nil || requestURL.Host == "" {
		return errors.New("cannot determine response origin for same-origin check")
	}
	if exchange.Host != requestURL.Host {
		return fmt.Errorf("token_exchange_url host %q must match response host %q", exchange.Host, requestURL.Host)
	}
	if exchange.Path != TokenPath {
		return fmt.Errorf("token_exchange_url path %q must be %q", exchange.Path, TokenPath)
	}
	return nil
}

// exchange runs the RFC 8693 exchange at the hint's origin and returns
// the issued access token with the cache TTL it earns. The request goes
// through the base transport so it never re-enters the retry logic.
func (t *Transport) exchange(ctx context.Context, hint unauthorizedHint, subject string) (string, time.Duration, error) {
	client := &sts.Client{
		Transport:         t.base,
		BaseURL:           strings.TrimSuffix(hint.TokenExchangeURL, TokenPath),
		Path:              TokenPath,
		AllowInsecureHTTP: t.allowInsecure,
	}
	ts, err := client.Exchange(ctx, sts.ExchangeRequest{
		SubjectToken:       subject,
		SubjectTokenType:   sts.SubjectTokenTypeJWT,
		RequestedTokenType: sts.SubjectTokenTypeAccessToken,
		Audience:           hint.Audience,
		ClientID:           t.clientID,
	})
	if err != nil {
		return "", 0, err //nolint:wrapcheck // sts already prefixes "token exchange:"
	}
	return ts.AccessToken, cacheTTL(time.Until(ts.ExpiresAt)), nil
}

// cacheTTL derives how long an exchanged token may live in the cache
// from its remaining lifetime: minus tokenExpiryBuffer, capped at
// cachedTokenTTL. A lifetime under the buffer yields <= 0 and is not
// cached (the triggering request still succeeds via the live retry).
func cacheTTL(remaining time.Duration) time.Duration {
	return min(remaining-tokenExpiryBuffer, cachedTokenTTL)
}

func (t *Transport) lookupToken(origin string) (string, bool) {
	v, ok := t.tokens.Load(origin)
	if !ok {
		return "", false
	}
	cached, _ := v.(cachedExchangedToken) //nolint:errcheck // type assertion, not error
	if time.Now().After(cached.exp) {
		t.tokens.Delete(origin)
		return "", false
	}
	return cached.token, true
}

func (t *Transport) storeToken(origin, token string, ttl time.Duration) {
	if origin == "" || token == "" || ttl <= 0 {
		return
	}
	t.tokens.Store(origin, cachedExchangedToken{token: token, exp: time.Now().Add(ttl)})
}
