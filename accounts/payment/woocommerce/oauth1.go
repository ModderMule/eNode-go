package woocommerce

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// WooCommerce accepts HTTP Basic auth only over HTTPS. Over plain HTTP — a local
// test shop — it requires one-legged OAuth 1.0a: the consumer key and a signature
// in the query string, no token. This is its variant exactly as
// WC_REST_Authentication::check_oauth_signature computes it, which differs from RFC
// 5849 in one place: the normalized parameters are percent-encoded once and joined
// with pre-encoded "%3D" and "%26", rather than the whole parameter string being
// encoded a second time. The two agree for the plain values sent here.

// oauthSign adds the OAuth parameters and the signature to query for a request of
// method to baseURL (scheme, host and path; no query).
func oauthSign(method, baseURL string, query url.Values, consumerKey, consumerSecret string, now time.Time, nonce string) {
	query.Set("oauth_consumer_key", consumerKey)
	query.Set("oauth_nonce", nonce)
	query.Set("oauth_signature_method", "HMAC-SHA256")
	query.Set("oauth_timestamp", strconv.FormatInt(now.Unix(), 10))
	query.Del("oauth_signature")
	query.Set("oauth_signature", oauthSignature(method, baseURL, query, consumerSecret))
}

// oauthSignature computes the signature over every parameter in query except
// oauth_signature itself.
func oauthSignature(method, baseURL string, query url.Values, consumerSecret string) string {
	type pair struct{ k, v string }
	var params []pair
	for k, vs := range query {
		if k == "oauth_signature" {
			continue
		}
		for _, v := range vs {
			params = append(params, pair{rfc3986(k), rfc3986(v)})
		}
	}
	// PHP's uksort with strcmp: byte order of the raw keys, which for the ASCII keys
	// used here equals the order of the encoded ones.
	sort.Slice(params, func(i, j int) bool {
		if params[i].k != params[j].k {
			return params[i].k < params[j].k
		}
		return params[i].v < params[j].v
	})
	parts := make([]string, len(params))
	for i, p := range params {
		parts[i] = p.k + "%3D" + p.v
	}
	toSign := strings.ToUpper(method) + "&" + rfc3986(baseURL) + "&" + strings.Join(parts, "%26")
	mac := hmac.New(sha256.New, []byte(consumerSecret+"&"))
	mac.Write([]byte(toSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// rfc3986 is PHP's rawurlencode: everything but unreserved characters escaped.
func rfc3986(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return b.String()
}

// newNonce returns a random alphanumeric nonce; WooCommerce rejects a reused one.
func newNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
