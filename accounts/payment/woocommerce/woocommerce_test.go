package woocommerce

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"enode/accounts/payment"
	"enode/storage"
)

// TestOAuthSignatureVector pins the signature against a value computed outside Go:
//
//	printf '%s' 'GET&http%3A%2F%2Flocalhost%2Fshop%2Fwp-json%2Fwc%2Fv3%2Forders&oauth_consumer_key%3Dck_test%26oauth_nonce%3Dabc123%26oauth_signature_method%3DHMAC-SHA256%26oauth_timestamp%3D1700000000%26per_page%3D1' \
//	  | openssl dgst -sha256 -hmac 'cs_secret&' -binary | base64
//
// The same code was checked against a live WooCommerce (integration_test.go).
func TestOAuthSignatureVector(t *testing.T) {
	q := url.Values{"per_page": {"1"}}
	oauthSign("GET", "http://localhost/shop/wp-json/wc/v3/orders", q, "ck_test", "cs_secret", time.Unix(1700000000, 0), "abc123")
	got := q.Get("oauth_signature")
	t.Logf("input: GET /orders?per_page=1 ck_test nonce=abc123 ts=1700000000 output: %s", got)
	if want := "n17cFBRv3fIvF5JhLLGkccxySydrh40U8fdun9kVwk0="; got != want {
		t.Fatalf("signature %s, want %s", got, want)
	}
	if rfc3986("a b/c~d+é") != "a%20b%2Fc~d%2B%C3%A9" {
		t.Fatalf("rfc3986 = %s", rfc3986("a b/c~d+é"))
	}
}

// fakeShop is a WooCommerce REST API double.
type fakeShop struct {
	mu        sync.Mutex
	orders    map[uint64]map[string]any
	next      uint64
	restRoute bool // serve only ?rest_route= (no pretty permalinks)
	requests  []*http.Request
	bodies    []string
}

func (f *fakeShop) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	f.requests = append(f.requests, r)
	f.bodies = append(f.bodies, string(body))
	route := strings.TrimPrefix(r.URL.Path, "/shop/wp-json/wc/v3")
	if f.restRoute {
		if strings.HasPrefix(r.URL.Path, "/shop/wp-json/") {
			http.Error(w, "<html>404</html>", http.StatusNotFound)
			return
		}
		route = strings.TrimPrefix(r.URL.Query().Get("rest_route"), "/wc/v3")
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && route == "/orders":
		_, _ = w.Write([]byte(`[]`))
	case r.Method == http.MethodPost && route == "/orders":
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		f.next++
		id := 500 + f.next
		o := map[string]any{"id": id, "order_key": "wc_order_k", "status": "pending", "total": "4.99", "currency": "EUR",
			"payment_url": "https://shop.example/checkout/order-pay/1", "meta_data": in["meta_data"]}
		f.orders[id] = o
		_ = json.NewEncoder(w).Encode(o)
	case r.Method == http.MethodGet && strings.HasPrefix(route, "/orders/"):
		var id uint64
		for _, o := range f.orders {
			if "/orders/"+jsonNum(o["id"]) == route {
				id = uint64(o["id"].(uint64))
			}
		}
		o, ok := f.orders[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"woocommerce_rest_shop_order_invalid_id","message":"Invalid ID."}`))
			return
		}
		_ = json.NewEncoder(w).Encode(o)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"rest_no_route","message":"No route"}`))
	}
}

func (f *fakeShop) setStatus(status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, o := range f.orders {
		o["status"] = status
	}
}

func jsonNum(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func newFakeShop(t *testing.T, tls bool) (*fakeShop, *httptest.Server) {
	shop := &fakeShop{orders: map[uint64]map[string]any{}}
	var srv *httptest.Server
	if tls {
		srv = httptest.NewTLSServer(shop)
	} else {
		srv = httptest.NewServer(shop)
	}
	t.Cleanup(srv.Close)
	return shop, srv
}

func checkoutReq() payment.CheckoutRequest {
	return payment.CheckoutRequest{
		Account:     storage.Account{ID: 7, Username: "olga", Email: "olga@example.org"},
		Payment:     storage.Payment{ID: 99},
		Plan:        payment.Plan{ID: "monthly", Title: "30 days", PeriodDays: 30},
		ProviderRef: "123",
		ReturnURL:   "https://enode.example.org/account/step/payment/return?payment=99",
	}
}

func TestPlainHTTPUsesOAuth(t *testing.T) {
	shop, srv := newFakeShop(t, false)
	p, err := New(Config{StoreURL: srv.URL + "/shop", ConsumerKey: "ck_1", ConsumerSecret: "cs_1"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	co, err := p.Checkout(context.Background(), checkoutReq())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: checkout on %s output: %+v", srv.URL, co)
	if co.ExternalID != "501" || co.ExternalKey != "wc_order_k" || co.Amount != "4.99" || co.Currency != "EUR" || co.RedirectURL == "" {
		t.Fatalf("checkout = %+v", co)
	}
	shop.mu.Lock()
	last, body := shop.requests[len(shop.requests)-1], shop.bodies[len(shop.bodies)-1]
	shop.mu.Unlock()
	if last.Header.Get("Authorization") != "" || last.URL.Query().Get("oauth_signature") == "" || last.URL.Query().Get("oauth_consumer_key") != "ck_1" {
		t.Fatalf("plain HTTP must sign with OAuth, not Basic: auth=%q query=%s", last.Header.Get("Authorization"), last.URL.RawQuery)
	}
	var sent map[string]any
	_ = json.Unmarshal([]byte(body), &sent)
	t.Logf("output: order body %s", body)
	items := sent["line_items"].([]any)
	if sent["status"] != "pending" || sent["set_paid"] != false || items[0].(map[string]any)["product_id"].(float64) != 123 {
		t.Fatalf("order body: %s", body)
	}
	if !strings.Contains(body, `"_enode_payment_id","value":"99"`) || !strings.Contains(body, `"_enode_account_id","value":"7"`) {
		t.Fatalf("order meta missing: %s", body)
	}

	for status, want := range map[string]storage.PaymentStatus{"pending": storage.PaymentPending, "processing": storage.PaymentPaid, "refunded": storage.PaymentRefunded} {
		shop.setStatus(status)
		res, err := p.Fetch(context.Background(), storage.Payment{ID: 99, ExternalID: co.ExternalID})
		t.Logf("input: order status %s output: %s %v", status, res.Status, err)
		if err != nil || res.Status != want {
			t.Fatalf("Fetch with %s = %s, %v; want %s", status, res.Status, err, want)
		}
	}
	if _, err := p.Fetch(context.Background(), storage.Payment{ID: 1, ExternalID: co.ExternalID}); err == nil {
		t.Fatalf("an order opened for payment 99 was accepted for payment 1")
	}
	var se *StatusError
	if _, err := p.Fetch(context.Background(), storage.Payment{ID: 99, ExternalID: "12345"}); !errors.As(err, &se) || se.Status != 404 {
		t.Fatalf("missing order: %v", err)
	}
}

func TestHTTPSUsesBasicAuth(t *testing.T) {
	shop, srv := newFakeShop(t, true)
	p, err := New(Config{StoreURL: srv.URL + "/shop/", ConsumerKey: "ck_2", ConsumerSecret: "cs_2"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	shop.mu.Lock()
	last := shop.requests[len(shop.requests)-1]
	shop.mu.Unlock()
	user, pass, ok := last.BasicAuth()
	t.Logf("input: ping over https output: basic=%v user=%s oauth=%q", ok, user, last.URL.Query().Get("oauth_signature"))
	if !ok || user != "ck_2" || pass != "cs_2" || last.URL.Query().Get("oauth_signature") != "" {
		t.Fatalf("https must use Basic auth only")
	}
}

func TestRestRouteFallback(t *testing.T) {
	shop, srv := newFakeShop(t, false)
	shop.restRoute = true
	p, err := New(Config{StoreURL: srv.URL + "/shop/", ConsumerKey: "ck", ConsumerSecret: "cs"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	co, err := p.Checkout(context.Background(), checkoutReq())
	t.Logf("input: shop without pretty permalinks output: restRoute=%v order=%s err=%v", p.restRoute, co.ExternalID, err)
	if err != nil || !p.restRoute || co.ExternalID == "" {
		t.Fatalf("fallback failed: %v", err)
	}
}

func TestWebhookSignature(t *testing.T) {
	p, err := New(Config{StoreURL: "https://shop.example/", ConsumerKey: "ck", ConsumerSecret: "cs", WebhookSecret: "whsec"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"id":501,"status":"processing"}`)
	mac := hmac.New(sha256.New, []byte("whsec"))
	mac.Write(body)
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/hook", nil)
	req.Header.Set("X-WC-Webhook-Signature", sig)
	id, err := p.Webhook(req, body)
	t.Logf("input: signed order.updated output: id=%s err=%v", id, err)
	if err != nil || id != "501" {
		t.Fatalf("valid webhook: %s %v", id, err)
	}
	req.Header.Set("X-WC-Webhook-Signature", base64.StdEncoding.EncodeToString([]byte("forged")))
	if _, err := p.Webhook(req, body); !errors.Is(err, payment.ErrBadSignature) {
		t.Fatalf("forged signature: %v", err)
	}
	ping := httptest.NewRequest(http.MethodPost, "/hook", nil)
	if _, err := p.Webhook(ping, []byte("webhook_id=12")); !errors.Is(err, payment.ErrIgnoreWebhook) {
		t.Fatalf("delivery test ping: %v", err)
	}
	noSecret, _ := New(Config{StoreURL: "https://shop.example/", ConsumerKey: "ck", ConsumerSecret: "cs"}, nil)
	if _, err := noSecret.Webhook(req, body); !errors.Is(err, payment.ErrNoWebhook) {
		t.Fatalf("webhook without a secret: %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	cases := []struct {
		cfg  Config
		want string
	}{
		{Config{StoreURL: "ftp://x", ConsumerKey: "k", ConsumerSecret: "s"}, "invalid"},
		{Config{StoreURL: "http://shop.example/", ConsumerKey: "k", ConsumerSecret: "s"}, "plain HTTP"},
		{Config{StoreURL: "http://shop.example/", ConsumerKey: "k", ConsumerSecret: "s", AllowInsecureStore: true}, ""},
		{Config{StoreURL: "http://127.0.0.1/wp/", ConsumerKey: "k", ConsumerSecret: "s"}, ""},
		{Config{StoreURL: "https://shop.example/"}, "consumerKey"},
	}
	for _, c := range cases {
		_, err := New(c.cfg, nil)
		t.Logf("input: %s insecure=%v key=%q output: %v", c.cfg.StoreURL, c.cfg.AllowInsecureStore, c.cfg.ConsumerKey, err)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: err=%v, want %q", c.cfg.StoreURL, err, c.want)
		}
	}
}

func TestMapStatus(t *testing.T) {
	cases := map[string]storage.PaymentStatus{
		"pending": storage.PaymentPending, "on-hold": storage.PaymentPending, "checkout-draft": storage.PaymentPending,
		"processing": storage.PaymentPaid, "completed": storage.PaymentPaid, "failed": storage.PaymentFailed,
		"cancelled": storage.PaymentCancelled, "trash": storage.PaymentCancelled, "refunded": storage.PaymentRefunded,
	}
	for in, want := range cases {
		got := MapStatus(in)
		t.Logf("input: %s output: %s", in, got)
		if got != want {
			t.Errorf("MapStatus(%s) = %s, want %s", in, got, want)
		}
	}
}
