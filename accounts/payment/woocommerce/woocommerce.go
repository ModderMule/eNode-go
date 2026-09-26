// Package woocommerce is a payment.Provider backed by a WooCommerce shop: the
// server opens a pending order for the plan's product through the shop's REST API
// (/wp-json/wc/v3), sends the user to the order's payment page, and reads the
// order's status back through the same API. The shop does the actual taking of
// money with whatever payment gateways its operator installed.
package woocommerce

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"enode/accounts"
	"enode/accounts/payment"
	"enode/storage"

	"gopkg.in/yaml.v3"
)

// Name is the provider's key under providers: and in storage.
const Name = "woocommerce"

// Order meta keys the provider writes. The leading underscore hides them from the
// shop's order screen custom-field box.
const (
	metaAccountID = "_enode_account_id"
	metaPaymentID = "_enode_payment_id"
	// metaReturnURL lets an optional shop-side snippet send the buyer back to the
	// eNode account page after checkout (see docs/meta-api.md).
	metaReturnURL = "_enode_return_url"
)

// Config is the provider's keys under providers.woocommerce.
type Config struct {
	Enabled *bool `yaml:"enabled"`
	// StoreURL is the WordPress site's home URL, e.g. https://shop.example.org/ or
	// http://localhost/wordpress/. It must match the site's configured home URL, which
	// is what an OAuth signature over plain HTTP is computed against.
	StoreURL       string `yaml:"storeURL"`
	ConsumerKey    string `yaml:"consumerKey"`
	ConsumerSecret string `yaml:"consumerSecret"`
	// WebhookSecret is the secret of an order.updated webhook pointed at
	// {publicURL}/account/step/<id>/hook/woocommerce. Empty disables the webhook;
	// the poller still finds every payment.
	WebhookSecret string `yaml:"webhookSecret"`
	// AllowInsecureStore permits a plain-HTTP store on a non-loopback host.
	AllowInsecureStore bool `yaml:"allowInsecureStore"`
	// Title is the provider's label on the plan page.
	Title          string `yaml:"title"`
	TimeoutSeconds int    `yaml:"timeoutSeconds"`
}

// Provider talks to one WooCommerce shop.
type Provider struct {
	cfg    Config
	store  *url.URL
	client *http.Client
	now    func() time.Time

	// restRoute is set when the shop has no pretty permalinks, so /wp-json/ 404s
	// and the API is reached as ?rest_route=/wc/v3/... instead. Detected on the
	// first call that gets an answer from the shop.
	mu        sync.Mutex
	detected  bool
	restRoute bool
}

// Factory builds the provider from its config node. Register it as Name.
func Factory(node yaml.Node, deps accounts.Deps) (payment.Provider, error) {
	var cfg Config
	if err := node.Decode(&cfg); err != nil {
		return nil, err
	}
	return New(cfg, deps.HTTPClient)
}

// New validates cfg and returns the provider. It does not contact the shop.
func New(cfg Config, client *http.Client) (*Provider, error) {
	u, err := url.Parse(strings.TrimSpace(cfg.StoreURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("storeURL %q is invalid: use the shop's home URL, e.g. https://shop.example.org/", cfg.StoreURL)
	}
	if u.Scheme == "http" && !cfg.AllowInsecureStore && !isLoopback(u.Hostname()) {
		return nil, fmt.Errorf("storeURL %q is plain HTTP: use https, or set allowInsecureStore for a shop on a trusted network", cfg.StoreURL)
	}
	if cfg.ConsumerKey == "" || cfg.ConsumerSecret == "" {
		return nil, errors.New("consumerKey and consumerSecret are required: create a REST API key with read/write access under WooCommerce → Settings → Advanced → REST API")
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.RawQuery, u.Fragment = "", ""
	if client == nil {
		client = &http.Client{}
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	// A copy, so the timeout and the redirect policy are this provider's own.
	c := *client
	c.Timeout = timeout
	// Following a redirect would drop the OAuth signature's binding to the URL, and a
	// POST turned into a GET would silently not create the order.
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Provider{cfg: cfg, store: u, client: &c, now: time.Now}, nil
}

// Name is the provider's key.
func (p *Provider) Name() string { return Name }

// Title is the label on the plan page.
func (p *Provider) Title(string) string {
	if p.cfg.Title != "" {
		return p.cfg.Title
	}
	return "Shop checkout"
}

// Ping checks the credentials with a one-row order listing and detects whether
// the shop needs the ?rest_route= form.
func (p *Provider) Ping(ctx context.Context) error {
	var orders []order
	return p.call(ctx, http.MethodGet, "/orders", url.Values{"per_page": {"1"}}, nil, &orders)
}

// Checkout creates a pending order for the plan's product.
func (p *Provider) Checkout(ctx context.Context, req payment.CheckoutRequest) (payment.Checkout, error) {
	productID, err := strconv.ParseUint(req.ProviderRef, 10, 64)
	if err != nil || productID == 0 {
		return payment.Checkout{}, fmt.Errorf("plan %s: providerRefs.woocommerce %q is not a product id", req.Plan.ID, req.ProviderRef)
	}
	body := map[string]any{
		"status":        "pending",
		"set_paid":      false,
		"customer_note": fmt.Sprintf("eNode account %s (%s)", req.Account.Username, req.Plan.Title),
		"line_items":    []map[string]any{{"product_id": productID, "quantity": 1}},
		"meta_data": []map[string]string{
			{"key": metaAccountID, "value": strconv.FormatUint(req.Account.ID, 10)},
			{"key": metaPaymentID, "value": strconv.FormatUint(req.Payment.ID, 10)},
			{"key": metaReturnURL, "value": req.ReturnURL},
		},
	}
	if req.Account.Email != "" {
		body["billing"] = map[string]string{"email": req.Account.Email}
	}
	var o order
	if err := p.call(ctx, http.MethodPost, "/orders", nil, body, &o); err != nil {
		return payment.Checkout{}, err
	}
	if o.ID == 0 || o.PaymentURL == "" {
		return payment.Checkout{}, fmt.Errorf("the shop created order %d without a payment_url", o.ID)
	}
	return payment.Checkout{
		ExternalID:  strconv.FormatUint(o.ID, 10),
		ExternalKey: o.OrderKey,
		RedirectURL: o.PaymentURL,
		Amount:      o.Total,
		Currency:    o.Currency,
	}, nil
}

// Fetch reads an order's status.
func (p *Provider) Fetch(ctx context.Context, pay storage.Payment) (payment.FetchResult, error) {
	var o order
	if err := p.call(ctx, http.MethodGet, "/orders/"+url.PathEscape(pay.ExternalID), nil, nil, &o); err != nil {
		return payment.FetchResult{}, err
	}
	// The order must be the one opened for this payment: an operator editing ids, or
	// a restored shop database, must not credit someone else's order.
	if id := o.meta(metaPaymentID); id != "" && id != strconv.FormatUint(pay.ID, 10) {
		return payment.FetchResult{}, fmt.Errorf("order %s belongs to payment %s, not %d", pay.ExternalID, id, pay.ID)
	}
	return payment.FetchResult{Status: MapStatus(o.Status), Amount: o.Total, Currency: o.Currency}, nil
}

// Webhook verifies an order webhook and returns the order id. WooCommerce signs
// the raw body with HMAC-SHA256 in X-WC-Webhook-Signature, base64.
func (p *Provider) Webhook(r *http.Request, body []byte) (string, error) {
	if p.cfg.WebhookSecret == "" {
		return "", payment.ErrNoWebhook
	}
	mac := hmac.New(sha256.New, []byte(p.cfg.WebhookSecret))
	mac.Write(body)
	want := mac.Sum(nil)
	got, err := base64.StdEncoding.DecodeString(r.Header.Get("X-WC-Webhook-Signature"))
	if err != nil || !hmac.Equal(got, want) {
		// WooCommerce's delivery test on saving a webhook is an unsigned form post
		// "webhook_id=N"; acknowledge it so the shop marks the webhook healthy.
		if r.Header.Get("X-WC-Webhook-Signature") == "" && strings.HasPrefix(string(body), "webhook_id=") {
			return "", payment.ErrIgnoreWebhook
		}
		return "", payment.ErrBadSignature
	}
	var o order
	if err := json.Unmarshal(body, &o); err != nil || o.ID == 0 {
		return "", payment.ErrIgnoreWebhook
	}
	return strconv.FormatUint(o.ID, 10), nil
}

// MapStatus maps a WooCommerce order status onto a payment status. processing is
// WooCommerce's "paid, awaiting fulfilment", which for a virtual product is paid.
func MapStatus(status string) storage.PaymentStatus {
	switch status {
	case "processing", "completed":
		return storage.PaymentPaid
	case "failed":
		return storage.PaymentFailed
	case "cancelled", "trash":
		return storage.PaymentCancelled
	case "refunded":
		return storage.PaymentRefunded
	default: // pending, on-hold, checkout-draft, and anything a plugin adds
		return storage.PaymentPending
	}
}

// StatusError is a non-2xx answer from the shop.
type StatusError struct {
	Status  int
	Code    string
	Message string
}

func (e *StatusError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("woocommerce: HTTP %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("woocommerce: HTTP %d %s", e.Status, e.Message)
}

// order is the part of a WooCommerce order this provider reads.
type order struct {
	ID         uint64 `json:"id"`
	OrderKey   string `json:"order_key"`
	Status     string `json:"status"`
	Total      string `json:"total"`
	Currency   string `json:"currency"`
	PaymentURL string `json:"payment_url"`
	MetaData   []struct {
		Key   string `json:"key"`
		Value any    `json:"value"`
	} `json:"meta_data"`
}

func (o order) meta(key string) string {
	for _, m := range o.MetaData {
		if m.Key == key {
			if s, ok := m.Value.(string); ok {
				return s
			}
			return fmt.Sprint(m.Value)
		}
	}
	return ""
}

// apiError is WooCommerce's error body.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// call performs one REST call. path is relative to /wc/v3, e.g. "/orders".
func (p *Provider) call(ctx context.Context, method, path string, query url.Values, body, out any) error {
	p.detectRestRoute(ctx)
	return p.do(ctx, method, path, query, body, out)
}

func (p *Provider) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	endpoint, q := p.endpoint(path)
	for k, vs := range query {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "", reader)
	if err != nil {
		return err
	}
	if p.store.Scheme == "https" {
		req.SetBasicAuth(p.cfg.ConsumerKey, p.cfg.ConsumerSecret)
	} else {
		oauthSign(method, endpoint, q, p.cfg.ConsumerKey, p.cfg.ConsumerSecret, p.now(), newNonce())
	}
	u, _ := url.Parse(endpoint)
	u.RawQuery = q.Encode()
	req.URL, req.Host = u, u.Host
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e apiError
		if json.Unmarshal(raw, &e) == nil && e.Code != "" {
			return &StatusError{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
		}
		return &StatusError{Status: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("woocommerce %s %s: decode: %w", method, path, err)
	}
	return nil
}

// endpoint returns the URL without query, and the query the route itself needs.
func (p *Provider) endpoint(path string) (string, url.Values) {
	p.mu.Lock()
	restRoute := p.restRoute
	p.mu.Unlock()
	if restRoute {
		return p.store.String(), url.Values{"rest_route": {"/wc/v3" + path}}
	}
	return p.store.String() + "wp-json/wc/v3" + path, url.Values{}
}

// detectRestRoute switches to ?rest_route= when /wp-json/ is not routed. It
// settles on the first answer from the shop; a transport error leaves it for the
// next call to try again.
func (p *Provider) detectRestRoute(ctx context.Context) {
	p.mu.Lock()
	done := p.detected
	p.mu.Unlock()
	if done {
		return
	}
	var orders []order
	err := p.do(ctx, http.MethodGet, "/orders", url.Values{"per_page": {"1"}}, nil, &orders)
	var se *StatusError
	if err != nil && !errors.As(err, &se) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.detected = true
	// WordPress answers an unrouted /wp-json/ with its own HTML 404, never a
	// WooCommerce error code.
	p.restRoute = se != nil && se.Status == http.StatusNotFound && se.Code == ""
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
