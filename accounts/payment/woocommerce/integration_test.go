package woocommerce

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"enode/accounts/payment"
	"enode/storage"
)

// TestLiveShop runs the whole provider against a real WooCommerce shop: ping, a
// throw-away virtual product, a pending order, a simulated payment and cleanup. It
// is skipped unless the shop is named in the environment:
//
//	ENODE_WOO_TEST_URL=http://localhost/wordpress/
//	ENODE_WOO_TEST_KEY=ck_...
//	ENODE_WOO_TEST_SECRET=cs_...
//	ENODE_WOO_TEST_PRODUCT_ID=123   (optional; otherwise a private product is created)
//
// Never put the credentials in a tracked file; enode.local.yaml is gitignored.
func TestLiveShop(t *testing.T) {
	storeURL, key, secret := os.Getenv("ENODE_WOO_TEST_URL"), os.Getenv("ENODE_WOO_TEST_KEY"), os.Getenv("ENODE_WOO_TEST_SECRET")
	if storeURL == "" || key == "" || secret == "" {
		t.Skip("set ENODE_WOO_TEST_URL, ENODE_WOO_TEST_KEY and ENODE_WOO_TEST_SECRET to run against a live shop")
	}
	t.Logf("input: store=%s key=%s… secret=<redacted>", storeURL, key[:min(len(key), 6)])
	p, err := New(Config{StoreURL: storeURL, ConsumerKey: key, ConsumerSecret: secret, AllowInsecureStore: true}, http.DefaultClient)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := p.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	t.Logf("output: ping ok (scheme=%s restRoute=%v)", p.store.Scheme, p.restRoute)

	productID := os.Getenv("ENODE_WOO_TEST_PRODUCT_ID")
	if productID == "" {
		var prod struct {
			ID uint64 `json:"id"`
		}
		err := p.call(ctx, http.MethodPost, "/products", nil, map[string]any{
			"name": "enode-test-" + strconv.FormatInt(time.Now().Unix(), 10), "type": "simple",
			"virtual": true, "regular_price": "1.00", "status": "private",
		}, &prod)
		if err != nil {
			t.Fatalf("create test product: %v", err)
		}
		productID = strconv.FormatUint(prod.ID, 10)
		t.Logf("output: created private test product %s", productID)
		defer func() {
			err := p.call(context.Background(), http.MethodDelete, "/products/"+productID, url.Values{"force": {"true"}}, nil, nil)
			t.Logf("cleanup: delete product %s: err=%v", productID, err)
		}()
	}

	acct := storage.Account{ID: 424242, Username: "enode-test"}
	pay := storage.Payment{ID: 777001, AccountID: acct.ID, PlanID: "test"}
	co, err := p.Checkout(ctx, payment.CheckoutRequest{
		Account: acct, Payment: pay, Plan: payment.Plan{ID: "test", Title: "Test", PeriodDays: 30},
		ProviderRef: productID, ReturnURL: "http://127.0.0.1:4672/account/step/payment/return?payment=777001",
	})
	if err != nil {
		t.Fatalf("Checkout: %v", err)
	}
	t.Logf("output: order id=%s key=%s total=%s %s payment_url=%s", co.ExternalID, co.ExternalKey, co.Amount, co.Currency, co.RedirectURL)
	defer func() {
		err := p.call(context.Background(), http.MethodDelete, "/orders/"+co.ExternalID, url.Values{"force": {"true"}}, nil, nil)
		t.Logf("cleanup: delete order %s: err=%v", co.ExternalID, err)
	}()
	if !strings.Contains(co.RedirectURL, "order-pay") && !strings.Contains(co.RedirectURL, "pay_for_order") {
		t.Errorf("payment_url %q does not look like an order payment page", co.RedirectURL)
	}

	pay.ExternalID = co.ExternalID
	res, err := p.Fetch(ctx, pay)
	if err != nil {
		t.Fatalf("Fetch pending: %v", err)
	}
	t.Logf("output: fetched status=%s", res.Status)
	if res.Status != storage.PaymentPending {
		t.Fatalf("new order status = %s, want pending", res.Status)
	}

	// Simulate the shop taking the money.
	if err := p.call(ctx, http.MethodPut, "/orders/"+co.ExternalID, nil, map[string]any{"status": "completed"}, nil); err != nil {
		t.Fatalf("complete order: %v", err)
	}
	res, err = p.Fetch(ctx, pay)
	if err != nil {
		t.Fatalf("Fetch completed: %v", err)
	}
	t.Logf("output: after completing, status=%s", res.Status)
	if res.Status != storage.PaymentPaid {
		t.Fatalf("completed order status = %s, want paid", res.Status)
	}

	// A payment id that does not match the order's meta must be refused.
	other := pay
	other.ID = 1
	if _, err := p.Fetch(ctx, other); err == nil {
		t.Errorf("Fetch accepted an order that belongs to another payment")
	} else {
		t.Logf("output: mismatched payment refused: %v", err)
	}
}
