package payment

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"enode/accounts"
	"enode/config"
	"enode/storage"

	"gopkg.in/yaml.v3"
)

// payAndCredit completes the harness user's checkout and lets the webhook credit it.
func (h *harness) payAndCredit(p storage.Payment) {
	h.t.Helper()
	h.prov.set(p.ExternalID, storage.PaymentPaid)
	if err := h.step.Reconcile(context.Background(), "fake", p.ExternalID); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) account(id uint64) storage.Account {
	h.t.Helper()
	a, err := h.store.AccountByID(context.Background(), id)
	if err != nil {
		h.t.Fatal(err)
	}
	st, err := h.svc.Evaluate(context.Background(), &a)
	if err != nil {
		h.t.Fatal(err)
	}
	a.State = st.State
	return a
}

func TestRefundIgnoredWhenWindowOff(t *testing.T) {
	h := newHarness(t)
	acct, p := h.registerAndCheckout("rita")
	h.payAndCredit(p)
	h.prov.set(p.ExternalID, storage.PaymentRefunded)
	h.now = h.now.Add(2 * time.Hour)
	_ = h.step.Reconcile(context.Background(), "fake", p.ExternalID)
	h.step.Poll(context.Background())
	a := h.account(acct.ID)
	got, _ := h.store.PaymentByID(context.Background(), p.ID)
	t.Logf("input: refund with refundWindowDays 0 output: state=%s until=%s payment=%s revoked=%v", a.State, a.AccessUntil, got.Status, !got.RevokedAt.IsZero())
	if a.State != storage.AccountActive || !got.RevokedAt.IsZero() || got.Status != storage.PaymentPaid {
		t.Fatalf("a refund was acted on with the window off")
	}
}

func TestRefundInsideWindowRevokesOnce(t *testing.T) {
	h := newHarnessWith(t, "refundWindowDays: 14\n")
	acct, p := h.registerAndCheckout("sam")
	h.payAndCredit(p)
	if a := h.account(acct.ID); a.State != storage.AccountActive {
		t.Fatalf("not active after paying: %s", a.State)
	}

	h.now = h.now.Add(3 * 24 * time.Hour)
	h.prov.set(p.ExternalID, storage.PaymentRefunded)
	for i := 0; i < 3; i++ { // repeated webhook deliveries, then the poller
		if err := h.step.Reconcile(context.Background(), "fake", p.ExternalID); err != nil {
			t.Fatal(err)
		}
	}
	h.step.Poll(context.Background())
	a := h.account(acct.ID)
	got, _ := h.store.PaymentByID(context.Background(), p.ID)
	st, _ := h.svc.Evaluate(context.Background(), &a)
	t.Logf("input: refund on day 3 of 30, 3 webhooks + poll output: state=%s until=%s payment=%s pending=%+v", a.State, a.AccessUntil, got.Status, st.Pending)
	if got.Status != storage.PaymentRefunded || got.RevokedAt.IsZero() {
		t.Fatalf("payment not marked refunded/revoked: %+v", got)
	}
	// 30 days taken back from day 0 + 30 = the original purchase time, which is past.
	if !a.AccessUntil.Equal(h.now.Add(-3 * 24 * time.Hour)) {
		t.Fatalf("access until %s, want %s (revoked exactly once)", a.AccessUntil, h.now.Add(-3*24*time.Hour))
	}
	if a.State == storage.AccountActive || len(st.Pending) != 1 || st.Pending[0].MsgCode != CodeRefunded {
		t.Fatalf("after a refund: state=%s pending=%+v, want the payment step open with %s", a.State, st.Pending, CodeRefunded)
	}

	// The account page says why. The browser session expired while the clock moved
	// three days, so log in again first.
	h.form("/account/login", "/account/login", url.Values{"username": {"sam"}, "password": {"password1"}}).Body.Close()
	resp, err := h.web.Get(h.base + "/account")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "refunded or cancelled") {
		t.Fatalf("account page does not explain the refund")
	}
}

func TestRefundOfOneStackedPurchase(t *testing.T) {
	h := newHarnessWith(t, "refundWindowDays: 14\n")
	acct, p1 := h.registerAndCheckout("tom")
	h.payAndCredit(p1)
	// A second, early renewal stacks another 30 days.
	resp := h.form("/account/step/payment/", "/account/step/payment/checkout", url.Values{"plan": {"monthly"}, "provider": {"fake"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("second checkout: %d", resp.StatusCode)
	}
	pays, _ := h.store.PaymentsByAccount(context.Background(), acct.ID, 10)
	p2 := pays[0]
	h.payAndCredit(p2)
	if a := h.account(acct.ID); !a.AccessUntil.Equal(h.now.Add(60 * 24 * time.Hour)) {
		t.Fatalf("two purchases: until %s, want 60 days", a.AccessUntil)
	}
	h.prov.set(p2.ExternalID, storage.PaymentCancelled)
	_ = h.step.Reconcile(context.Background(), "fake", p2.ExternalID)
	a := h.account(acct.ID)
	t.Logf("input: 2×30 days, second cancelled output: state=%s until=%s", a.State, a.AccessUntil)
	if a.State != storage.AccountActive || !a.AccessUntil.Equal(h.now.Add(30*24*time.Hour)) {
		t.Fatalf("want still active for 30 days, got %s until %s", a.State, a.AccessUntil)
	}
}

func TestRefundOutsideWindowIgnored(t *testing.T) {
	h := newHarnessWith(t, "refundWindowDays: 14\n")
	acct, p := h.registerAndCheckout("uma")
	h.payAndCredit(p)
	fetches := h.prov.fetches.Load()
	h.now = h.now.Add(20 * 24 * time.Hour)
	h.prov.set(p.ExternalID, storage.PaymentRefunded)
	_ = h.step.Reconcile(context.Background(), "fake", p.ExternalID)
	h.step.Poll(context.Background())
	a := h.account(acct.ID)
	t.Logf("input: refund on day 20, window 14 output: state=%s extra fetches=%d", a.State, h.prov.fetches.Load()-fetches)
	if a.State != storage.AccountActive || h.prov.fetches.Load() != fetches {
		t.Fatalf("a payment outside the window was re-checked or revoked")
	}
}

func TestRefundWindowValidation(t *testing.T) {
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(stepYAML+"refundWindowDays: -1\n"), &node); err != nil {
		t.Fatal(err)
	}
	_, err := New(config.AccountStepConfig{ID: "payment", Type: TypeName, Enabled: true, Raw: *node.Content[0]},
		accounts.Deps{}, Providers{"fake": func(yaml.Node, accounts.Deps) (Provider, error) { return &fakeProvider{}, nil }})
	t.Logf("input: refundWindowDays -1 output: %v", err)
	if err == nil || !strings.Contains(err.Error(), "refundWindowDays") {
		t.Fatalf("negative window accepted: %v", err)
	}
}
