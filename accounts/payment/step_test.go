package payment

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enode/accounts"
	"enode/config"
	"enode/storage"

	"gopkg.in/yaml.v3"
)

// durableMemory is the memory engine claiming durability, so the payment step
// (which refuses a store that loses accounts) can be tested without a database.
type durableMemory struct{ *storage.MemoryEngine }

func (durableMemory) DurableAccounts() bool { return true }

// fakeProvider is a scriptable payment backend.
type fakeProvider struct {
	mu       sync.Mutex
	orders   map[string]storage.PaymentStatus
	next     int
	fetches  atomic.Int64
	fetchErr error
}

func (f *fakeProvider) Name() string        { return "fake" }
func (f *fakeProvider) Title(string) string { return "Fake Pay" }
func (f *fakeProvider) Checkout(_ context.Context, req CheckoutRequest) (Checkout, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	id := strconv.Itoa(1000 + f.next)
	f.orders[id] = storage.PaymentPending
	return Checkout{ExternalID: id, ExternalKey: "key-" + id, RedirectURL: "https://pay.example/" + id + "?ref=" + req.ProviderRef,
		Amount: "5.00", Currency: "EUR"}, nil
}
func (f *fakeProvider) Fetch(_ context.Context, p storage.Payment) (FetchResult, error) {
	f.fetches.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fetchErr != nil {
		return FetchResult{}, f.fetchErr
	}
	return FetchResult{Status: f.orders[p.ExternalID], Amount: "5.00", Currency: "EUR"}, nil
}
func (f *fakeProvider) Webhook(r *http.Request, body []byte) (string, error) {
	if r.Header.Get("X-Sig") != "ok" {
		return "", ErrBadSignature
	}
	if len(body) == 0 {
		return "", ErrIgnoreWebhook
	}
	return string(body), nil
}
func (f *fakeProvider) set(id string, s storage.PaymentStatus) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.orders[id] = s
}

const stepYAML = `
id: payment
type: payment
enabled: true
plans:
  - {id: monthly, title: "30 days", periodDays: 30, providerRefs: {fake: "42"}}
providers:
  fake: {enabled: true}
`

type harness struct {
	t     *testing.T
	svc   *accounts.Service
	store durableMemory
	prov  *fakeProvider
	step  *Step
	base  string
	web   *http.Client
	now   time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWith(t, "")
}

// newHarnessWith appends extra step keys (YAML at the entry's indentation).
func newHarnessWith(t *testing.T, extra string) *harness {
	t.Helper()
	h := &harness{t: t, store: durableMemory{storage.NewMemoryEngine()}, prov: &fakeProvider{orders: map[string]storage.PaymentStatus{}},
		now: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(stepYAML+extra), &node); err != nil {
		t.Fatal(err)
	}
	var sc config.AccountStepConfig
	if err := node.Content[0].Decode(&sc); err != nil {
		t.Fatal(err)
	}
	reg := accounts.Registry{}
	reg.Register(TypeName, func(c config.AccountStepConfig, deps accounts.Deps) (accounts.Step, error) {
		s, err := New(c, deps, Providers{"fake": func(yaml.Node, accounts.Deps) (Provider, error) { return h.prov, nil }})
		h.step = s
		return s, err
	})
	svc, err := accounts.New(accounts.Config{PublicURL: "http://placeholder", AllowRegistration: true, SessionTTL: time.Hour,
		MinPasswordLength: 8}, h.store, reg, []config.AccountStepConfig{sc}, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetClock(func() time.Time { return h.now })
	h.svc = svc
	srv := httptest.NewServer(accounts.NewWeb(svc, accounts.PortalConfig{ServerName: "t"}).Handler())
	t.Cleanup(srv.Close)
	h.base = srv.URL
	jar, _ := cookiejar.New(nil)
	h.web = &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Host == "pay.example" {
			return http.ErrUseLastResponse // the "shop": stop here
		}
		return nil
	}}
	return h
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (h *harness) form(page, action string, v url.Values) *http.Response {
	h.t.Helper()
	resp, err := h.web.Get(h.base + page)
	if err != nil {
		h.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if m := csrfRe.FindSubmatch(b); m != nil {
		v.Set("csrf", string(m[1]))
	}
	resp, err = h.web.PostForm(h.base+action, v)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

// registerAndCheckout signs up a user in the browser and submits the checkout.
func (h *harness) registerAndCheckout(user string) (storage.Account, storage.Payment) {
	h.t.Helper()
	resp := h.form("/account/register", "/account/register", url.Values{"username": {user}, "password": {"password1"}, "password2": {"password1"}})
	resp.Body.Close()
	resp = h.form("/account/step/payment/", "/account/step/payment/checkout", url.Values{"plan": {"monthly"}, "provider": {"fake"}})
	resp.Body.Close()
	h.t.Logf("input: checkout monthly output: %d Location=%s", resp.StatusCode, resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "https://pay.example/") {
		h.t.Fatalf("checkout did not redirect to the provider: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	acct, err := h.store.AccountByUsername(context.Background(), user)
	if err != nil {
		h.t.Fatal(err)
	}
	pays, _ := h.store.PaymentsByAccount(context.Background(), acct.ID, 10)
	if len(pays) != 1 {
		h.t.Fatalf("payments after checkout: %+v", pays)
	}
	return acct, pays[0]
}

func TestCheckoutRecordsPendingPayment(t *testing.T) {
	h := newHarness(t)
	acct, p := h.registerAndCheckout("henry")
	t.Logf("output: payment %+v", p)
	if p.Status != storage.PaymentPending || p.ExternalID == "" || p.Amount != "5.00" || p.PeriodDays != 30 || p.Provider != "fake" {
		t.Fatalf("payment row: %+v", p)
	}
	st, _ := h.svc.Evaluate(context.Background(), &acct)
	if st.State != storage.AccountPending || len(st.Pending) != 1 || st.Pending[0].MsgCode != CodePending {
		t.Fatalf("status while unpaid: %+v", st)
	}
}

func TestWebhookActivatesOnce(t *testing.T) {
	h := newHarness(t)
	acct, p := h.registerAndCheckout("iris")

	post := func(sig, body string) int {
		req, _ := http.NewRequest(http.MethodPost, h.base+"/account/step/payment/hook/fake", strings.NewReader(body))
		req.Header.Set("X-Sig", sig)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post("bad", p.ExternalID); code != http.StatusUnauthorized {
		t.Fatalf("bad signature: %d, want 401", code)
	}
	if code := post("ok", ""); code != http.StatusOK {
		t.Fatalf("ping: %d, want 200", code)
	}
	if code := post("ok", "no-such-order"); code != http.StatusOK {
		t.Fatalf("unknown order: %d, want 200", code)
	}
	req, _ := http.NewRequest(http.MethodPost, h.base+"/account/step/payment/hook/nope", nil)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown provider: %d, want 404", resp.StatusCode)
	}

	// Still unpaid: the webhook changes nothing.
	if code := post("ok", p.ExternalID); code != http.StatusOK {
		t.Fatalf("webhook: %d", code)
	}
	a, _ := h.store.AccountByID(context.Background(), acct.ID)
	if !a.AccessUntil.IsZero() {
		t.Fatalf("access granted before payment")
	}

	h.prov.set(p.ExternalID, storage.PaymentPaid)
	for i := 0; i < 3; i++ { // the shop retries deliveries
		if code := post("ok", p.ExternalID); code != http.StatusOK {
			t.Fatalf("webhook %d: %d", i, code)
		}
	}
	a, _ = h.store.AccountByID(context.Background(), acct.ID)
	st, _ := h.svc.Evaluate(context.Background(), &a)
	t.Logf("input: paid + 3 webhook deliveries output: state=%s until=%s", st.State, st.AccessUntil)
	if st.State != storage.AccountActive || !st.AccessUntil.Equal(h.now.Add(30*24*time.Hour)) {
		t.Fatalf("want active for exactly 30 days, got %s until %s", st.State, st.AccessUntil)
	}
}

// TestConcurrentPathsCreditOnce races every path that can observe a payment as
// paid — return URL, status check, poller, webhook — and requires one grant.
func TestConcurrentPathsCreditOnce(t *testing.T) {
	h := newHarness(t)
	acct, p := h.registerAndCheckout("jack")
	h.prov.set(p.ExternalID, storage.PaymentPaid)

	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				_ = h.step.Reconcile(ctx, "fake", p.ExternalID)
			case 1:
				a, _ := h.store.AccountByID(ctx, acct.ID)
				_, _ = h.svc.Evaluate(ctx, &a)
			default:
				h.step.Poll(ctx)
			}
		}(i)
	}
	wg.Wait()
	a, _ := h.store.AccountByID(ctx, acct.ID)
	t.Logf("input: 20 concurrent reconciliations of one paid order output: until=%s state=%s fetches=%d", a.AccessUntil, a.State, h.prov.fetches.Load())
	if !a.AccessUntil.Equal(h.now.Add(30 * 24 * time.Hour)) {
		t.Fatalf("granted %s, want exactly 30 days from now", a.AccessUntil.Sub(h.now))
	}
	if a.State != storage.AccountActive {
		t.Fatalf("state %s, want active", a.State)
	}
}

func TestReturnPageAndFailedPayment(t *testing.T) {
	h := newHarness(t)
	_, p := h.registerAndCheckout("kate")
	h.prov.set(p.ExternalID, storage.PaymentFailed)
	resp, err := h.web.Get(h.base + "/account/step/payment/return?payment=" + strconv.FormatUint(p.ID, 10))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("input: return from a failed payment output: landed %s", resp.Request.URL)
	if !strings.Contains(resp.Request.URL.RawQuery, CodeFailed) || !strings.Contains(string(body), "did not go through") {
		t.Fatalf("failed payment not reported: %s", resp.Request.URL)
	}
	// Someone else's payment id is not reconciled or reported.
	other := newHarness(t)
	other.registerAndCheckout("leo")
	resp, _ = other.web.Get(other.base + "/account/step/payment/return?payment=999")
	resp.Body.Close()
	if strings.Contains(resp.Request.URL.RawQuery, "step.payment") {
		t.Fatalf("an unknown payment id produced a payment notice: %s", resp.Request.URL)
	}
}

func TestPollAbandonsOldPaymentsAndThrottles(t *testing.T) {
	h := newHarness(t)
	_, p := h.registerAndCheckout("mia")
	ctx := context.Background()

	h.step.Poll(ctx)
	h.step.Poll(ctx) // inside fetchInterval: no second fetch
	t.Logf("input: two polls within %s output: %d fetches", fetchInterval, h.prov.fetches.Load())
	if h.prov.fetches.Load() != 1 {
		t.Fatalf("fetches = %d, want 1 (throttled)", h.prov.fetches.Load())
	}
	// The store stamps CreatedAt with the wall clock, so age it from there.
	h.now = time.Now().Add(31 * 24 * time.Hour)
	h.step.Poll(ctx)
	got, _ := h.store.PaymentByID(ctx, p.ID)
	t.Logf("input: poll 31 days later output: status=%s", got.Status)
	if got.Status != storage.PaymentCancelled {
		t.Fatalf("abandoned payment status %s, want cancelled", got.Status)
	}
}

func TestProviderErrorsKeepStepPending(t *testing.T) {
	h := newHarness(t)
	acct, _ := h.registerAndCheckout("nora")
	h.prov.mu.Lock()
	h.prov.fetchErr = errors.New("shop down")
	h.prov.mu.Unlock()
	h.now = h.now.Add(time.Minute)
	st, err := h.svc.Evaluate(context.Background(), &acct)
	t.Logf("input: provider down output: state=%s err=%v", st.State, err)
	if err != nil || st.State != storage.AccountPending {
		t.Fatalf("a provider outage must leave the account pending without failing: %s %v", st.State, err)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	cases := map[string]string{
		"no provider":         "plans: [{id: m, providerRefs: {fake: '1'}}]",
		"unknown provider":    "plans: [{id: m, providerRefs: {x: '1'}}]\nproviders: {x: {}}",
		"plan not sellable":   "plans: [{id: m, providerRefs: {other: '1'}}]\nproviders: {fake: {}}",
		"no plans":            "providers: {fake: {}}",
		"duplicate plan":      "plans: [{id: m, providerRefs: {fake: '1'}}, {id: m, providerRefs: {fake: '2'}}]\nproviders: {fake: {}}",
		"provider turned off": "plans: [{id: m, providerRefs: {fake: '1'}}]\nproviders: {fake: {enabled: false}}",
	}
	for name, src := range cases {
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(src), &node); err != nil {
			t.Fatal(err)
		}
		_, err := New(config.AccountStepConfig{ID: "payment", Type: TypeName, Enabled: true, Raw: *node.Content[0]},
			accounts.Deps{}, Providers{"fake": func(yaml.Node, accounts.Deps) (Provider, error) { return &fakeProvider{}, nil }})
		t.Logf("input: %s output: %v", name, err)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
