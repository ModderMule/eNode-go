package payment

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"enode/accounts"
	"enode/config"
	"enode/internal/ratelimit"
	"enode/locales"
	"enode/logging"
	"enode/storage"

	"gopkg.in/yaml.v3"
)

// TypeName is the step's `type:` in metaApi.accounts.steps.
const TypeName = "payment"

// MsgCodes of this step. Each must exist in every locales/*.json file.
const (
	CodeRequired    = "step.payment.required"
	CodePending     = "step.payment.pending"
	CodeFailed      = "step.payment.failed"
	CodeConfirmed   = "step.payment.confirmed"
	CodeUnavailable = "step.payment.unavailable"
	CodeRefunded    = "step.payment.refunded"
	codeTitle       = "step.payment.title"
)

const (
	// fetchInterval throttles provider lookups per payment: status pages and API
	// clients may ask every few seconds, the provider must not be asked that often.
	fetchInterval = 10 * time.Second
	// abandonAfter is when an open payment stops being polled: the user never paid
	// and the provider never said so.
	abandonAfter = 30 * 24 * time.Hour
	// maxWebhookBody bounds what a callback may send.
	maxWebhookBody = 1 << 20
	// refundCheckInterval throttles the background re-check of a credited payment
	// for a refund; a webhook re-checks at once.
	refundCheckInterval = time.Hour
)

//go:embed html/payment.html
var pageFS embed.FS

var pageTemplate = template.Must(template.ParseFS(pageFS, "html/payment.html"))

// stepConfig is the step's own keys.
type stepConfig struct {
	// Title overrides the step's label per language, e.g. {en: "Membership"}.
	Title map[string]string `yaml:"title"`
	// Renewable reopens the step when access expires. *bool, defaults on.
	Renewable *bool `yaml:"renewable"`
	// RefundWindowDays keeps re-checking a credited payment for this many days, and
	// takes its access back when the provider reports it refunded or cancelled. 0
	// (the default) never re-checks a payment once it is credited.
	RefundWindowDays int                  `yaml:"refundWindowDays"`
	Plans            []Plan               `yaml:"plans"`
	Providers        map[string]yaml.Node `yaml:"providers"`
}

// Step is the payment step.
type Step struct {
	id        string
	title     map[string]string
	renewable bool
	plans     []Plan
	providers map[string]Provider
	order     []string // provider names, sorted, for a stable page
	host      accounts.Host
	checkouts *ratelimit.Limiter
	// refundWindow is how long after crediting a payment is re-checked; 0 = never.
	refundWindow time.Duration

	mu        sync.Mutex
	lastFetch map[uint64]time.Time
}

// NewFactory returns the step factory for the given providers. Register it as
// TypeName.
func NewFactory(providers Providers) accounts.StepFactory {
	return func(cfg config.AccountStepConfig, deps accounts.Deps) (accounts.Step, error) {
		return New(cfg, deps, providers)
	}
}

// New builds the step from its config entry.
func New(cfg config.AccountStepConfig, deps accounts.Deps, providers Providers) (*Step, error) {
	var sc stepConfig
	if err := cfg.Decode(&sc); err != nil {
		return nil, err
	}
	s := &Step{
		id:        cfg.ID,
		title:     sc.Title,
		renewable: sc.Renewable == nil || *sc.Renewable,
		providers: map[string]Provider{},
		host:      deps.Host,
		checkouts: ratelimit.New(6),
		lastFetch: map[uint64]time.Time{},
	}
	if sc.RefundWindowDays < 0 {
		return nil, errors.New("refundWindowDays must not be negative; 0 disables refund checks")
	}
	s.refundWindow = time.Duration(sc.RefundWindowDays) * 24 * time.Hour
	for name, node := range sc.Providers {
		var common struct {
			Enabled *bool `yaml:"enabled"`
		}
		if err := node.Decode(&common); err != nil {
			return nil, fmt.Errorf("providers.%s: %w", name, err)
		}
		if common.Enabled != nil && !*common.Enabled {
			continue
		}
		factory, ok := providers[name]
		if !ok {
			return nil, fmt.Errorf("providers.%s: unknown payment provider (known: %s)", name, knownProviders(providers))
		}
		p, err := factory(node, deps)
		if err != nil {
			return nil, fmt.Errorf("providers.%s: %w", name, err)
		}
		s.providers[name] = p
		s.order = append(s.order, name)
	}
	sort.Strings(s.order)
	if len(s.providers) == 0 {
		return nil, errors.New("no payment provider is enabled")
	}
	seen := map[string]bool{}
	for i, plan := range sc.Plans {
		if plan.ID == "" || seen[plan.ID] {
			return nil, fmt.Errorf("plans[%d]: id %q is empty or used twice", i, plan.ID)
		}
		seen[plan.ID] = true
		sellable := false
		for name := range s.providers {
			if plan.ProviderRefs[name] != "" {
				sellable = true
			}
		}
		if !sellable {
			return nil, fmt.Errorf("plans[%d] (%s): no providerRefs entry for any enabled provider (%v)", i, plan.ID, s.order)
		}
		if plan.Title == "" {
			plan.Title = plan.ID
		}
		s.plans = append(s.plans, plan)
	}
	if len(s.plans) == 0 {
		return nil, errors.New("no plans configured")
	}
	return s, nil
}

func (s *Step) ID() string              { return s.id }
func (s *Step) Kind() accounts.StepKind { return accounts.StepKindPayment }
func (s *Step) Durable() bool           { return true }
func (s *Step) Renewable() bool         { return s.renewable }

// Title returns the configured label for lang, or the translated default.
func (s *Step) Title(lang string) string {
	if t := s.title[lang]; t != "" {
		return t
	}
	if t := s.title[locales.Default]; t != "" {
		return t
	}
	return locales.T(lang, codeTitle)
}

// Check reconciles the account's open payments for this step and reports where the
// step stands. A payment found paid grants its period here, via reconcile.
func (s *Step) Check(ctx context.Context, acct storage.Account, _ storage.AccountStep) (accounts.StepResult, error) {
	payments, err := s.host.Store().PaymentsByAccount(ctx, acct.ID, 20)
	if err != nil {
		return accounts.StepResult{Status: storage.StepPending, MsgCode: CodeRequired}, err
	}
	var firstErr error
	code := CodeRequired
	for i := len(payments) - 1; i >= 0; i-- { // oldest first
		p := payments[i]
		if p.StepID != s.id {
			continue
		}
		credited, err := s.reconcile(ctx, &p, false)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		switch {
		case credited:
			return accounts.StepResult{Status: storage.StepDone}, nil
		case p.Status.Open():
			code = CodePending
		case !p.RevokedAt.IsZero():
			if code == CodeRequired {
				code = CodeRefunded
			}
		case p.Status == storage.PaymentFailed || p.Status == storage.PaymentCancelled:
			if code != CodePending {
				code = CodeFailed
			}
		}
	}
	return accounts.StepResult{Status: storage.StepPending, MsgCode: code}, firstErr
}

// Poll reconciles every open payment of this step, gives up on ones abandoned long
// ago, and re-checks recently credited ones for refunds when that is on.
func (s *Step) Poll(ctx context.Context) {
	s.pollRefunds(ctx)
	payments, err := s.host.Store().OpenPayments(ctx, 500)
	if err != nil {
		logging.Warnf("payment %s: list open payments: %v", s.id, err)
		return
	}
	for _, p := range payments {
		if p.StepID != s.id {
			continue
		}
		if s.host.Now().Sub(p.CreatedAt) > abandonAfter {
			p.Status = storage.PaymentCancelled
			if err := s.host.Store().UpdatePayment(ctx, &p); err != nil {
				logging.Warnf("payment %s: abandon payment %d: %v", s.id, p.ID, err)
			}
			continue
		}
		if _, err := s.reconcile(ctx, &p, false); err != nil {
			logging.Warnf("payment %s: reconcile payment %d: %v", s.id, p.ID, err)
		}
	}
}

// Routes mounts the plan page, the checkout, the provider return, a manual refresh
// and the provider webhooks.
func (s *Step) Routes(mux *http.ServeMux, portal accounts.Portal) {
	base := accounts.StepPath(s.id)
	mux.HandleFunc("GET "+base+"{$}", func(w http.ResponseWriter, r *http.Request) { s.handlePage(w, r, portal) })
	mux.HandleFunc("POST "+base+"checkout", func(w http.ResponseWriter, r *http.Request) { s.handleCheckout(w, r, portal) })
	mux.HandleFunc("GET "+base+"return", func(w http.ResponseWriter, r *http.Request) { s.handleReturn(w, r, portal) })
	mux.HandleFunc("POST "+base+"refresh", func(w http.ResponseWriter, r *http.Request) { s.handleRefresh(w, r, portal) })
	mux.HandleFunc("POST "+base+"hook/{provider}", s.handleWebhook)
}

// Reconcile re-fetches one payment by its provider id and grants it if paid. It is
// what every path converges on: return URL, webhook, status checks and the poller.
func (s *Step) Reconcile(ctx context.Context, provider, externalID string) error {
	p, err := s.host.Store().PaymentByExternal(ctx, provider, externalID)
	if err != nil {
		return err
	}
	if p.StepID != s.id {
		return nil
	}
	_, err = s.reconcile(ctx, &p, true)
	return err
}

func (s *Step) handlePage(w http.ResponseWriter, r *http.Request, portal accounts.Portal) {
	acct, ok := portal.Account(r)
	if !ok {
		portal.Redirect(w, r, "/account/login", "")
		return
	}
	lang := portal.Lang(r)
	type planRow struct {
		ID         string
		Title      string
		PeriodDays uint32
	}
	type providerRow struct{ Name, Title string }
	type paymentRow struct{ Date, Plan, Amount, Status, Class string }
	var plans []planRow
	for _, p := range s.plans {
		row := planRow{ID: p.ID, Title: p.Title}
		if p.Title == p.ID { // no title configured: say what it buys
			row.PeriodDays = p.PeriodDays
		}
		plans = append(plans, row)
	}
	var providers []providerRow
	for _, name := range s.order {
		providers = append(providers, providerRow{Name: name, Title: s.providers[name].Title(lang)})
	}
	var rows []paymentRow
	hasOpen := false
	if list, err := s.host.Store().PaymentsByAccount(r.Context(), acct.ID, 10); err == nil {
		for _, p := range list {
			if p.StepID != s.id {
				continue
			}
			class := ""
			switch {
			case p.Status == storage.PaymentPaid:
				class = "ok"
			case p.Status.Open():
				hasOpen = true
			default:
				class = "err"
			}
			amount := p.Amount
			if amount != "" && p.Currency != "" {
				amount += " " + p.Currency
			}
			rows = append(rows, paymentRow{Date: p.CreatedAt.UTC().Format("2006-01-02"), Plan: s.planTitle(p.PlanID),
				Amount: amount, Status: p.Status.String(), Class: class})
		}
	}
	var buf bytes.Buffer
	err := pageTemplate.ExecuteTemplate(&buf, "payment", map[string]any{
		"T":         func(code string) string { return locales.T(lang, code) },
		"CSRF":      portal.CSRFField(r),
		"Path":      accounts.StepPath(s.id),
		"Plans":     plans,
		"Providers": providers,
		"Payments":  rows,
		"HasOpen":   hasOpen,
	})
	if err != nil {
		logging.Errorf("payment %s: render: %v", s.id, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	portal.Render(w, r, s.Title(lang), template.HTML(buf.String()), "")
}

func (s *Step) handleCheckout(w http.ResponseWriter, r *http.Request, portal accounts.Portal) {
	acct, ok := portal.Account(r)
	if !ok {
		portal.Redirect(w, r, "/account/login", "")
		return
	}
	page := accounts.StepPath(s.id)
	if !portal.CheckCSRF(r) {
		portal.Redirect(w, r, page, accounts.CodeInvalidForm)
		return
	}
	if !s.checkouts.Allow(strconv.FormatUint(acct.ID, 10)) {
		portal.Redirect(w, r, page, accounts.CodeRateLimited)
		return
	}
	plan, okPlan := s.plan(r.PostFormValue("plan"))
	provider, okProvider := s.providers[r.PostFormValue("provider")]
	if !okPlan || !okProvider || plan.ProviderRefs[provider.Name()] == "" {
		portal.Redirect(w, r, page, accounts.CodeInvalidForm)
		return
	}
	payment := storage.Payment{AccountID: acct.ID, StepID: s.id, PlanID: plan.ID, Provider: provider.Name(),
		Status: storage.PaymentCreated, PeriodDays: plan.PeriodDays}
	if err := s.host.Store().CreatePayment(r.Context(), &payment); err != nil {
		logging.Errorf("payment %s: store payment for account %d: %v", s.id, acct.ID, err)
		portal.Redirect(w, r, page, accounts.CodeServerError)
		return
	}
	returnURL := portal.URL(page + "return?payment=" + strconv.FormatUint(payment.ID, 10))
	checkout, err := provider.Checkout(r.Context(), CheckoutRequest{
		Account: acct, Payment: payment, Plan: plan, ProviderRef: plan.ProviderRefs[provider.Name()], ReturnURL: returnURL,
	})
	if err != nil {
		logging.Errorf("payment %s: %s checkout for account %d (payment %d): %v", s.id, provider.Name(), acct.ID, payment.ID, err)
		payment.Status = storage.PaymentFailed
		_ = s.host.Store().UpdatePayment(r.Context(), &payment)
		portal.Redirect(w, r, page, CodeUnavailable)
		return
	}
	payment.ExternalID, payment.ExternalKey = checkout.ExternalID, checkout.ExternalKey
	payment.Amount, payment.Currency = checkout.Amount, checkout.Currency
	payment.Status = storage.PaymentPending
	if err := s.host.Store().UpdatePayment(r.Context(), &payment); err != nil {
		logging.Errorf("payment %s: record %s order %s for payment %d: %v", s.id, provider.Name(), checkout.ExternalID, payment.ID, err)
		portal.Redirect(w, r, page, accounts.CodeServerError)
		return
	}
	logging.Infof("payment %s: account %d opened %s order %s (payment %d, plan %s)",
		s.id, acct.ID, provider.Name(), checkout.ExternalID, payment.ID, plan.ID)
	http.Redirect(w, r, checkout.RedirectURL, http.StatusSeeOther)
}

func (s *Step) handleReturn(w http.ResponseWriter, r *http.Request, portal accounts.Portal) {
	acct, ok := portal.Account(r)
	if !ok {
		portal.Redirect(w, r, "/account/login", "")
		return
	}
	id, _ := strconv.ParseUint(r.URL.Query().Get("payment"), 10, 64)
	p, err := s.host.Store().PaymentByID(r.Context(), id)
	if err != nil || p.AccountID != acct.ID || p.StepID != s.id {
		portal.Redirect(w, r, "/account", "")
		return
	}
	credited, err := s.reconcile(r.Context(), &p, true)
	switch {
	case err != nil:
		portal.Redirect(w, r, "/account", CodeUnavailable)
	case credited || p.Status == storage.PaymentPaid:
		portal.Redirect(w, r, "/account", CodeConfirmed)
	case p.Status.Open():
		portal.Redirect(w, r, "/account", CodePending)
	default:
		portal.Redirect(w, r, "/account", CodeFailed)
	}
}

func (s *Step) handleRefresh(w http.ResponseWriter, r *http.Request, portal accounts.Portal) {
	acct, ok := portal.Account(r)
	if !ok {
		portal.Redirect(w, r, "/account/login", "")
		return
	}
	page := accounts.StepPath(s.id)
	if !portal.CheckCSRF(r) {
		portal.Redirect(w, r, page, accounts.CodeInvalidForm)
		return
	}
	if _, err := s.Check(r.Context(), acct, storage.AccountStep{}); err != nil {
		portal.Redirect(w, r, page, CodeUnavailable)
		return
	}
	portal.Redirect(w, r, "/account", "")
}

func (s *Step) handleWebhook(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.providers[r.PathValue("provider")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	externalID, err := provider.Webhook(r, body)
	switch {
	case errors.Is(err, ErrNoWebhook):
		http.NotFound(w, r)
		return
	case errors.Is(err, ErrIgnoreWebhook):
		w.WriteHeader(http.StatusOK)
		return
	case errors.Is(err, ErrBadSignature):
		logging.Warnf("payment %s: %s webhook with a bad signature from %s", s.id, provider.Name(), r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	case err != nil:
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.Reconcile(r.Context(), provider.Name(), externalID); err != nil && !errors.Is(err, storage.ErrPaymentNotFound) {
		// The provider retries a failed delivery, which is what we want.
		logging.Warnf("payment %s: %s webhook for %s: %v", s.id, provider.Name(), externalID, err)
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// reconcile fetches p from its provider when due (always when force), stores a
// changed status, and grants the plan once when p is paid. It reports whether this
// call granted it. p is updated in place.
func (s *Step) reconcile(ctx context.Context, p *storage.Payment, force bool) (bool, error) {
	if p.ExternalID == "" {
		return false, nil
	}
	if p.Status == storage.PaymentPaid && !p.CreditedAt.IsZero() {
		return false, s.recheckRefund(ctx, p, force)
	}
	if p.Status == storage.PaymentPaid {
		return s.credit(ctx, p)
	}
	if !p.Status.Open() || !s.due(p.ID, force, fetchInterval) {
		return false, nil
	}
	provider, ok := s.providers[p.Provider]
	if !ok {
		return false, nil // provider switched off since; leave the row alone
	}
	res, err := provider.Fetch(ctx, *p)
	if err != nil {
		return false, fmt.Errorf("%s fetch %s: %w", p.Provider, p.ExternalID, err)
	}
	if res.Status != p.Status || (res.Amount != "" && res.Amount != p.Amount) {
		p.Status = res.Status
		if res.Amount != "" {
			p.Amount, p.Currency = res.Amount, res.Currency
		}
		if err := s.host.Store().UpdatePayment(ctx, p); err != nil {
			return false, err
		}
		logging.Infof("payment %s: payment %d (%s %s) is %s", s.id, p.ID, p.Provider, p.ExternalID, p.Status)
	}
	if p.Status != storage.PaymentPaid {
		return false, nil
	}
	return s.credit(ctx, p)
}

// credit grants a paid payment's period exactly once.
func (s *Step) credit(ctx context.Context, p *storage.Payment) (bool, error) {
	if !p.CreditedAt.IsZero() {
		return false, nil
	}
	won, err := s.host.Store().MarkPaymentCredited(ctx, p.ID, s.host.Now())
	if err != nil || !won {
		return false, err
	}
	if err := s.host.GrantAccess(ctx, p.AccountID, s.id, p.PeriodDays); err != nil {
		// The payment is marked credited but the grant failed: an operator has to
		// finish it, so say exactly what is owed.
		logging.Errorf("payment %s: payment %d (%s %s) is paid and marked credited, but granting %d days to account %d failed: %v",
			s.id, p.ID, p.Provider, p.ExternalID, p.PeriodDays, p.AccountID, err)
		return false, err
	}
	p.CreditedAt = s.host.Now()
	return true, nil
}

// recheckRefund asks the provider about a credited payment still inside the refund
// window, and takes its access back once if the provider reports it undone.
func (s *Step) recheckRefund(ctx context.Context, p *storage.Payment, force bool) error {
	if s.refundWindow <= 0 || !p.RevokedAt.IsZero() || s.host.Now().Sub(p.CreditedAt) > s.refundWindow {
		return nil
	}
	if !s.due(p.ID, force, refundCheckInterval) {
		return nil
	}
	provider, ok := s.providers[p.Provider]
	if !ok {
		return nil
	}
	res, err := provider.Fetch(ctx, *p)
	if err != nil {
		return fmt.Errorf("%s refund check %s: %w", p.Provider, p.ExternalID, err)
	}
	switch res.Status {
	case storage.PaymentRefunded, storage.PaymentCancelled, storage.PaymentFailed:
	default:
		return nil
	}
	p.Status = res.Status
	if err := s.host.Store().UpdatePayment(ctx, p); err != nil {
		return err
	}
	won, err := s.host.Store().MarkPaymentRevoked(ctx, p.ID, s.host.Now())
	if err != nil || !won {
		return err
	}
	logging.Infof("payment %s: payment %d (%s %s) was %s after crediting; revoking %d days from account %d",
		s.id, p.ID, p.Provider, p.ExternalID, p.Status, p.PeriodDays, p.AccountID)
	if err := s.host.RevokeAccess(ctx, p.AccountID, s.id, p.PeriodDays); err != nil {
		logging.Errorf("payment %s: payment %d is marked revoked, but taking %d days from account %d failed: %v",
			s.id, p.ID, p.PeriodDays, p.AccountID, err)
		return err
	}
	p.RevokedAt = s.host.Now()
	return nil
}

// pollRefunds re-checks this step's payments credited within the refund window.
func (s *Step) pollRefunds(ctx context.Context) {
	if s.refundWindow <= 0 {
		return
	}
	payments, err := s.host.Store().CreditedPayments(ctx, s.host.Now().Add(-s.refundWindow), 500)
	if err != nil {
		logging.Warnf("payment %s: list credited payments: %v", s.id, err)
		return
	}
	for _, p := range payments {
		if p.StepID != s.id {
			continue
		}
		if _, err := s.reconcile(ctx, &p, false); err != nil {
			logging.Warnf("payment %s: refund check of payment %d: %v", s.id, p.ID, err)
		}
	}
}

// due reports whether a payment may be fetched again after interval, and records
// the attempt.
func (s *Step) due(paymentID uint64, force bool, interval time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.host.Now()
	if last, ok := s.lastFetch[paymentID]; ok && !force && now.Sub(last) < interval {
		return false
	}
	s.lastFetch[paymentID] = now
	if len(s.lastFetch) > 10000 {
		for id, t := range s.lastFetch {
			if now.Sub(t) > refundCheckInterval {
				delete(s.lastFetch, id)
			}
		}
	}
	return true
}

func (s *Step) plan(id string) (Plan, bool) {
	for _, p := range s.plans {
		if p.ID == id {
			return p, true
		}
	}
	return Plan{}, false
}

func (s *Step) planTitle(id string) string {
	if p, ok := s.plan(id); ok {
		return p.Title
	}
	return id
}

func knownProviders(p Providers) string {
	names := make([]string, 0, len(p))
	for n := range p {
		names = append(names, n)
	}
	sort.Strings(names)
	return fmt.Sprint(names)
}
