// Package payment is the "payment" registration step: the user picks a plan and a
// payment provider, is sent to the provider's checkout, and the account is granted
// the plan's period once the provider confirms the payment.
//
// The step knows nothing about any provider. A provider — WooCommerce is the first
// (accounts/payment/woocommerce) — implements Provider and is registered by name in
// Providers; adding Stripe, BTCPay or anything else means one more implementation,
// not a change here, in the account core, in the schema or in the contract.
package payment

import (
	"context"
	"errors"
	"net/http"

	"enode/accounts"
	"enode/storage"

	"gopkg.in/yaml.v3"
)

// Provider is one payment backend.
type Provider interface {
	// Name is the provider's key in the config and in storage.Payment.Provider,
	// e.g. "woocommerce". It appears in the webhook URL.
	Name() string
	// Title is what the user picks from, in lang.
	Title(lang string) string
	// Checkout opens an order or invoice for one payment and returns where to send
	// the user to pay it.
	Checkout(ctx context.Context, req CheckoutRequest) (Checkout, error)
	// Fetch asks the provider where a payment stands. It is the only source of truth:
	// a return URL or a webhook only says which payment to fetch.
	Fetch(ctx context.Context, p storage.Payment) (FetchResult, error)
	// Webhook verifies a provider callback and returns the external id of the
	// payment it is about. It returns ErrNoWebhook when the provider has none, and
	// ErrIgnoreWebhook for a valid callback that concerns no payment (a ping).
	Webhook(r *http.Request, body []byte) (externalID string, err error)
}

// CheckoutRequest is one checkout to open.
type CheckoutRequest struct {
	Account storage.Account
	// Payment is the already stored row; its ID ties the provider's order to it.
	Payment storage.Payment
	Plan    Plan
	// ProviderRef is the plan's reference at this provider, e.g. a product id.
	ProviderRef string
	// ReturnURL is where the provider should send the user afterwards, if it can.
	ReturnURL string
}

// Checkout is an opened order or invoice.
type Checkout struct {
	ExternalID  string
	ExternalKey string
	RedirectURL string
	Amount      string
	Currency    string
}

// FetchResult is a provider's answer about one payment.
type FetchResult struct {
	Status   storage.PaymentStatus
	Amount   string
	Currency string
}

// Plan is one thing to buy: access for PeriodDays (0 = no expiry).
type Plan struct {
	ID         string `yaml:"id"`
	Title      string `yaml:"title"`
	PeriodDays uint32 `yaml:"periodDays"`
	// ProviderRefs is the plan's reference per provider, e.g. {woocommerce: "123"}
	// for a WooCommerce product id. A provider without an entry cannot sell the plan.
	ProviderRefs map[string]string `yaml:"providerRefs"`
}

// ProviderFactory builds a provider from its config node (the mapping under
// providers.<name>).
type ProviderFactory func(node yaml.Node, deps accounts.Deps) (Provider, error)

// Providers maps a provider name to its factory.
type Providers map[string]ProviderFactory

// Errors a provider returns.
var (
	ErrNoWebhook     = errors.New("payment: provider has no webhook")
	ErrIgnoreWebhook = errors.New("payment: webhook concerns no payment")
	ErrBadSignature  = errors.New("payment: webhook signature invalid")
)
