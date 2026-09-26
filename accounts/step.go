package accounts

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"time"

	"enode/config"
	"enode/storage"
)

// StepKind mirrors enode.meta.v1.StepKind, so the numbers are the wire values.
type StepKind uint8

const (
	StepKindPayment           StepKind = 1
	StepKindEmailVerification StepKind = 2
	StepKindApproval          StepKind = 3
	StepKindOther             StepKind = 4
)

// Step is one registration requirement, such as a payment. The configured steps run
// in order; an account is active once every one of them is done (or skipped) and
// its access has not expired.
//
// A step owns its own portal pages under StepPath(ID()) and its own state, in
// storage.AccountStep.Data or elsewhere. To mark itself done it calls
// Host.CompleteStep, or Host.GrantAccess when it also buys time.
type Step interface {
	// ID is the step's id from the config, e.g. "payment". It appears in URLs.
	ID() string
	Kind() StepKind
	// Title is a short label in lang, e.g. "Payment".
	Title(lang string) string
	// Durable reports whether the step must not run on a store that loses accounts
	// on restart. Every step that takes money is durable.
	Durable() bool
	// Renewable reports whether the step reopens when the account's access expires,
	// as a subscription payment does. A one-off check (an email address) does not.
	Renewable() bool
	// Check re-evaluates an open step and reports where it stands, calling
	// Host.CompleteStep or Host.GrantAccess first when it has just been completed. It
	// may contact an external service and is called on every status request, so an
	// implementation throttles its own outbound calls. MsgCode says what the user
	// should be told about an open step.
	Check(ctx context.Context, acct storage.Account, rec storage.AccountStep) (StepResult, error)
	// Routes mounts the step's pages under StepPath(ID()).
	Routes(mux *http.ServeMux, portal Portal)
}

// Poller is implemented by a step with outstanding work to reconcile in the
// background, such as payments whose provider never called back.
type Poller interface {
	Poll(ctx context.Context)
}

// StepResult is what Check found.
type StepResult struct {
	Status  storage.StepStatus
	MsgCode string
}

// Host is what a step may do to an account. The Service implements it.
type Host interface {
	Store() storage.AccountStore
	// CompleteStep marks stepID done for the account and re-evaluates its state.
	CompleteStep(ctx context.Context, accountID uint64, stepID string) error
	// GrantAccess marks stepID done and extends the account's access by days, counted
	// from now or from the end of the current period, whichever is later; 0 days
	// removes the expiry. The caller must make sure one purchase is granted once
	// (storage.MarkPaymentCredited).
	GrantAccess(ctx context.Context, accountID uint64, stepID string, days uint32) error
	// ResetStep marks stepID pending again.
	ResetStep(ctx context.Context, accountID uint64, stepID string) error
	// RevokeAccess takes back days granted by stepID, as for a refunded purchase: the
	// access end moves back by days (0 = the grant had no expiry, so access ends
	// now), and the step reopens once access has run out. The caller makes sure one
	// purchase is revoked once (storage.MarkPaymentRevoked).
	RevokeAccess(ctx context.Context, accountID uint64, stepID string, days uint32) error
	Now() time.Time
}

// Portal is what a step's pages may use of the account website.
type Portal interface {
	// Account returns the logged-in account of the request, if any.
	Account(r *http.Request) (storage.Account, bool)
	// Lang is the request's negotiated language.
	Lang(r *http.Request) string
	// Render writes a page: the site layout around body, with an optional MsgCode
	// shown as a notice.
	Render(w http.ResponseWriter, r *http.Request, title string, body template.HTML, noticeCode string)
	// CSRFField is the hidden form field a POST form must include.
	CSRFField(r *http.Request) template.HTML
	// CheckCSRF validates a POST form's CSRF field.
	CheckCSRF(r *http.Request) bool
	// Redirect sends the browser to a site path, optionally with a notice MsgCode.
	Redirect(w http.ResponseWriter, r *http.Request, path, noticeCode string)
	// URL is the absolute public URL of a site path, for a provider's return link.
	URL(path string) string
	// ClientIP is the request's client address, for rate limits.
	ClientIP(r *http.Request) string
}

// Deps is what a step factory receives.
type Deps struct {
	Host Host
	// HTTPClient is for calls to external services, with a sensible timeout.
	HTTPClient *http.Client
}

// StepFactory builds a step from its config entry. It validates the entry's own keys
// and returns an error naming them.
type StepFactory func(cfg config.AccountStepConfig, deps Deps) (Step, error)

// Registry maps a step type name, the `type:` of a config entry, to its factory.
type Registry map[string]StepFactory

// Register adds a step type. It panics on a duplicate name: that is a wiring bug.
func (r Registry) Register(typ string, f StepFactory) {
	if _, dup := r[typ]; dup {
		panic(fmt.Sprintf("accounts: step type %q registered twice", typ))
	}
	r[typ] = f
}

// Types lists the registered type names, sorted.
func (r Registry) Types() []string {
	out := make([]string, 0, len(r))
	for t := range r {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// StepPath is the site path under which a step's pages live.
func StepPath(stepID string) string { return "/account/step/" + stepID + "/" }
