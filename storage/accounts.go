package storage

import (
	"context"
	"errors"
	"time"
)

// Accounts back the optional login on the client-facing Meta API (docs/meta-api.md).
// They live beside the eD2K tables but behind their own interface, AccountStore, so
// the Engine interface every search and login goes through is unchanged, and an
// engine that does not persist (memory) can be told apart by the caller.
//
// Nothing here is specific to one registration step or payment provider: a step
// keeps its own state in AccountStep.Data, and every provider's orders or invoices
// are Payment rows told apart by Provider. Adding a step type or a provider needs no
// schema change.

// AccountState mirrors enode.meta.v1.AccountState, so the numbers are the wire values.
type AccountState uint8

const (
	AccountPending  AccountState = 1
	AccountActive   AccountState = 2
	AccountExpired  AccountState = 3
	AccountDisabled AccountState = 4
)

// String returns the state's name, as used in logs and the dashboard.
func (s AccountState) String() string {
	switch s {
	case AccountPending:
		return "pending"
	case AccountActive:
		return "active"
	case AccountExpired:
		return "expired"
	case AccountDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}

// StepStatus is where one registration step stands for one account.
type StepStatus uint8

const (
	StepPending StepStatus = 0
	StepDone    StepStatus = 1
	StepFailed  StepStatus = 2
	StepSkipped StepStatus = 3
)

// String returns the status's name.
func (s StepStatus) String() string {
	switch s {
	case StepPending:
		return "pending"
	case StepDone:
		return "done"
	case StepFailed:
		return "failed"
	case StepSkipped:
		return "skipped"
	default:
		return "unknown"
	}
}

// ParseAccountState is the inverse of AccountState.String; "" and unknown names
// give 0, which lists every state.
func ParseAccountState(name string) AccountState {
	for _, st := range []AccountState{AccountPending, AccountActive, AccountExpired, AccountDisabled} {
		if st.String() == name {
			return st
		}
	}
	return 0
}

// PaymentStatus is a provider-neutral payment state. A provider maps its own
// vocabulary (a WooCommerce order status, an invoice state) onto these.
type PaymentStatus uint8

const (
	// PaymentCreated: the row exists, the provider has not confirmed a checkout yet.
	PaymentCreated PaymentStatus = 0
	// PaymentPending: the provider holds an order or invoice awaiting payment.
	PaymentPending   PaymentStatus = 1
	PaymentPaid      PaymentStatus = 2
	PaymentFailed    PaymentStatus = 3
	PaymentCancelled PaymentStatus = 4
	PaymentRefunded  PaymentStatus = 5
)

// String returns the status's name.
func (s PaymentStatus) String() string {
	switch s {
	case PaymentCreated:
		return "created"
	case PaymentPending:
		return "pending"
	case PaymentPaid:
		return "paid"
	case PaymentFailed:
		return "failed"
	case PaymentCancelled:
		return "cancelled"
	case PaymentRefunded:
		return "refunded"
	default:
		return "unknown"
	}
}

// Open reports whether the payment may still become paid.
func (s PaymentStatus) Open() bool { return s == PaymentCreated || s == PaymentPending }

// Account is one registered user. Username is stored normalized (lower case); the
// caller normalizes before every lookup.
type Account struct {
	ID           uint64
	Username     string
	Email        string
	PasswordHash string
	State        AccountState
	// AccessUntil is when access granted by a renewable step (a paid period) ends.
	// Zero means access does not expire.
	AccessUntil time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// AccountStep is one account's progress through one configured step, keyed by
// (AccountID, StepID).
type AccountStep struct {
	ID        uint64
	AccountID uint64
	// StepID is the step's id from the config, e.g. "payment".
	StepID string
	Status StepStatus
	// Data is the step's own state, opaque to the store (JSON by convention).
	Data        []byte
	CompletedAt time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Payment is one order or invoice at one payment provider. (Provider, ExternalID) is
// unique once ExternalID is set.
type Payment struct {
	ID        uint64
	AccountID uint64
	StepID    string
	PlanID    string
	// Provider names the backend, e.g. "woocommerce".
	Provider string
	// ExternalID and ExternalKey are the provider's identifiers, e.g. a WooCommerce
	// order id and order key. Empty until the checkout has been created.
	ExternalID  string
	ExternalKey string
	Status      PaymentStatus
	Amount      string
	Currency    string
	PeriodDays  uint32
	// CreditedAt is set once, when the payment's access was granted. It is what makes
	// crediting idempotent however many paths observe the payment as paid.
	CreditedAt time.Time
	// RevokedAt is set once, when a credited payment was refunded or cancelled and
	// its access taken back. Same exactly-once role as CreditedAt.
	RevokedAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AccountFilter selects accounts to list.
type AccountFilter struct {
	// State 0 lists every state.
	State AccountState
	// Search matches a substring of the username or email, ignoring case. Empty
	// matches all.
	Search string
}

// AccountSession is one login: a website cookie or an API bearer token. Only the
// SHA-256 of the token is stored.
type AccountSession struct {
	ID        uint64
	AccountID uint64
	TokenHash []byte
	// Client names what logged in, e.g. "web" or "eMuleQt 0.3.1".
	Client    string
	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Errors an AccountStore returns.
var (
	ErrAccountNotFound  = errors.New("storage: account not found")
	ErrUsernameTaken    = errors.New("storage: username already registered")
	ErrPaymentNotFound  = errors.New("storage: payment not found")
	ErrPaymentDuplicate = errors.New("storage: payment already recorded for that provider id")
	ErrSessionNotFound  = errors.New("storage: session not found")
)

// AccountStore persists accounts, their step progress, payments and sessions. The
// memory, MySQL and MongoDB engines implement it. Every method takes a context so a
// slow database costs the one request, not a server goroutine forever.
type AccountStore interface {
	// DurableAccounts reports whether accounts survive a restart. The memory engine
	// says false, and paid steps refuse to run on it.
	DurableAccounts() bool
	// InitAccounts prepares the account tables or collections. It is idempotent and
	// runs at startup only when accounts are enabled.
	InitAccounts(ctx context.Context) error

	// CreateAccount inserts a and sets its ID and timestamps. It returns
	// ErrUsernameTaken when the username exists.
	CreateAccount(ctx context.Context, a *Account) error
	AccountByID(ctx context.Context, id uint64) (Account, error)
	AccountByUsername(ctx context.Context, username string) (Account, error)
	// UpdateAccount writes every mutable field of a (not ID, Username, CreatedAt) and
	// sets UpdatedAt.
	UpdateAccount(ctx context.Context, a *Account) error
	// CountAccounts returns how many accounts are in each state.
	CountAccounts(ctx context.Context) (map[AccountState]int, error)
	// ListAccounts pages through the accounts matching filter, newest first.
	ListAccounts(ctx context.Context, filter AccountFilter, limit, offset int) ([]Account, error)

	// AccountSteps returns every step record of one account.
	AccountSteps(ctx context.Context, accountID uint64) ([]AccountStep, error)
	// UpsertAccountStep inserts or replaces the record for (AccountID, StepID) and
	// sets its ID and timestamps.
	UpsertAccountStep(ctx context.Context, s *AccountStep) error

	// CreatePayment inserts p and sets its ID and timestamps.
	CreatePayment(ctx context.Context, p *Payment) error
	// UpdatePayment writes ExternalID, ExternalKey, Status, Amount and Currency. It
	// returns ErrPaymentDuplicate when (Provider, ExternalID) belongs to another row.
	// It never touches CreditedAt or RevokedAt; the Mark* methods own those.
	UpdatePayment(ctx context.Context, p *Payment) error
	PaymentByID(ctx context.Context, id uint64) (Payment, error)
	PaymentByExternal(ctx context.Context, provider, externalID string) (Payment, error)
	// OpenPayments returns up to limit payments still created or pending, oldest
	// first, for the background reconciler.
	OpenPayments(ctx context.Context, limit int) ([]Payment, error)
	// PaymentsByAccount returns an account's payments, newest first.
	PaymentsByAccount(ctx context.Context, accountID uint64, limit int) ([]Payment, error)
	// MarkPaymentCredited sets CreditedAt if it is unset and reports whether this
	// call set it. Exactly one caller wins, whatever the concurrency.
	MarkPaymentCredited(ctx context.Context, id uint64, at time.Time) (bool, error)
	// MarkPaymentRevoked sets RevokedAt on a credited payment if it is unset and
	// reports whether this call set it. Exactly one caller wins.
	MarkPaymentRevoked(ctx context.Context, id uint64, at time.Time) (bool, error)
	// CreditedPayments returns up to limit payments credited at or after since and
	// not revoked, newest credit first, for refund checks.
	CreditedPayments(ctx context.Context, since time.Time, limit int) ([]Payment, error)

	CreateSession(ctx context.Context, s *AccountSession) error
	// SessionByTokenHash returns the session, expired or not; the caller checks.
	SessionByTokenHash(ctx context.Context, tokenHash []byte) (AccountSession, error)
	DeleteSession(ctx context.Context, id uint64) error
	// DeleteExpiredSessions removes sessions that expired before now and returns how
	// many it removed.
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int, error)
}

// Every engine is an AccountStore.
var (
	_ AccountStore = (*MemoryEngine)(nil)
	_ AccountStore = (*MySQLEngine)(nil)
	_ AccountStore = (*MongoDBEngine)(nil)
)
