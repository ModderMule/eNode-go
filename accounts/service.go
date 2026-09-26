package accounts

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"time"

	"enode/config"
	"enode/logging"
	"enode/storage"
)

// Config is the service's share of metaApi.accounts.
type Config struct {
	// PublicURL is the website's base URL, without a trailing slash.
	PublicURL         string
	AllowRegistration bool
	SessionTTL        time.Duration
	MinPasswordLength int
	PollInterval      time.Duration
}

// ConfigFrom converts the config section.
func ConfigFrom(c config.AccountsConfig) Config {
	return Config{
		PublicURL:         strings.TrimRight(c.PublicURL, "/"),
		AllowRegistration: c.AllowRegistrationOrDefault(),
		SessionTTL:        time.Duration(c.SessionTTLHours) * time.Hour,
		MinPasswordLength: c.MinPasswordLength,
		PollInterval:      time.Duration(c.PollSeconds) * time.Second,
	}
}

// Status is an account's evaluated state: what AccountApi.GetAuthStatus reports.
type Status struct {
	State       storage.AccountState
	AccessUntil time.Time
	MsgCode     string
	// Pending are the open steps, in configured order.
	Pending []PendingStep
}

// Active reports whether the account may use the API.
func (s Status) Active() bool { return s.State == storage.AccountActive }

// PendingStep is one open step as shown to a user.
type PendingStep struct {
	ID      string
	Kind    StepKind
	Title   string
	URL     string
	MsgCode string
}

// Service is the account system: one per server.
type Service struct {
	cfg   Config
	store storage.AccountStore
	steps []Step
	now   func() time.Time
	// accountLocks serialize every read-modify-write of one account (striped): grants,
	// revocations, operator actions and the state Evaluate stores. Without them two
	// payments credited at once could both read the old period and one extension be
	// lost, or Evaluate could write back a stale access end.
	accountLocks [64]sync.Mutex
}

// usernamePattern is applied after lower-casing.
var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)

// New builds the service and every enabled step in stepCfgs, in order. It fails on
// an unknown step type, on a step whose own config is invalid, and on a durable
// step over a store that is not.
func New(cfg Config, store storage.AccountStore, reg Registry, stepCfgs []config.AccountStepConfig, httpClient *http.Client) (*Service, error) {
	s := &Service{cfg: cfg, store: store, now: time.Now}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	deps := Deps{Host: s, HTTPClient: httpClient}
	for _, sc := range stepCfgs {
		if !sc.Enabled {
			continue
		}
		factory, ok := reg[sc.Type]
		if !ok {
			return nil, fmt.Errorf("metaApi.accounts.steps %q: unknown type %q (known: %s)", sc.ID, sc.Type, strings.Join(reg.Types(), ", "))
		}
		step, err := factory(sc, deps)
		if err != nil {
			return nil, fmt.Errorf("metaApi.accounts.steps %q: %w", sc.ID, err)
		}
		if step.Durable() && !store.DurableAccounts() {
			return nil, fmt.Errorf("metaApi.accounts.steps %q needs a storage engine that keeps accounts across restarts (mysql or mongodb); the memory engine would lose paid accounts", sc.ID)
		}
		s.steps = append(s.steps, step)
	}
	return s, nil
}

// SetClock replaces the clock, for tests.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Steps returns the enabled steps in order.
func (s *Service) Steps() []Step { return s.steps }

// StepTitle is a step's label in lang, or its id when no such step is configured.
func (s *Service) StepTitle(id, lang string) string {
	for _, step := range s.steps {
		if step.ID() == id {
			return step.Title(lang)
		}
	}
	return id
}

// Store returns the account store. Part of Host.
func (s *Service) Store() storage.AccountStore { return s.store }

// Now returns the current time. Part of Host.
func (s *Service) Now() time.Time { return s.now() }

// RegistrationURL is where a new user signs up.
func (s *Service) RegistrationURL() string { return s.cfg.PublicURL + "/account/register" }

// AccountURL is where a user sees and continues their account.
func (s *Service) AccountURL() string { return s.cfg.PublicURL + "/account" }

// PublicURL is the website's base URL.
func (s *Service) PublicURL() string { return s.cfg.PublicURL }

// AllowRegistration reports whether sign-up is open.
func (s *Service) AllowRegistration() bool { return s.cfg.AllowRegistration }

// MinPasswordLength is the shortest password accepted.
func (s *Service) MinPasswordLength() int { return s.cfg.MinPasswordLength }

// NormalizeUsername lower-cases and trims a username.
func NormalizeUsername(username string) string { return strings.ToLower(strings.TrimSpace(username)) }

// Register creates an account. It is pending until its steps are done, which with no
// steps configured is immediately.
func (s *Service) Register(ctx context.Context, username, email, password string) (storage.Account, error) {
	if !s.cfg.AllowRegistration {
		return storage.Account{}, NewError(KindForbidden, CodeRegistrationClosed)
	}
	username = NormalizeUsername(username)
	if !usernamePattern.MatchString(username) {
		return storage.Account{}, NewError(KindInvalid, CodeUsernameInvalid)
	}
	email = strings.TrimSpace(email)
	if email != "" {
		if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email {
			return storage.Account{}, NewError(KindInvalid, CodeEmailInvalid)
		}
	}
	if len([]rune(password)) < s.cfg.MinPasswordLength {
		return storage.Account{}, NewError(KindInvalid, CodeWeakPassword)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return storage.Account{}, WrapError(KindUnavailable, CodeServerError, err)
	}
	acct := storage.Account{Username: username, Email: email, PasswordHash: hash, State: storage.AccountPending}
	if err := s.store.CreateAccount(ctx, &acct); err != nil {
		if errors.Is(err, storage.ErrUsernameTaken) {
			return storage.Account{}, NewError(KindConflict, CodeUsernameTaken)
		}
		return storage.Account{}, WrapError(KindUnavailable, CodeServerError, err)
	}
	logging.Infof("accounts: registered %q (id=%d)", acct.Username, acct.ID)
	// Settle the initial state: with no steps the account is active at once.
	if _, err := s.Evaluate(ctx, &acct); err != nil {
		logging.Warnf("accounts: evaluate new account %d: %v", acct.ID, err)
	}
	return acct, nil
}

// CheckPassword returns the account for a correct username and password. It takes
// as long for an unknown username as for a wrong password.
func (s *Service) CheckPassword(ctx context.Context, username, password string) (storage.Account, error) {
	acct, err := s.store.AccountByUsername(ctx, NormalizeUsername(username))
	if errors.Is(err, storage.ErrAccountNotFound) {
		_, _ = VerifyPassword(dummyHash, password)
		return storage.Account{}, NewError(KindUnauthenticated, CodeInvalidCredentials)
	}
	if err != nil {
		return storage.Account{}, WrapError(KindUnavailable, CodeServerError, err)
	}
	ok, err := VerifyPassword(acct.PasswordHash, password)
	if err != nil {
		return storage.Account{}, WrapError(KindUnavailable, CodeServerError, err)
	}
	if !ok {
		return storage.Account{}, NewError(KindUnauthenticated, CodeInvalidCredentials)
	}
	return acct, nil
}

// Login checks the password and opens a session. The token is returned once and
// only its hash is stored. A login succeeds for an account that is not active, so
// its owner can see what is left to do.
func (s *Service) Login(ctx context.Context, username, password, client string) (string, storage.AccountSession, storage.Account, error) {
	acct, err := s.CheckPassword(ctx, username, password)
	if err != nil {
		return "", storage.AccountSession{}, storage.Account{}, err
	}
	token, hash, err := NewToken()
	if err != nil {
		return "", storage.AccountSession{}, storage.Account{}, WrapError(KindUnavailable, CodeServerError, err)
	}
	if len(client) > 64 {
		client = client[:64]
	}
	sess := storage.AccountSession{AccountID: acct.ID, TokenHash: hash, Client: client, ExpiresAt: s.now().Add(s.cfg.SessionTTL)}
	if err := s.store.CreateSession(ctx, &sess); err != nil {
		return "", storage.AccountSession{}, storage.Account{}, WrapError(KindUnavailable, CodeServerError, err)
	}
	return token, sess, acct, nil
}

// Authenticate resolves a session token to its account.
func (s *Service) Authenticate(ctx context.Context, token string) (storage.Account, storage.AccountSession, error) {
	if token == "" {
		return storage.Account{}, storage.AccountSession{}, NewError(KindUnauthenticated, CodeAuthRequired)
	}
	sess, err := s.store.SessionByTokenHash(ctx, TokenHash(token))
	if errors.Is(err, storage.ErrSessionNotFound) {
		return storage.Account{}, storage.AccountSession{}, NewError(KindUnauthenticated, CodeSessionExpired)
	}
	if err != nil {
		return storage.Account{}, storage.AccountSession{}, WrapError(KindUnavailable, CodeServerError, err)
	}
	if !s.now().Before(sess.ExpiresAt) {
		return storage.Account{}, storage.AccountSession{}, NewError(KindUnauthenticated, CodeSessionExpired)
	}
	acct, err := s.store.AccountByID(ctx, sess.AccountID)
	if errors.Is(err, storage.ErrAccountNotFound) {
		return storage.Account{}, storage.AccountSession{}, NewError(KindUnauthenticated, CodeSessionExpired)
	}
	if err != nil {
		return storage.Account{}, storage.AccountSession{}, WrapError(KindUnavailable, CodeServerError, err)
	}
	return acct, sess, nil
}

// Logout revokes a session token. An unknown token is not an error.
func (s *Service) Logout(ctx context.Context, token string) error {
	sess, err := s.store.SessionByTokenHash(ctx, TokenHash(token))
	if errors.Is(err, storage.ErrSessionNotFound) {
		return nil
	}
	if err != nil {
		return WrapError(KindUnavailable, CodeServerError, err)
	}
	return s.store.DeleteSession(ctx, sess.ID)
}

// Authorize reports whether acct may use the API now, evaluating its steps only
// when the stored state says it may not: an active account inside its period is the
// hot path and costs nothing.
func (s *Service) Authorize(ctx context.Context, acct *storage.Account) (Status, error) {
	if acct.State == storage.AccountActive && (acct.AccessUntil.IsZero() || s.now().Before(acct.AccessUntil)) {
		return Status{State: storage.AccountActive, AccessUntil: acct.AccessUntil}, nil
	}
	return s.Evaluate(ctx, acct)
}

// Evaluate walks the configured steps, lets each open one check itself, and settles
// and stores the account's state. acct is refreshed in place.
func (s *Service) Evaluate(ctx context.Context, acct *storage.Account) (Status, error) {
	if acct.State == storage.AccountDisabled {
		return Status{State: storage.AccountDisabled, AccessUntil: acct.AccessUntil, MsgCode: CodeDisabled}, nil
	}
	recs, err := s.stepRecords(ctx, acct.ID)
	if err != nil {
		return Status{}, WrapError(KindUnavailable, CodeServerError, err)
	}
	expired := s.expired(*acct)
	codes := map[string]string{}
	for _, step := range s.steps {
		rec := recs[step.ID()]
		// A lapsed period reopens every renewable step it had closed.
		if expired && step.Renewable() && rec.Status == storage.StepDone {
			if err := s.ResetStep(ctx, acct.ID, step.ID()); err != nil {
				return Status{}, WrapError(KindUnavailable, CodeServerError, err)
			}
			rec.Status = storage.StepPending
		}
		if isClosed(rec.Status) {
			continue
		}
		res, err := step.Check(ctx, *acct, rec)
		if err != nil {
			logging.Warnf("accounts: step %s check for account %d: %v", step.ID(), acct.ID, err)
		}
		codes[step.ID()] = res.MsgCode
		if err == nil && isClosed(res.Status) {
			// A step normally records its own completion through the Host; this
			// closes it for one that only reported it. CompleteStep keeps the
			// step's data and is harmless when the step already did it.
			if err := s.closeStep(ctx, acct.ID, step.ID(), res.Status); err != nil {
				return Status{}, WrapError(KindUnavailable, CodeServerError, err)
			}
		}
	}

	// A check may have completed a step or granted access, so read both back. Under
	// the account's lock: a grant, a revocation or an operator action running
	// concurrently is then either wholly before this read or wholly after the write
	// below, which otherwise could store a state derived from a stale read, or a
	// stale access end over a fresh grant.
	unlock := s.lockAccount(acct.ID)
	defer unlock()
	fresh, err := s.store.AccountByID(ctx, acct.ID)
	if err != nil {
		return Status{}, WrapError(KindUnavailable, CodeServerError, err)
	}
	if fresh.State == storage.AccountDisabled {
		*acct = fresh
		return Status{State: storage.AccountDisabled, AccessUntil: fresh.AccessUntil, MsgCode: CodeDisabled}, nil
	}
	recs, err = s.stepRecords(ctx, acct.ID)
	if err != nil {
		return Status{}, WrapError(KindUnavailable, CodeServerError, err)
	}
	status := Status{AccessUntil: fresh.AccessUntil}
	for _, step := range s.steps {
		rec := recs[step.ID()]
		if isClosed(rec.Status) {
			continue
		}
		code := codes[step.ID()]
		if code == "" {
			code = defaultStepCode(step)
		}
		status.Pending = append(status.Pending, PendingStep{
			ID: step.ID(), Kind: step.Kind(), Title: step.Title("en"),
			URL: s.cfg.PublicURL + StepPath(step.ID()), MsgCode: code,
		})
	}
	switch {
	case s.expired(fresh):
		status.State, status.MsgCode = storage.AccountExpired, CodeExpired
	case len(status.Pending) > 0:
		status.State, status.MsgCode = storage.AccountPending, CodePending
	default:
		status.State = storage.AccountActive
	}
	if fresh.State != status.State {
		prev := fresh.State
		fresh.State = status.State
		if err := s.store.UpdateAccount(ctx, &fresh); err != nil {
			return Status{}, WrapError(KindUnavailable, CodeServerError, err)
		}
		logging.Infof("accounts: %q (id=%d) %s -> %s", fresh.Username, fresh.ID, prev, status.State)
	}
	*acct = fresh
	return status, nil
}

// CompleteStep marks a step done, keeping its data. Part of Host.
func (s *Service) CompleteStep(ctx context.Context, accountID uint64, stepID string) error {
	return s.closeStep(ctx, accountID, stepID, storage.StepDone)
}

// ResetStep marks a step pending again, keeping its data. Part of Host.
func (s *Service) ResetStep(ctx context.Context, accountID uint64, stepID string) error {
	recs, err := s.stepRecords(ctx, accountID)
	if err != nil {
		return err
	}
	rec := recs[stepID]
	rec.AccountID, rec.StepID, rec.Status, rec.CompletedAt = accountID, stepID, storage.StepPending, time.Time{}
	return s.store.UpsertAccountStep(ctx, &rec)
}

// GrantAccess extends an account's access and closes the step that paid for it.
// Part of Host.
func (s *Service) GrantAccess(ctx context.Context, accountID uint64, stepID string, days uint32) error {
	unlock := s.lockAccount(accountID)
	defer unlock()
	acct, err := s.store.AccountByID(ctx, accountID)
	if err != nil {
		return err
	}
	if days == 0 {
		// A one-off purchase: access no longer expires.
		acct.AccessUntil = time.Time{}
	} else {
		from := s.now()
		if acct.AccessUntil.After(from) {
			from = acct.AccessUntil
		}
		acct.AccessUntil = from.Add(time.Duration(days) * 24 * time.Hour)
	}
	if err := s.store.UpdateAccount(ctx, &acct); err != nil {
		return err
	}
	until := "no expiry"
	if !acct.AccessUntil.IsZero() {
		until = acct.AccessUntil.UTC().Format(time.RFC3339)
	}
	logging.Infof("accounts: %q (id=%d) granted %d days by step %s, access until %s",
		acct.Username, acct.ID, days, stepID, until)
	return s.CompleteStep(ctx, accountID, stepID)
}

// RevokeAccess takes back access granted by a step. Part of Host.
func (s *Service) RevokeAccess(ctx context.Context, accountID uint64, stepID string, days uint32) error {
	unlock := s.lockAccount(accountID)
	acct, err := s.store.AccountByID(ctx, accountID)
	if err != nil {
		unlock()
		return err
	}
	now := s.now()
	if days == 0 || acct.AccessUntil.IsZero() {
		acct.AccessUntil = now
	} else {
		acct.AccessUntil = acct.AccessUntil.Add(-time.Duration(days) * 24 * time.Hour)
	}
	err = s.store.UpdateAccount(ctx, &acct)
	unlock()
	if err != nil {
		return err
	}
	logging.Infof("accounts: %q (id=%d) lost %d days from step %s, access until %s",
		acct.Username, acct.ID, days, stepID, acct.AccessUntil.UTC().Format(time.RFC3339))
	if !now.Before(acct.AccessUntil) {
		if err := s.ResetStep(ctx, accountID, stepID); err != nil {
			return err
		}
	}
	_, err = s.Evaluate(ctx, &acct)
	return err
}

// SetDisabled disables an account, or re-enables it and settles its state from its
// steps. An operator action.
func (s *Service) SetDisabled(ctx context.Context, accountID uint64, disabled bool) error {
	unlock := s.lockAccount(accountID)
	acct, err := s.store.AccountByID(ctx, accountID)
	if err != nil {
		unlock()
		return err
	}
	if disabled == (acct.State == storage.AccountDisabled) {
		unlock()
		return nil
	}
	if disabled {
		acct.State = storage.AccountDisabled
		err := s.store.UpdateAccount(ctx, &acct)
		unlock()
		if err != nil {
			return err
		}
		logging.Infof("accounts: %q (id=%d) disabled by the operator", acct.Username, acct.ID)
		return nil
	}
	acct.State = storage.AccountPending
	err = s.store.UpdateAccount(ctx, &acct)
	unlock()
	if err != nil {
		return err
	}
	logging.Infof("accounts: %q (id=%d) re-enabled by the operator", acct.Username, acct.ID)
	_, err = s.Evaluate(ctx, &acct)
	return err
}

// AdjustAccess moves an account's access end by days, positive or negative, as an
// operator action. Extending counts from the later of now and the current end. An
// account whose access does not expire cannot be adjusted.
func (s *Service) AdjustAccess(ctx context.Context, accountID uint64, days int) error {
	if days == 0 {
		return nil
	}
	unlock := s.lockAccount(accountID)
	acct, err := s.store.AccountByID(ctx, accountID)
	if err != nil {
		unlock()
		return err
	}
	if acct.AccessUntil.IsZero() {
		unlock()
		return ErrNoExpiry
	}
	from := acct.AccessUntil
	if days > 0 && s.now().After(from) {
		from = s.now()
	}
	acct.AccessUntil = from.Add(time.Duration(days) * 24 * time.Hour)
	err = s.store.UpdateAccount(ctx, &acct)
	unlock()
	if err != nil {
		return err
	}
	logging.Infof("accounts: %q (id=%d) access moved by %d days by the operator, until %s",
		acct.Username, acct.ID, days, acct.AccessUntil.UTC().Format(time.RFC3339))
	_, err = s.Evaluate(ctx, &acct)
	return err
}

// SkipStep closes a configured step without it being done, as an operator action,
// e.g. to let a user in without paying.
func (s *Service) SkipStep(ctx context.Context, accountID uint64, stepID string) error {
	if !s.hasStep(stepID) {
		return ErrUnknownStep
	}
	acct, err := s.store.AccountByID(ctx, accountID)
	if err != nil {
		return err
	}
	if err := s.closeStep(ctx, accountID, stepID, storage.StepSkipped); err != nil {
		return err
	}
	logging.Infof("accounts: %q (id=%d) step %s skipped by the operator", acct.Username, acct.ID, stepID)
	_, err = s.Evaluate(ctx, &acct)
	return err
}

// Counts returns how many accounts are in each state, for the dashboard.
func (s *Service) Counts(ctx context.Context) (map[storage.AccountState]int, error) {
	return s.store.CountAccounts(ctx)
}

// Run reconciles steps in the background and sweeps expired sessions, every
// PollInterval, until ctx ends.
func (s *Service) Run(ctx context.Context) {
	interval := s.cfg.PollInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		s.pollOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// lockAccount takes the account's lock and returns its release.
func (s *Service) lockAccount(accountID uint64) func() {
	mu := &s.accountLocks[lockIndex(accountID)]
	mu.Lock()
	return mu.Unlock
}

func (s *Service) hasStep(id string) bool {
	for _, step := range s.steps {
		if step.ID() == id {
			return true
		}
	}
	return false
}

func (s *Service) pollOnce(ctx context.Context) {
	for _, step := range s.steps {
		if p, ok := step.(Poller); ok {
			p.Poll(ctx)
		}
	}
	if n, err := s.store.DeleteExpiredSessions(ctx, s.now()); err != nil {
		logging.Warnf("accounts: sweep expired sessions: %v", err)
	} else if n > 0 {
		logging.Debugf("accounts: removed %d expired sessions", n)
	}
}

// closeStep sets a step done or skipped unless it already is, keeping its data.
func (s *Service) closeStep(ctx context.Context, accountID uint64, stepID string, status storage.StepStatus) error {
	recs, err := s.stepRecords(ctx, accountID)
	if err != nil {
		return err
	}
	rec := recs[stepID]
	if isClosed(rec.Status) {
		return nil
	}
	rec.AccountID, rec.StepID, rec.Status, rec.CompletedAt = accountID, stepID, status, s.now()
	return s.store.UpsertAccountStep(ctx, &rec)
}

func (s *Service) stepRecords(ctx context.Context, accountID uint64) (map[string]storage.AccountStep, error) {
	list, err := s.store.AccountSteps(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]storage.AccountStep, len(list))
	for _, r := range list {
		out[r.StepID] = r
	}
	return out, nil
}

func (s *Service) expired(acct storage.Account) bool {
	return !acct.AccessUntil.IsZero() && !s.now().Before(acct.AccessUntil)
}

func isClosed(st storage.StepStatus) bool {
	return st == storage.StepDone || st == storage.StepSkipped
}

// defaultStepCode is the MsgCode for an open step whose Check gave none.
func defaultStepCode(step Step) string {
	if step.Kind() == StepKindPayment {
		return "step.payment.required"
	}
	return CodePending
}

func lockIndex(accountID uint64) int {
	h := fnv.New32a()
	var b [8]byte
	for i := range b {
		b[i] = byte(accountID >> (8 * i))
	}
	_, _ = h.Write(b[:])
	return int(h.Sum32() % 64)
}
