package storage

import (
	"context"
	"sort"
	"strings"
	"time"
)

// memoryAccounts is the MemoryEngine's AccountStore. Its zero value is ready to use,
// so a MemoryEngine built as a literal (as some tests do) works without a constructor.
// It has its own lock: account traffic must not contend with the eD2K index.
type memoryAccounts struct {
	nextID   uint64
	accounts map[uint64]Account
	byName   map[string]uint64
	steps    map[uint64]map[string]AccountStep // accountID → stepID → record
	payments map[uint64]Payment
	sessions map[uint64]AccountSession
	byToken  map[string]uint64
}

// DurableAccounts is false: the memory engine loses every account on restart.
func (m *MemoryEngine) DurableAccounts() bool { return false }

// InitAccounts has nothing to prepare.
func (m *MemoryEngine) InitAccounts(context.Context) error { return nil }

func (m *MemoryEngine) CreateAccount(_ context.Context, a *Account) error {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	s := m.acctStore()
	if _, ok := s.byName[a.Username]; ok {
		return ErrUsernameTaken
	}
	now := time.Now()
	a.ID = s.id()
	a.CreatedAt, a.UpdatedAt = now, now
	s.accounts[a.ID] = *a
	s.byName[a.Username] = a.ID
	return nil
}

func (m *MemoryEngine) AccountByID(_ context.Context, id uint64) (Account, error) {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	a, ok := m.acctStore().accounts[id]
	if !ok {
		return Account{}, ErrAccountNotFound
	}
	return a, nil
}

func (m *MemoryEngine) AccountByUsername(_ context.Context, username string) (Account, error) {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	s := m.acctStore()
	id, ok := s.byName[username]
	if !ok {
		return Account{}, ErrAccountNotFound
	}
	return s.accounts[id], nil
}

func (m *MemoryEngine) UpdateAccount(_ context.Context, a *Account) error {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	s := m.acctStore()
	cur, ok := s.accounts[a.ID]
	if !ok {
		return ErrAccountNotFound
	}
	cur.Email = a.Email
	cur.PasswordHash = a.PasswordHash
	cur.State = a.State
	cur.AccessUntil = a.AccessUntil
	cur.UpdatedAt = time.Now()
	s.accounts[a.ID] = cur
	*a = cur
	return nil
}

func (m *MemoryEngine) CountAccounts(context.Context) (map[AccountState]int, error) {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	out := map[AccountState]int{}
	for _, a := range m.acctStore().accounts {
		out[a.State]++
	}
	return out, nil
}

func (m *MemoryEngine) ListAccounts(_ context.Context, filter AccountFilter, limit, offset int) ([]Account, error) {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	search := strings.ToLower(filter.Search)
	var out []Account
	for _, a := range m.acctStore().accounts {
		if filter.State != 0 && a.State != filter.State {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(a.Username), search) && !strings.Contains(strings.ToLower(a.Email), search) {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return page(out, limit, offset), nil
}

func (m *MemoryEngine) AccountSteps(_ context.Context, accountID uint64) ([]AccountStep, error) {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	var out []AccountStep
	for _, st := range m.acctStore().steps[accountID] {
		st.Data = append([]byte(nil), st.Data...)
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MemoryEngine) UpsertAccountStep(_ context.Context, st *AccountStep) error {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	s := m.acctStore()
	byStep := s.steps[st.AccountID]
	if byStep == nil {
		byStep = map[string]AccountStep{}
		s.steps[st.AccountID] = byStep
	}
	now := time.Now()
	if cur, ok := byStep[st.StepID]; ok {
		st.ID, st.CreatedAt = cur.ID, cur.CreatedAt
	} else {
		st.ID, st.CreatedAt = s.id(), now
	}
	st.UpdatedAt = now
	rec := *st
	rec.Data = append([]byte(nil), st.Data...)
	byStep[st.StepID] = rec
	return nil
}

func (m *MemoryEngine) CreatePayment(_ context.Context, p *Payment) error {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	s := m.acctStore()
	if p.ExternalID != "" && s.paymentByExternal(p.Provider, p.ExternalID, 0) {
		return ErrPaymentDuplicate
	}
	now := time.Now()
	p.ID = s.id()
	p.CreatedAt, p.UpdatedAt = now, now
	s.payments[p.ID] = *p
	return nil
}

func (m *MemoryEngine) UpdatePayment(_ context.Context, p *Payment) error {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	s := m.acctStore()
	cur, ok := s.payments[p.ID]
	if !ok {
		return ErrPaymentNotFound
	}
	if p.ExternalID != "" && s.paymentByExternal(cur.Provider, p.ExternalID, p.ID) {
		return ErrPaymentDuplicate
	}
	cur.ExternalID = p.ExternalID
	cur.ExternalKey = p.ExternalKey
	cur.Status = p.Status
	cur.Amount = p.Amount
	cur.Currency = p.Currency
	cur.UpdatedAt = time.Now()
	s.payments[p.ID] = cur
	*p = cur
	return nil
}

func (m *MemoryEngine) PaymentByID(_ context.Context, id uint64) (Payment, error) {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	p, ok := m.acctStore().payments[id]
	if !ok {
		return Payment{}, ErrPaymentNotFound
	}
	return p, nil
}

func (m *MemoryEngine) PaymentByExternal(_ context.Context, provider, externalID string) (Payment, error) {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	for _, p := range m.acctStore().payments {
		if p.Provider == provider && p.ExternalID == externalID && externalID != "" {
			return p, nil
		}
	}
	return Payment{}, ErrPaymentNotFound
}

func (m *MemoryEngine) OpenPayments(_ context.Context, limit int) ([]Payment, error) {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	var out []Payment
	for _, p := range m.acctStore().payments {
		if p.Status.Open() {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return page(out, limit, 0), nil
}

func (m *MemoryEngine) PaymentsByAccount(_ context.Context, accountID uint64, limit int) ([]Payment, error) {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	var out []Payment
	for _, p := range m.acctStore().payments {
		if p.AccountID == accountID {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return page(out, limit, 0), nil
}

func (m *MemoryEngine) MarkPaymentCredited(_ context.Context, id uint64, at time.Time) (bool, error) {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	s := m.acctStore()
	p, ok := s.payments[id]
	if !ok {
		return false, ErrPaymentNotFound
	}
	if !p.CreditedAt.IsZero() {
		return false, nil
	}
	p.CreditedAt = at
	p.UpdatedAt = time.Now()
	s.payments[id] = p
	return true, nil
}

func (m *MemoryEngine) MarkPaymentRevoked(_ context.Context, id uint64, at time.Time) (bool, error) {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	s := m.acctStore()
	p, ok := s.payments[id]
	if !ok {
		return false, ErrPaymentNotFound
	}
	if p.CreditedAt.IsZero() || !p.RevokedAt.IsZero() {
		return false, nil
	}
	p.RevokedAt = at
	p.UpdatedAt = time.Now()
	s.payments[id] = p
	return true, nil
}

func (m *MemoryEngine) CreditedPayments(_ context.Context, since time.Time, limit int) ([]Payment, error) {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	var out []Payment
	for _, p := range m.acctStore().payments {
		if !p.CreditedAt.IsZero() && !p.CreditedAt.Before(since) && p.RevokedAt.IsZero() {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreditedAt.After(out[j].CreditedAt) })
	return page(out, limit, 0), nil
}

func (m *MemoryEngine) CreateSession(_ context.Context, sess *AccountSession) error {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	s := m.acctStore()
	now := time.Now()
	sess.ID = s.id()
	sess.CreatedAt, sess.UpdatedAt = now, now
	s.sessions[sess.ID] = *sess
	s.byToken[string(sess.TokenHash)] = sess.ID
	return nil
}

func (m *MemoryEngine) SessionByTokenHash(_ context.Context, tokenHash []byte) (AccountSession, error) {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	s := m.acctStore()
	id, ok := s.byToken[string(tokenHash)]
	if !ok {
		return AccountSession{}, ErrSessionNotFound
	}
	return s.sessions[id], nil
}

func (m *MemoryEngine) DeleteSession(_ context.Context, id uint64) error {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	s := m.acctStore()
	if sess, ok := s.sessions[id]; ok {
		delete(s.byToken, string(sess.TokenHash))
		delete(s.sessions, id)
	}
	return nil
}

func (m *MemoryEngine) DeleteExpiredSessions(_ context.Context, now time.Time) (int, error) {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	s := m.acctStore()
	n := 0
	for id, sess := range s.sessions {
		if sess.ExpiresAt.Before(now) {
			delete(s.byToken, string(sess.TokenHash))
			delete(s.sessions, id)
			n++
		}
	}
	return n, nil
}

// acctStore returns the account maps, creating them on first use. Callers hold acctMu.
func (m *MemoryEngine) acctStore() *memoryAccounts {
	s := &m.accts
	if s.accounts == nil {
		s.accounts = map[uint64]Account{}
		s.byName = map[string]uint64{}
		s.steps = map[uint64]map[string]AccountStep{}
		s.payments = map[uint64]Payment{}
		s.sessions = map[uint64]AccountSession{}
		s.byToken = map[string]uint64{}
	}
	return s
}

// id hands out the next primary key. One sequence for every kind of row is enough:
// the keys only have to be unique within a kind.
func (s *memoryAccounts) id() uint64 {
	s.nextID++
	return s.nextID
}

// paymentByExternal reports whether a payment other than except carries that
// provider id.
func (s *memoryAccounts) paymentByExternal(provider, externalID string, except uint64) bool {
	for _, p := range s.payments {
		if p.ID != except && p.Provider == provider && p.ExternalID == externalID {
			return true
		}
	}
	return false
}

// page applies limit and offset to an already sorted slice. limit <= 0 means all.
func page[T any](in []T, limit, offset int) []T {
	if offset >= len(in) {
		return nil
	}
	in = in[offset:]
	if limit > 0 && limit < len(in) {
		in = in[:limit]
	}
	return in
}
