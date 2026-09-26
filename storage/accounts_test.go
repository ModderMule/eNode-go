package storage

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestMemoryAccountStore runs the AccountStore conformance suite on the memory
// engine. integration_accounts_test.go runs the same suite on MySQL and MongoDB.
func TestMemoryAccountStore(t *testing.T) {
	testAccountStore(t, NewMemoryEngine())
}

// TestMemoryAccountsNotDurable pins the flag the payment step relies on to refuse
// the memory engine.
func TestMemoryAccountsNotDurable(t *testing.T) {
	m := NewMemoryEngine()
	t.Logf("input: memory engine output: DurableAccounts=%v", m.DurableAccounts())
	if m.DurableAccounts() {
		t.Fatal("the memory engine claims durable accounts")
	}
}

// testAccountStore exercises every AccountStore method against one engine.
func testAccountStore(t *testing.T, s AccountStore) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := s.InitAccounts(ctx); err != nil {
		t.Fatalf("InitAccounts: %v", err)
	}
	if err := s.InitAccounts(ctx); err != nil {
		t.Fatalf("InitAccounts is not idempotent: %v", err)
	}

	// Accounts.
	a := Account{Username: "alice", Email: "a@example.org", PasswordHash: "h1", State: AccountPending}
	if err := s.CreateAccount(ctx, &a); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	t.Logf("input: create alice output: id=%d created=%s", a.ID, a.CreatedAt)
	if a.ID == 0 || a.CreatedAt.IsZero() {
		t.Fatalf("CreateAccount did not set ID/CreatedAt: %+v", a)
	}
	dup := Account{Username: "alice", PasswordHash: "x", State: AccountPending}
	if err := s.CreateAccount(ctx, &dup); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("duplicate username: err=%v, want ErrUsernameTaken", err)
	}
	b := Account{Username: "bob", PasswordHash: "h2", State: AccountActive}
	if err := s.CreateAccount(ctx, &b); err != nil {
		t.Fatalf("CreateAccount bob: %v", err)
	}
	if b.ID == a.ID {
		t.Fatalf("two accounts share id %d", a.ID)
	}

	got, err := s.AccountByUsername(ctx, "alice")
	if err != nil || got.ID != a.ID || got.Email != "a@example.org" || got.State != AccountPending || !got.AccessUntil.IsZero() {
		t.Fatalf("AccountByUsername: %+v, %v", got, err)
	}
	if _, err := s.AccountByUsername(ctx, "nobody"); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("unknown username: err=%v, want ErrAccountNotFound", err)
	}
	if _, err := s.AccountByID(ctx, 999999); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("unknown id: err=%v, want ErrAccountNotFound", err)
	}

	until := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Millisecond)
	got.State, got.AccessUntil, got.PasswordHash = AccountActive, until, "h1b"
	if err := s.UpdateAccount(ctx, &got); err != nil {
		t.Fatalf("UpdateAccount: %v", err)
	}
	re, err := s.AccountByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: update alice active until %s output: %+v", until, re)
	if re.State != AccountActive || re.PasswordHash != "h1b" || !re.AccessUntil.Equal(until) {
		t.Fatalf("UpdateAccount not persisted: %+v", re)
	}
	missing := Account{ID: 999999}
	if err := s.UpdateAccount(ctx, &missing); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("update unknown: err=%v, want ErrAccountNotFound", err)
	}

	counts, err := s.CountAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: counts=%v", counts)
	if counts[AccountActive] != 2 || counts[AccountPending] != 0 {
		t.Fatalf("CountAccounts = %v, want 2 active", counts)
	}
	list, err := s.ListAccounts(ctx, AccountFilter{State: AccountActive}, 1, 0)
	if err != nil || len(list) != 1 || list[0].ID != b.ID {
		t.Fatalf("ListAccounts(active,1,0) = %+v, %v; want bob first (newest)", list, err)
	}
	list, err = s.ListAccounts(ctx, AccountFilter{}, 10, 1)
	if err != nil || len(list) != 1 || list[0].ID != a.ID {
		t.Fatalf("ListAccounts(all,10,1) = %+v, %v; want alice", list, err)
	}
	for _, c := range []struct {
		search string
		want   int
	}{{"ALI", 1}, {"example.org", 1}, {"bo", 1}, {"%", 0}, {"a_i", 0}, {"", 2}} {
		list, err = s.ListAccounts(ctx, AccountFilter{Search: c.search}, 10, 0)
		t.Logf("input: search %q output: %d accounts", c.search, len(list))
		if err != nil || len(list) != c.want {
			t.Fatalf("search %q: %d accounts, %v; want %d", c.search, len(list), err, c.want)
		}
	}

	// Steps: upsert inserts, then replaces, keyed by (account, step).
	st := AccountStep{AccountID: a.ID, StepID: "payment", Status: StepPending, Data: []byte(`{"x":1}`)}
	if err := s.UpsertAccountStep(ctx, &st); err != nil {
		t.Fatalf("UpsertAccountStep: %v", err)
	}
	firstID := st.ID
	done := time.Now().UTC().Truncate(time.Millisecond)
	st2 := AccountStep{AccountID: a.ID, StepID: "payment", Status: StepDone, Data: []byte(`{"x":2}`), CompletedAt: done}
	if err := s.UpsertAccountStep(ctx, &st2); err != nil {
		t.Fatal(err)
	}
	if st2.ID != firstID {
		t.Fatalf("upsert changed the step id: %d -> %d", firstID, st2.ID)
	}
	other := AccountStep{AccountID: a.ID, StepID: "email", Status: StepPending}
	if err := s.UpsertAccountStep(ctx, &other); err != nil {
		t.Fatal(err)
	}
	steps, err := s.AccountSteps(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: steps=%+v", steps)
	if len(steps) != 2 || steps[0].StepID != "payment" || steps[0].Status != StepDone ||
		!bytes.Equal(steps[0].Data, []byte(`{"x":2}`)) || !steps[0].CompletedAt.Equal(done) {
		t.Fatalf("AccountSteps = %+v", steps)
	}
	if none, err := s.AccountSteps(ctx, b.ID); err != nil || len(none) != 0 {
		t.Fatalf("bob's steps = %+v, %v; want none", none, err)
	}

	// Payments: two rows before checkout (no external id) must not collide.
	p1 := Payment{AccountID: a.ID, StepID: "payment", PlanID: "monthly", Provider: "woocommerce", PeriodDays: 30}
	p2 := Payment{AccountID: a.ID, StepID: "payment", PlanID: "monthly", Provider: "woocommerce", PeriodDays: 30}
	if err := s.CreatePayment(ctx, &p1); err != nil {
		t.Fatalf("CreatePayment: %v", err)
	}
	if err := s.CreatePayment(ctx, &p2); err != nil {
		t.Fatalf("second CreatePayment without external id: %v", err)
	}
	p1.ExternalID, p1.ExternalKey, p1.Status, p1.Amount, p1.Currency = "1001", "wc_order_x", PaymentPending, "5.00", "EUR"
	if err := s.UpdatePayment(ctx, &p1); err != nil {
		t.Fatalf("UpdatePayment: %v", err)
	}
	p2.ExternalID = "1001"
	if err := s.UpdatePayment(ctx, &p2); !errors.Is(err, ErrPaymentDuplicate) {
		t.Fatalf("duplicate external id: err=%v, want ErrPaymentDuplicate", err)
	}
	byExt, err := s.PaymentByExternal(ctx, "woocommerce", "1001")
	if err != nil || byExt.ID != p1.ID || byExt.Amount != "5.00" || byExt.Status != PaymentPending || byExt.ExternalKey != "wc_order_x" {
		t.Fatalf("PaymentByExternal = %+v, %v", byExt, err)
	}
	if _, err := s.PaymentByExternal(ctx, "other", "1001"); !errors.Is(err, ErrPaymentNotFound) {
		t.Fatalf("other provider: err=%v, want ErrPaymentNotFound", err)
	}
	open, err := s.OpenPayments(ctx, 10)
	if err != nil || len(open) != 2 || open[0].ID != p1.ID {
		t.Fatalf("OpenPayments = %+v, %v; want p1, p2", open, err)
	}
	mine, err := s.PaymentsByAccount(ctx, a.ID, 10)
	if err != nil || len(mine) != 2 || mine[0].ID != p2.ID {
		t.Fatalf("PaymentsByAccount = %+v, %v; want newest first", mine, err)
	}

	// MarkPaymentCredited: exactly one of many concurrent callers wins.
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			won, err := s.MarkPaymentCredited(ctx, p1.ID, time.Now())
			if err != nil {
				t.Errorf("MarkPaymentCredited: %v", err)
			}
			if won {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	t.Logf("input: 8 concurrent MarkPaymentCredited output: %d won", wins)
	if wins != 1 {
		t.Fatalf("%d callers credited the payment, want exactly 1", wins)
	}
	if _, err := s.MarkPaymentCredited(ctx, 999999, time.Now()); !errors.Is(err, ErrPaymentNotFound) {
		t.Fatalf("credit unknown payment: err=%v, want ErrPaymentNotFound", err)
	}
	credited, _ := s.PaymentByID(ctx, p1.ID)
	if credited.CreditedAt.IsZero() {
		t.Fatalf("CreditedAt not stored: %+v", credited)
	}
	credited.Status = PaymentPaid
	if err := s.UpdatePayment(ctx, &credited); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.PaymentByID(ctx, p1.ID); again.CreditedAt.IsZero() {
		t.Fatalf("UpdatePayment cleared CreditedAt")
	}
	if open, _ := s.OpenPayments(ctx, 10); len(open) != 1 || open[0].ID != p2.ID {
		t.Fatalf("OpenPayments after paid = %+v, want only p2", open)
	}

	// Refund checks: credited payments inside the window, until revoked once.
	if won, err := s.MarkPaymentRevoked(ctx, p2.ID, time.Now()); err != nil || won {
		t.Fatalf("revoking an uncredited payment: won=%v err=%v, want false", won, err)
	}
	recent, err := s.CreditedPayments(ctx, time.Now().Add(-time.Hour), 10)
	t.Logf("input: credited payments of the last hour output: %d", len(recent))
	if err != nil || len(recent) != 1 || recent[0].ID != p1.ID {
		t.Fatalf("CreditedPayments = %+v, %v; want p1", recent, err)
	}
	if later, _ := s.CreditedPayments(ctx, time.Now().Add(time.Hour), 10); len(later) != 0 {
		t.Fatalf("CreditedPayments ignored since: %+v", later)
	}
	revokes := 0
	var rwg sync.WaitGroup
	for i := 0; i < 8; i++ {
		rwg.Add(1)
		go func() {
			defer rwg.Done()
			if won, err := s.MarkPaymentRevoked(ctx, p1.ID, time.Now()); err == nil && won {
				mu.Lock()
				revokes++
				mu.Unlock()
			}
		}()
	}
	rwg.Wait()
	t.Logf("input: 8 concurrent MarkPaymentRevoked output: %d won", revokes)
	if revokes != 1 {
		t.Fatalf("%d callers revoked the payment, want exactly 1", revokes)
	}
	if rp, _ := s.PaymentByID(ctx, p1.ID); rp.RevokedAt.IsZero() || rp.CreditedAt.IsZero() {
		t.Fatalf("RevokedAt not stored or CreditedAt lost: %+v", rp)
	}
	if recent, _ := s.CreditedPayments(ctx, time.Now().Add(-time.Hour), 10); len(recent) != 0 {
		t.Fatalf("a revoked payment is still listed for refund checks: %+v", recent)
	}

	// Sessions.
	hash := bytes.Repeat([]byte{0xab}, 32)
	sess := AccountSession{AccountID: a.ID, TokenHash: hash, Client: "eMuleQt", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.CreateSession(ctx, &sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	gs, err := s.SessionByTokenHash(ctx, hash)
	if err != nil || gs.ID != sess.ID || gs.AccountID != a.ID || gs.Client != "eMuleQt" {
		t.Fatalf("SessionByTokenHash = %+v, %v", gs, err)
	}
	old := AccountSession{AccountID: a.ID, TokenHash: bytes.Repeat([]byte{0xcd}, 32), ExpiresAt: time.Now().Add(-time.Hour)}
	if err := s.CreateSession(ctx, &old); err != nil {
		t.Fatal(err)
	}
	n, err := s.DeleteExpiredSessions(ctx, time.Now())
	t.Logf("input: one live, one expired session output: deleted=%d err=%v", n, err)
	if err != nil {
		t.Fatal(err)
	}
	// MongoDB's TTL monitor may have removed the expired one first; either way it
	// must be gone and the live one kept.
	if _, err := s.SessionByTokenHash(ctx, old.TokenHash); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expired session still found: %v", err)
	}
	if _, err := s.SessionByTokenHash(ctx, hash); err != nil {
		t.Fatalf("live session lost: %v", err)
	}
	if err := s.DeleteSession(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByTokenHash(ctx, hash); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("deleted session still found: %v", err)
	}
}
