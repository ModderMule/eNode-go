package accounts

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"enode/storage"
)

func TestOperatorActions(t *testing.T) {
	pay := &fakeStep{id: "payment", renewable: true, grantDays: 30}
	svc, store := newTestService(t, pay)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	svc.SetClock(func() time.Time { return now })
	acct, _ := svc.Register(ctx, "vera", "", "password1")

	// An account without expiry cannot be moved.
	if err := svc.AdjustAccess(ctx, acct.ID, 5); !errors.Is(err, ErrNoExpiry) {
		t.Fatalf("adjust without expiry: %v, want ErrNoExpiry", err)
	}
	if err := svc.SkipStep(ctx, acct.ID, "nope"); !errors.Is(err, ErrUnknownStep) {
		t.Fatalf("skip unknown step: %v", err)
	}

	// Skipping the payment step lets the user in without paying.
	if err := svc.SkipStep(ctx, acct.ID, "payment"); err != nil {
		t.Fatal(err)
	}
	a, _ := store.AccountByID(ctx, acct.ID)
	t.Logf("input: skip payment output: state=%s until=%v", a.State, a.AccessUntil)
	if a.State != storage.AccountActive {
		t.Fatalf("skipped step: state %s, want active", a.State)
	}

	// Grant, then move the end back.
	_ = svc.GrantAccess(ctx, acct.ID, "payment", 30)
	if err := svc.AdjustAccess(ctx, acct.ID, 10); err != nil {
		t.Fatal(err)
	}
	if err := svc.AdjustAccess(ctx, acct.ID, -5); err != nil {
		t.Fatal(err)
	}
	a, _ = store.AccountByID(ctx, acct.ID)
	t.Logf("input: grant 30, +10, -5 output: until=%s", a.AccessUntil)
	if !a.AccessUntil.Equal(now.Add(35 * 24 * time.Hour)) {
		t.Fatalf("until %s, want +35 days", a.AccessUntil)
	}
	if err := svc.AdjustAccess(ctx, acct.ID, -40); err != nil {
		t.Fatal(err)
	}
	a, _ = store.AccountByID(ctx, acct.ID)
	if a.State != storage.AccountExpired {
		t.Fatalf("moved into the past: state %s, want expired", a.State)
	}

	// Disable wins over everything; enabling settles the state again.
	_ = svc.AdjustAccess(ctx, acct.ID, 60)
	if err := svc.SetDisabled(ctx, acct.ID, true); err != nil {
		t.Fatal(err)
	}
	a, _ = store.AccountByID(ctx, acct.ID)
	if st, _ := svc.Authorize(ctx, &a); st.State != storage.AccountDisabled {
		t.Fatalf("disabled account authorized as %s", st.State)
	}
	if err := svc.SetDisabled(ctx, acct.ID, false); err != nil {
		t.Fatal(err)
	}
	a, _ = store.AccountByID(ctx, acct.ID)
	t.Logf("input: disable then enable output: state=%s", a.State)
	if a.State != storage.AccountActive {
		t.Fatalf("re-enabled: state %s, want active", a.State)
	}
}

func TestRevokeAccessReopensStep(t *testing.T) {
	pay := &fakeStep{id: "payment", renewable: true, grantDays: 30}
	svc, store := newTestService(t, pay)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	svc.SetClock(func() time.Time { return now })
	acct, _ := svc.Register(ctx, "walt", "", "password1")
	pay.complete(acct.ID)
	st, _ := svc.Evaluate(ctx, &acct)
	if !st.Active() {
		t.Fatalf("not active after paying")
	}
	pay.mu.Lock()
	delete(pay.doneFor, acct.ID)
	pay.mu.Unlock()
	if err := svc.RevokeAccess(ctx, acct.ID, "payment", 30); err != nil {
		t.Fatal(err)
	}
	a, _ := store.AccountByID(ctx, acct.ID)
	st, _ = svc.Evaluate(ctx, &a)
	t.Logf("input: revoke the only 30-day purchase output: state=%s until=%s pending=%d", st.State, a.AccessUntil, len(st.Pending))
	if st.Active() || len(st.Pending) != 1 {
		t.Fatalf("after revoking: %+v", st)
	}
}

// TestConcurrentGrantsAndEvaluationsLoseNothing races grants against state
// evaluations: an Evaluate that wrote back a stale account would drop a grant.
func TestConcurrentGrantsAndEvaluationsLoseNothing(t *testing.T) {
	pay := &fakeStep{id: "payment", renewable: true}
	svc, store := newTestService(t, pay)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	svc.SetClock(func() time.Time { return now })
	acct, _ := svc.Register(ctx, "yuri", "", "password1")

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_ = svc.GrantAccess(ctx, acct.ID, "payment", 1)
				return
			}
			a, _ := store.AccountByID(ctx, acct.ID)
			_, _ = svc.Evaluate(ctx, &a)
		}(i)
	}
	wg.Wait()
	a, _ := store.AccountByID(ctx, acct.ID)
	st, _ := svc.Evaluate(ctx, &a)
	t.Logf("input: 20 one-day grants racing 20 evaluations output: until=%s state=%s", a.AccessUntil, st.State)
	if !a.AccessUntil.Equal(now.Add(20 * 24 * time.Hour)) {
		t.Fatalf("access until %s, want 20 days: a grant was lost", a.AccessUntil)
	}
	if st.State != storage.AccountActive {
		t.Fatalf("state %s, want active", st.State)
	}
}
