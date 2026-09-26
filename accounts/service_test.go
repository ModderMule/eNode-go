package accounts

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"enode/config"
	"enode/storage"

	"gopkg.in/yaml.v3"
)

// fakeStep is a controllable step: it reports done when its account is in doneFor,
// granting grantDays the first time.
type fakeStep struct {
	id        string
	renewable bool
	durable   bool
	grantDays uint32
	host      Host

	mu      sync.Mutex
	doneFor map[uint64]bool
	granted map[uint64]bool
	checks  int
}

func (f *fakeStep) ID() string                    { return f.id }
func (f *fakeStep) Kind() StepKind                { return StepKindPayment }
func (f *fakeStep) Title(lang string) string      { return "Fake " + lang }
func (f *fakeStep) Durable() bool                 { return f.durable }
func (f *fakeStep) Renewable() bool               { return f.renewable }
func (f *fakeStep) Routes(*http.ServeMux, Portal) {}

func (f *fakeStep) Check(ctx context.Context, acct storage.Account, _ storage.AccountStep) (StepResult, error) {
	f.mu.Lock()
	f.checks++
	done := f.doneFor[acct.ID]
	first := done && !f.granted[acct.ID]
	if first {
		f.granted[acct.ID] = true
	}
	f.mu.Unlock()
	if !done {
		return StepResult{Status: storage.StepPending, MsgCode: "step.payment.pending"}, nil
	}
	if first {
		if f.grantDays > 0 {
			return StepResult{Status: storage.StepDone}, f.host.GrantAccess(ctx, acct.ID, f.id, f.grantDays)
		}
		return StepResult{Status: storage.StepDone}, f.host.CompleteStep(ctx, acct.ID, f.id)
	}
	return StepResult{Status: storage.StepDone}, nil
}

// complete marks the account's step as paid, to be granted on the next Check.
func (f *fakeStep) complete(accountID uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.doneFor[accountID] = true
	delete(f.granted, accountID)
}

// newTestService builds a service over the memory engine with the given fake steps.
func newTestService(t *testing.T, steps ...*fakeStep) (*Service, *storage.MemoryEngine) {
	t.Helper()
	reg := Registry{}
	var cfgs []config.AccountStepConfig
	for _, st := range steps {
		st := st
		st.doneFor, st.granted = map[uint64]bool{}, map[uint64]bool{}
		reg.Register("fake-"+st.id, func(_ config.AccountStepConfig, deps Deps) (Step, error) {
			st.host = deps.Host
			return st, nil
		})
		cfgs = append(cfgs, config.AccountStepConfig{ID: st.id, Type: "fake-" + st.id, Enabled: true})
	}
	store := storage.NewMemoryEngine()
	svc, err := New(Config{PublicURL: "https://enode.example.org", AllowRegistration: true, SessionTTL: time.Hour,
		MinPasswordLength: 8, PollInterval: time.Minute}, store, reg, cfgs, nil)
	if err != nil {
		t.Fatal(err)
	}
	return svc, store
}

func TestPasswordHashRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: 'correct horse' output: %s", h)
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected hash format %q", h)
	}
	for pw, want := range map[string]bool{"correct horse": true, "correct horsE": false, "": false} {
		ok, err := VerifyPassword(h, pw)
		t.Logf("input: verify %q output: %v %v", pw, ok, err)
		if err != nil || ok != want {
			t.Errorf("VerifyPassword(%q) = %v, %v; want %v", pw, ok, err, want)
		}
	}
	h2, _ := HashPassword("correct horse")
	if h == h2 {
		t.Errorf("two hashes of one password are equal: the salt is not random")
	}
	if _, err := VerifyPassword("$bcrypt$nope", "x"); err == nil {
		t.Errorf("a malformed hash verified without error")
	}
}

func TestRegisterWithoutStepsIsActive(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	acct, err := svc.Register(ctx, "  Alice ", "alice@example.org", "password1")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: register ' Alice ' with no steps output: %q state=%s", acct.Username, acct.State)
	if acct.Username != "alice" || acct.State != storage.AccountActive {
		t.Fatalf("got %q %s, want alice active", acct.Username, acct.State)
	}
	if _, err := svc.Register(ctx, "ALICE", "", "password1"); AsError(err).MsgCode != CodeUsernameTaken {
		t.Fatalf("case-insensitive duplicate: err=%v, want %s", err, CodeUsernameTaken)
	}
}

func TestRegisterValidation(t *testing.T) {
	svc, _ := newTestService(t)
	cases := []struct{ user, email, pass, want string }{
		{"ab", "", "password1", CodeUsernameInvalid},
		{"bad name", "", "password1", CodeUsernameInvalid},
		{"good.name", "not-an-email", "password1", CodeEmailInvalid},
		{"good.name", "Bob <b@x.org>", "password1", CodeEmailInvalid},
		{"good.name", "", "short", CodeWeakPassword},
		{"good.name", "b@x.org", "password1", ""},
	}
	for _, c := range cases {
		_, err := svc.Register(context.Background(), c.user, c.email, c.pass)
		got := ""
		if err != nil {
			got = AsError(err).MsgCode
		}
		t.Logf("input: user=%q email=%q pass=%q output: %q", c.user, c.email, c.pass, got)
		if got != c.want {
			t.Errorf("Register(%q,%q,%q) = %q, want %q", c.user, c.email, c.pass, got, c.want)
		}
	}
	svc.cfg.AllowRegistration = false
	if _, err := svc.Register(context.Background(), "late.user", "", "password1"); AsError(err).MsgCode != CodeRegistrationClosed {
		t.Errorf("closed registration: err=%v", err)
	}
}

func TestLoginAuthenticateLogout(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Register(ctx, "bob", "", "password1"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := svc.Login(ctx, "bob", "wrong-password", "test"); AsError(err).Kind != KindUnauthenticated {
		t.Fatalf("wrong password: %v", err)
	}
	if _, _, _, err := svc.Login(ctx, "nobody", "password1", "test"); AsError(err).MsgCode != CodeInvalidCredentials {
		t.Fatalf("unknown user must look like a wrong password: %v", err)
	}
	token, sess, acct, err := svc.Login(ctx, "BOB", "password1", "eMuleQt test")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: login bob output: token=%d chars session=%d expires=%s", len(token), sess.ID, sess.ExpiresAt)
	got, _, err := svc.Authenticate(ctx, token)
	if err != nil || got.ID != acct.ID {
		t.Fatalf("Authenticate: %+v %v", got, err)
	}
	if _, _, err := svc.Authenticate(ctx, token+"x"); AsError(err).Kind != KindUnauthenticated {
		t.Fatalf("tampered token accepted: %v", err)
	}
	svc.SetClock(func() time.Time { return time.Now().Add(2 * time.Hour) })
	if _, _, err := svc.Authenticate(ctx, token); AsError(err).MsgCode != CodeSessionExpired {
		t.Fatalf("expired session accepted: %v", err)
	}
	svc.SetClock(time.Now)
	if err := svc.Logout(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Authenticate(ctx, token); err == nil {
		t.Fatalf("token still valid after logout")
	}
}

// TestStepsGateActivationInOrder walks an account through two steps, the second
// granting 30 days, then lets the period lapse and renews it.
func TestStepsGateActivationInOrder(t *testing.T) {
	email := &fakeStep{id: "email"}
	pay := &fakeStep{id: "payment", renewable: true, grantDays: 30}
	svc, _ := newTestService(t, email, pay)
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	svc.SetClock(func() time.Time { return now })

	acct, err := svc.Register(ctx, "carol", "", "password1")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := svc.Evaluate(ctx, &acct)
	t.Logf("input: new account, 2 steps output: state=%s pending=%v", st.State, pendingIDs(st))
	if st.State != storage.AccountPending || strings.Join(pendingIDs(st), ",") != "email,payment" {
		t.Fatalf("want pending [email payment], got %s %v", st.State, pendingIDs(st))
	}
	if st.Pending[1].URL != "https://enode.example.org/account/step/payment/" || st.Pending[1].MsgCode != "step.payment.pending" {
		t.Fatalf("pending step fields: %+v", st.Pending[1])
	}

	email.complete(acct.ID)
	st, _ = svc.Evaluate(ctx, &acct)
	t.Logf("input: email done output: state=%s pending=%v", st.State, pendingIDs(st))
	if st.State != storage.AccountPending || strings.Join(pendingIDs(st), ",") != "payment" {
		t.Fatalf("want pending [payment], got %s %v", st.State, pendingIDs(st))
	}

	pay.complete(acct.ID)
	st, _ = svc.Evaluate(ctx, &acct)
	t.Logf("input: payment done output: state=%s until=%s", st.State, st.AccessUntil)
	if st.State != storage.AccountActive || !st.AccessUntil.Equal(now.Add(30*24*time.Hour)) {
		t.Fatalf("want active for 30 days, got %s until %s", st.State, st.AccessUntil)
	}
	if stored, _ := svc.Store().AccountByID(ctx, acct.ID); stored.State != storage.AccountActive {
		t.Fatalf("state not persisted: %s", stored.State)
	}

	// Authorize takes the fast path while active: no step is checked.
	checks := pay.checks
	if s, err := svc.Authorize(ctx, &acct); err != nil || !s.Active() || pay.checks != checks {
		t.Fatalf("Authorize fast path: %+v %v (checks %d -> %d)", s, err, checks, pay.checks)
	}

	// The period lapses: the renewable step reopens, the one-off step stays done.
	now = now.Add(31 * 24 * time.Hour)
	pay.mu.Lock()
	delete(pay.doneFor, acct.ID)
	pay.mu.Unlock()
	st, _ = svc.Authorize(ctx, &acct)
	t.Logf("input: 31 days later output: state=%s pending=%v", st.State, pendingIDs(st))
	if st.State != storage.AccountExpired || strings.Join(pendingIDs(st), ",") != "payment" || st.MsgCode != CodeExpired {
		t.Fatalf("want expired with [payment], got %s %v %s", st.State, pendingIDs(st), st.MsgCode)
	}

	// Renewing grants from now, since the old period is over.
	pay.complete(acct.ID)
	st, _ = svc.Evaluate(ctx, &acct)
	t.Logf("input: renewed output: state=%s until=%s", st.State, st.AccessUntil)
	if st.State != storage.AccountActive || !st.AccessUntil.Equal(now.Add(30*24*time.Hour)) {
		t.Fatalf("renewal: %s until %s", st.State, st.AccessUntil)
	}
}

func TestGrantAccessExtendsAndLifetime(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc.SetClock(func() time.Time { return now })
	acct, _ := svc.Register(ctx, "dave", "", "password1")

	_ = svc.GrantAccess(ctx, acct.ID, "payment", 30)
	_ = svc.GrantAccess(ctx, acct.ID, "payment", 30)
	got, _ := store.AccountByID(ctx, acct.ID)
	t.Logf("input: two 30-day grants output: until=%s", got.AccessUntil)
	if !got.AccessUntil.Equal(now.Add(60 * 24 * time.Hour)) {
		t.Fatalf("grants did not stack: %s", got.AccessUntil)
	}
	_ = svc.GrantAccess(ctx, acct.ID, "payment", 0)
	got, _ = store.AccountByID(ctx, acct.ID)
	t.Logf("input: a 0-day (lifetime) grant output: until=%v", got.AccessUntil)
	if !got.AccessUntil.IsZero() {
		t.Fatalf("lifetime grant kept an expiry: %s", got.AccessUntil)
	}
}

func TestDisabledAccountStaysDisabled(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	acct, _ := svc.Register(ctx, "eve", "", "password1")
	acct.State = storage.AccountDisabled
	_ = store.UpdateAccount(ctx, &acct)
	st, err := svc.Authorize(ctx, &acct)
	t.Logf("input: disabled account output: %s %s", st.State, st.MsgCode)
	if err != nil || st.State != storage.AccountDisabled || st.MsgCode != CodeDisabled {
		t.Fatalf("got %+v %v", st, err)
	}
}

func TestDurableStepRefusesMemoryEngine(t *testing.T) {
	reg := Registry{}
	reg.Register("paid", func(config.AccountStepConfig, Deps) (Step, error) {
		return &fakeStep{id: "paid", durable: true}, nil
	})
	_, err := New(Config{}, storage.NewMemoryEngine(), reg, []config.AccountStepConfig{{ID: "paid", Type: "paid", Enabled: true}}, nil)
	t.Logf("input: durable step on the memory engine output: %v", err)
	if err == nil || !strings.Contains(err.Error(), "memory engine") {
		t.Fatalf("want a refusal naming the memory engine, got %v", err)
	}
	_, err = New(Config{}, storage.NewMemoryEngine(), reg, []config.AccountStepConfig{{ID: "x", Type: "nope", Enabled: true}}, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("unknown step type: %v", err)
	}
	var yamlErr error
	reg.Register("broken", func(config.AccountStepConfig, Deps) (Step, error) { return nil, errors.New("plans missing") })
	_, yamlErr = New(Config{}, storage.NewMemoryEngine(), reg, []config.AccountStepConfig{{ID: "b", Type: "broken", Enabled: true, Raw: yaml.Node{}}}, nil)
	if yamlErr == nil || !strings.Contains(yamlErr.Error(), `"b"`) {
		t.Fatalf("a factory error must name the step: %v", yamlErr)
	}
}

func pendingIDs(st Status) []string {
	var out []string
	for _, p := range st.Pending {
		out = append(out, p.ID)
	}
	return out
}
