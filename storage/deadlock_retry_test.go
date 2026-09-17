package storage

import (
	"errors"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
)

// 1213 and 1205 are the two lock errors, and they are not interchangeable.
// A wrapper that treats them as one is the classic bug: 1213 rolls the whole
// transaction back, whereas 1205 rolls back only the statement and leaves the
// transaction open and partially applied.
func TestIsRetryableLockError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"deadlock 1213", &mysqldriver.MySQLError{Number: mysqlErrDeadlock, Message: "Deadlock found"}, true},
		{"lock wait timeout 1205", &mysqldriver.MySQLError{Number: mysqlErrLockWaitTimeout, Message: "Lock wait timeout"}, true},
		{"data too long 1406 is not retryable", &mysqldriver.MySQLError{Number: 1406, Message: "Data too long"}, false},
		{"only_full_group_by 1055 is not retryable", &mysqldriver.MySQLError{Number: 1055, Message: "not in GROUP BY"}, false},
		{"duplicate entry 1062 is not retryable", &mysqldriver.MySQLError{Number: 1062, Message: "Duplicate entry"}, false},
		{"a wrapped deadlock is still retryable", errors.Join(errors.New("context"), &mysqldriver.MySQLError{Number: mysqlErrDeadlock}), true},
		{"a non-driver error is not retryable", errors.New("connection refused"), false},
		{"nil is not retryable", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isRetryableLockError(tc.err)
			t.Logf("input: %v -> output: retryable=%t", tc.err, got)
			if got != tc.want {
				t.Fatalf("got %t, want %t", got, tc.want)
			}
		})
	}
}

// The retry must actually re-run the statement, stop once it succeeds, and give
// up after the configured count rather than looping forever.
func TestExecRetryBehaviour(t *testing.T) {
	deadlock := &mysqldriver.MySQLError{Number: mysqlErrDeadlock, Message: "Deadlock found"}

	cases := []struct {
		name        string
		failures    int
		retries     int
		wantCalls   int
		wantSuccess bool
	}{
		{"succeeds first time", 0, 3, 1, true},
		{"succeeds on the second attempt", 1, 3, 2, true},
		{"succeeds on the last allowed attempt", 3, 3, 4, true},
		{"gives up after the retry budget", 4, 3, 4, false},
		{"a single retry still retries once", 1, 1, 2, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := &MySQLEngine{cfg: MySQLConfig{
				DeadlockDelay:   time.Millisecond,
				DeadlockRetries: tc.retries,
			}}

			calls := 0
			err := engine.execRetry("test statement", func() error {
				calls++
				if calls <= tc.failures {
					return deadlock
				}
				return nil
			})

			t.Logf("input: %d deadlocks, retries=%d", tc.failures, tc.retries)
			t.Logf("output: calls=%d err=%v", calls, err)

			if calls != tc.wantCalls {
				t.Fatalf("statement ran %d times, want %d", calls, tc.wantCalls)
			}
			if gotSuccess := err == nil; gotSuccess != tc.wantSuccess {
				t.Fatalf("success=%t, want %t (err=%v)", gotSuccess, tc.wantSuccess, err)
			}
		})
	}
}

// A non-lock error must fail immediately. Retrying "Data too long" would just
// repeat a guaranteed failure and delay the log line that explains it.
func TestExecRetryDoesNotRetryOtherErrors(t *testing.T) {
	engine := &MySQLEngine{cfg: MySQLConfig{DeadlockDelay: time.Millisecond, DeadlockRetries: 3}}
	tooLong := &mysqldriver.MySQLError{Number: 1406, Message: "Data too long for column 'name'"}

	calls := 0
	err := engine.execRetry("test statement", func() error {
		calls++
		return tooLong
	})

	t.Logf("input: a 1406 Data too long error, retries=3")
	t.Logf("output: calls=%d err=%v", calls, err)

	if calls != 1 {
		t.Fatalf("statement ran %d times, want 1", calls)
	}
	if !errors.Is(err, tooLong) {
		t.Fatalf("the original error was not returned: %v", err)
	}
}

// Defaults must be populated, or DeadlockRetries of 0 would disable retrying
// entirely while looking configured.
func TestNewMySQLEngineDeadlockDefaults(t *testing.T) {
	engine, err := NewMySQLEngine(MySQLConfig{
		Host: "localhost", Port: 3306, User: "enode", Database: "enode",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: DeadlockDelay=%s DeadlockRetries=%d", engine.cfg.DeadlockDelay, engine.cfg.DeadlockRetries)

	if engine.cfg.DeadlockDelay != defaultDeadlockDelay {
		t.Fatalf("DeadlockDelay=%s, want %s", engine.cfg.DeadlockDelay, defaultDeadlockDelay)
	}
	if engine.cfg.DeadlockRetries != defaultDeadlockRetries {
		t.Fatalf("DeadlockRetries=%d, want %d", engine.cfg.DeadlockRetries, defaultDeadlockRetries)
	}

	configured, err := NewMySQLEngine(MySQLConfig{
		Host: "localhost", Port: 3306, User: "enode", Database: "enode",
		DeadlockDelay: 250 * time.Millisecond, DeadlockRetries: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: configured DeadlockDelay=%s DeadlockRetries=%d",
		configured.cfg.DeadlockDelay, configured.cfg.DeadlockRetries)
	if configured.cfg.DeadlockDelay != 250*time.Millisecond || configured.cfg.DeadlockRetries != 7 {
		t.Fatal("explicit values were overwritten by the defaults")
	}
}

// Two statements that deadlocked must not retry in lockstep, and a file many offers
// contend for must see the pauses grow: each delay doubles per attempt, stays within
// the upper half of that value, and never passes maxDeadlockDelay.
func TestLockRetryDelayBacksOffWithJitter(t *testing.T) {
	engine := &MySQLEngine{cfg: MySQLConfig{DeadlockDelay: 100 * time.Millisecond}}
	for attempt := 0; attempt < 8; attempt++ {
		ceiling := min(100*time.Millisecond<<attempt, maxDeadlockDelay)
		lo, hi := time.Duration(1<<62), time.Duration(0)
		distinct := map[time.Duration]bool{}
		for i := 0; i < 200; i++ {
			d := engine.lockRetryDelay(attempt)
			lo, hi = min(lo, d), max(hi, d)
			distinct[d] = true
		}
		t.Logf("input: DeadlockDelay=100ms attempt=%d -> output: delays in [%s, %s], %d distinct of 200, want within [%s, %s]",
			attempt, lo, hi, len(distinct), ceiling/2, ceiling)
		if lo < ceiling/2 || hi > ceiling {
			t.Fatalf("attempt %d: delay range [%s, %s] outside [%s, %s]", attempt, lo, hi, ceiling/2, ceiling)
		}
		if len(distinct) < 100 {
			t.Fatalf("attempt %d: only %d distinct delays of 200 — the retries are not randomized", attempt, len(distinct))
		}
	}
}
