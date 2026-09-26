package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
)

// accountsDDL creates the account tables. Embedded rather than read from a path
// like misc/enode.sql: it has to run on existing databases too, so it must always
// be the version this binary expects.
//
//go:embed accounts_mysql.sql
var accountsDDL string

// mysqlErrDuplicateKey is ER_DUP_ENTRY.
const mysqlErrDuplicateKey = 1062

const accountColumns = `id,username,email,password_hash,state,access_until,created_at,updated_at`

const paymentColumns = `id,account_id,step_id,plan_id,provider,external_id,external_key,status,amount,currency,period_days,credited_at,revoked_at,created_at,updated_at`

// DurableAccounts is true: accounts live in the database.
func (m *MySQLEngine) DurableAccounts() bool { return true }

// InitAccounts creates the account tables when missing. Called at startup only when
// accounts are enabled, so a server without them never grows the tables.
func (m *MySQLEngine) InitAccounts(ctx context.Context) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	for _, stmt := range splitSQLStatements(accountsDDL) {
		if _, err := m.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("mysql create account tables: %w", err)
		}
	}
	return nil
}

func (m *MySQLEngine) CreateAccount(ctx context.Context, a *Account) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	now := time.Now().UTC()
	res, err := m.db.ExecContext(ctx,
		`INSERT INTO accounts(username,email,password_hash,state,access_until,created_at,updated_at) VALUES (?,?,?,?,?,?,?)`,
		a.Username, a.Email, a.PasswordHash, a.State, nullTime(a.AccessUntil), now, now)
	if isDuplicateKey(err) {
		return ErrUsernameTaken
	}
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	a.ID, a.CreatedAt, a.UpdatedAt = uint64(id), now, now
	return nil
}

func (m *MySQLEngine) AccountByID(ctx context.Context, id uint64) (Account, error) {
	if err := m.ensureDB(); err != nil {
		return Account{}, err
	}
	return scanAccount(m.db.QueryRowContext(ctx, `SELECT `+accountColumns+` FROM accounts WHERE id=?`, id))
}

func (m *MySQLEngine) AccountByUsername(ctx context.Context, username string) (Account, error) {
	if err := m.ensureDB(); err != nil {
		return Account{}, err
	}
	return scanAccount(m.db.QueryRowContext(ctx, `SELECT `+accountColumns+` FROM accounts WHERE username=?`, username))
}

func (m *MySQLEngine) UpdateAccount(ctx context.Context, a *Account) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	now := time.Now().UTC()
	res, err := m.db.ExecContext(ctx,
		`UPDATE accounts SET email=?,password_hash=?,state=?,access_until=?,updated_at=? WHERE id=?`,
		a.Email, a.PasswordHash, a.State, nullTime(a.AccessUntil), now, a.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// RowsAffected is 0 both for a missing row and, without CLIENT_FOUND_ROWS, for
		// an unchanged one — but updated_at always changes, so 0 means missing.
		return ErrAccountNotFound
	}
	a.UpdatedAt = now
	return nil
}

func (m *MySQLEngine) CountAccounts(ctx context.Context) (map[AccountState]int, error) {
	if err := m.ensureDB(); err != nil {
		return nil, err
	}
	rows, err := m.db.QueryContext(ctx, `SELECT state, COUNT(*) FROM accounts GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[AccountState]int{}
	for rows.Next() {
		var state AccountState
		var n int
		if err := rows.Scan(&state, &n); err != nil {
			return nil, err
		}
		out[state] = n
	}
	return out, rows.Err()
}

func (m *MySQLEngine) ListAccounts(ctx context.Context, filter AccountFilter, limit, offset int) ([]Account, error) {
	if err := m.ensureDB(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 1000
	}
	query := `SELECT ` + accountColumns + ` FROM accounts WHERE 1=1`
	args := []any{}
	if filter.State != 0 {
		query += ` AND state=?`
		args = append(args, filter.State)
	}
	if filter.Search != "" {
		// The column collation is case-insensitive; the pattern is escaped so a
		// search for "a_b" does not match "axb".
		like := "%" + escapeLike(filter.Search) + "%"
		query += ` AND (username LIKE ? OR email LIKE ?)`
		args = append(args, like, like)
	}
	query += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, max(offset, 0))
	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (m *MySQLEngine) AccountSteps(ctx context.Context, accountID uint64) ([]AccountStep, error) {
	if err := m.ensureDB(); err != nil {
		return nil, err
	}
	rows, err := m.db.QueryContext(ctx,
		`SELECT id,account_id,step_id,status,data,completed_at,created_at,updated_at FROM account_steps WHERE account_id=? ORDER BY id`,
		accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccountStep
	for rows.Next() {
		var st AccountStep
		var completed sql.NullTime
		if err := rows.Scan(&st.ID, &st.AccountID, &st.StepID, &st.Status, &st.Data, &completed, &st.CreatedAt, &st.UpdatedAt); err != nil {
			return nil, err
		}
		st.CompletedAt = completed.Time
		out = append(out, st)
	}
	return out, rows.Err()
}

func (m *MySQLEngine) UpsertAccountStep(ctx context.Context, st *AccountStep) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	now := time.Now().UTC()
	if _, err := m.db.ExecContext(ctx,
		`INSERT INTO account_steps(account_id,step_id,status,data,completed_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE status=VALUES(status),data=VALUES(data),completed_at=VALUES(completed_at),updated_at=VALUES(updated_at)`,
		st.AccountID, st.StepID, st.Status, st.Data, nullTime(st.CompletedAt), now, now); err != nil {
		return err
	}
	// LastInsertId is unreliable on the update path, so read the key back.
	if err := m.db.QueryRowContext(ctx,
		`SELECT id,created_at FROM account_steps WHERE account_id=? AND step_id=?`, st.AccountID, st.StepID,
	).Scan(&st.ID, &st.CreatedAt); err != nil {
		return err
	}
	st.UpdatedAt = now
	return nil
}

func (m *MySQLEngine) CreatePayment(ctx context.Context, p *Payment) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	now := time.Now().UTC()
	res, err := m.db.ExecContext(ctx,
		`INSERT INTO payments(account_id,step_id,plan_id,provider,external_id,external_key,status,amount,currency,period_days,credited_at,created_at,updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.AccountID, p.StepID, p.PlanID, p.Provider, nullString(p.ExternalID), p.ExternalKey, p.Status,
		p.Amount, p.Currency, p.PeriodDays, nullTime(p.CreditedAt), now, now)
	if isDuplicateKey(err) {
		return ErrPaymentDuplicate
	}
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	p.ID, p.CreatedAt, p.UpdatedAt = uint64(id), now, now
	return nil
}

func (m *MySQLEngine) UpdatePayment(ctx context.Context, p *Payment) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	now := time.Now().UTC()
	res, err := m.db.ExecContext(ctx,
		`UPDATE payments SET external_id=?,external_key=?,status=?,amount=?,currency=?,updated_at=? WHERE id=?`,
		nullString(p.ExternalID), p.ExternalKey, p.Status, p.Amount, p.Currency, now, p.ID)
	if isDuplicateKey(err) {
		return ErrPaymentDuplicate
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrPaymentNotFound
	}
	p.UpdatedAt = now
	return nil
}

func (m *MySQLEngine) PaymentByID(ctx context.Context, id uint64) (Payment, error) {
	if err := m.ensureDB(); err != nil {
		return Payment{}, err
	}
	return scanPayment(m.db.QueryRowContext(ctx, `SELECT `+paymentColumns+` FROM payments WHERE id=?`, id))
}

func (m *MySQLEngine) PaymentByExternal(ctx context.Context, provider, externalID string) (Payment, error) {
	if err := m.ensureDB(); err != nil {
		return Payment{}, err
	}
	if externalID == "" {
		return Payment{}, ErrPaymentNotFound
	}
	return scanPayment(m.db.QueryRowContext(ctx,
		`SELECT `+paymentColumns+` FROM payments WHERE provider=? AND external_id=?`, provider, externalID))
}

func (m *MySQLEngine) OpenPayments(ctx context.Context, limit int) ([]Payment, error) {
	if err := m.ensureDB(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 1000
	}
	return m.queryPayments(ctx,
		`SELECT `+paymentColumns+` FROM payments WHERE status IN (?,?) ORDER BY id LIMIT ?`,
		PaymentCreated, PaymentPending, limit)
}

func (m *MySQLEngine) PaymentsByAccount(ctx context.Context, accountID uint64, limit int) ([]Payment, error) {
	if err := m.ensureDB(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 1000
	}
	return m.queryPayments(ctx,
		`SELECT `+paymentColumns+` FROM payments WHERE account_id=? ORDER BY id DESC LIMIT ?`, accountID, limit)
}

func (m *MySQLEngine) MarkPaymentCredited(ctx context.Context, id uint64, at time.Time) (bool, error) {
	if err := m.ensureDB(); err != nil {
		return false, err
	}
	// The IS NULL predicate is the compare-and-set: of several concurrent callers,
	// InnoDB's row lock lets exactly one match.
	res, err := m.db.ExecContext(ctx,
		`UPDATE payments SET credited_at=?,updated_at=? WHERE id=? AND credited_at IS NULL`,
		at.UTC(), time.Now().UTC(), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		if _, err := m.PaymentByID(ctx, id); err != nil {
			return false, err
		}
	}
	return n == 1, nil
}

func (m *MySQLEngine) MarkPaymentRevoked(ctx context.Context, id uint64, at time.Time) (bool, error) {
	if err := m.ensureDB(); err != nil {
		return false, err
	}
	res, err := m.db.ExecContext(ctx,
		`UPDATE payments SET revoked_at=?,updated_at=? WHERE id=? AND credited_at IS NOT NULL AND revoked_at IS NULL`,
		at.UTC(), time.Now().UTC(), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		if _, err := m.PaymentByID(ctx, id); err != nil {
			return false, err
		}
	}
	return n == 1, nil
}

func (m *MySQLEngine) CreditedPayments(ctx context.Context, since time.Time, limit int) ([]Payment, error) {
	if err := m.ensureDB(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 1000
	}
	return m.queryPayments(ctx,
		`SELECT `+paymentColumns+` FROM payments WHERE credited_at >= ? AND revoked_at IS NULL ORDER BY credited_at DESC LIMIT ?`,
		since.UTC(), limit)
}

func (m *MySQLEngine) CreateSession(ctx context.Context, s *AccountSession) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	now := time.Now().UTC()
	res, err := m.db.ExecContext(ctx,
		`INSERT INTO account_sessions(account_id,token_hash,client,expires_at,created_at,updated_at) VALUES (?,?,?,?,?,?)`,
		s.AccountID, s.TokenHash, s.Client, s.ExpiresAt.UTC(), now, now)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	s.ID, s.CreatedAt, s.UpdatedAt = uint64(id), now, now
	return nil
}

func (m *MySQLEngine) SessionByTokenHash(ctx context.Context, tokenHash []byte) (AccountSession, error) {
	if err := m.ensureDB(); err != nil {
		return AccountSession{}, err
	}
	var s AccountSession
	err := m.db.QueryRowContext(ctx,
		`SELECT id,account_id,token_hash,client,expires_at,created_at,updated_at FROM account_sessions WHERE token_hash=?`,
		tokenHash,
	).Scan(&s.ID, &s.AccountID, &s.TokenHash, &s.Client, &s.ExpiresAt, &s.CreatedAt, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AccountSession{}, ErrSessionNotFound
	}
	return s, err
}

func (m *MySQLEngine) DeleteSession(ctx context.Context, id uint64) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	_, err := m.db.ExecContext(ctx, `DELETE FROM account_sessions WHERE id=?`, id)
	return err
}

func (m *MySQLEngine) DeleteExpiredSessions(ctx context.Context, now time.Time) (int, error) {
	if err := m.ensureDB(); err != nil {
		return 0, err
	}
	res, err := m.db.ExecContext(ctx, `DELETE FROM account_sessions WHERE expires_at < ?`, now.UTC())
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (m *MySQLEngine) queryPayments(ctx context.Context, query string, args ...any) ([]Payment, error) {
	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Payment
	for rows.Next() {
		p, err := scanPayment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// rowScanner is what *sql.Row and *sql.Rows have in common.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAccount(r rowScanner) (Account, error) {
	var a Account
	var access sql.NullTime
	err := r.Scan(&a.ID, &a.Username, &a.Email, &a.PasswordHash, &a.State, &access, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, ErrAccountNotFound
	}
	a.AccessUntil = access.Time
	return a, err
}

func scanPayment(r rowScanner) (Payment, error) {
	var p Payment
	var external sql.NullString
	var credited, revoked sql.NullTime
	err := r.Scan(&p.ID, &p.AccountID, &p.StepID, &p.PlanID, &p.Provider, &external, &p.ExternalKey, &p.Status,
		&p.Amount, &p.Currency, &p.PeriodDays, &credited, &revoked, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Payment{}, ErrPaymentNotFound
	}
	p.ExternalID, p.CreditedAt, p.RevokedAt = external.String, credited.Time, revoked.Time
	return p, err
}

// nullTime stores the zero time as NULL, which is how "not set" reads back.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isDuplicateKey(err error) bool {
	var mysqlErr *mysqldriver.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == mysqlErrDuplicateKey
}

// splitSQLStatements splits a DDL file into single statements, dropping comment
// lines, so it runs on the engine's normal pool without multiStatements.
func splitSQLStatements(ddl string) []string {
	var b strings.Builder
	for _, line := range strings.Split(ddl, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	var out []string
	for _, stmt := range strings.Split(b.String(), ";") {
		if stmt = strings.TrimSpace(stmt); stmt != "" {
			out = append(out, stmt)
		}
	}
	return out
}
