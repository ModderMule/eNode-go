package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"enode/logging"
)

// AccountAdmin is what the dashboard needs to manage Meta API accounts. The caller
// adapts the accounts service to it, so this package keeps no dependency on it.
type AccountAdmin interface {
	ListAccounts(ctx context.Context, q AccountQuery) ([]AccountRow, error)
	Account(ctx context.Context, id uint64) (AccountDetail, error)
	SetDisabled(ctx context.Context, id uint64, disabled bool) error
	// AdjustAccess moves the access end by days, positive or negative.
	AdjustAccess(ctx context.Context, id uint64, days int) error
	// SkipStep closes a registration step without it being done.
	SkipStep(ctx context.Context, id uint64, stepID string) error
}

// ErrAccountNotFound is what an AccountAdmin returns for an unknown id.
var ErrAccountNotFound = errors.New("account not found")

// AccountQuery filters the account list.
type AccountQuery struct {
	// State is "", "pending", "active", "expired" or "disabled".
	State  string
	Search string
	Limit  int
	Offset int
}

// AccountRow is one account in the list.
type AccountRow struct {
	ID          uint64 `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	State       string `json:"state"`
	AccessUntil string `json:"accessUntil"` // RFC 3339, "" = no expiry
	CreatedAt   string `json:"createdAt"`
}

// AccountDetail is one account with its steps and payments.
type AccountDetail struct {
	AccountRow
	Steps    []AccountStepRow `json:"steps"`
	Payments []PaymentRow     `json:"payments"`
}

// AccountStepRow is one configured step for the account.
type AccountStepRow struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Status      string `json:"status"` // pending, done, failed, skipped
	CompletedAt string `json:"completedAt"`
}

// PaymentRow is one payment of the account.
type PaymentRow struct {
	ID         uint64 `json:"id"`
	Provider   string `json:"provider"`
	ExternalID string `json:"externalId"`
	Plan       string `json:"plan"`
	Status     string `json:"status"`
	Amount     string `json:"amount"`
	Currency   string `json:"currency"`
	PeriodDays uint32 `json:"periodDays"`
	CreatedAt  string `json:"createdAt"`
	CreditedAt string `json:"creditedAt"`
	RevokedAt  string `json:"revokedAt"`
}

// SetAccounts enables the account pages. Call before Start.
func (s *Server) SetAccounts(a AccountAdmin) {
	s.accounts = a
	s.static.Accounts = a != nil
}

// FormatTime renders a time for the JSON rows, "" for the zero time.
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (s *Server) handleAccountsPage(w http.ResponseWriter, r *http.Request) {
	if s.accounts == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := accountsTemplate.Execute(w, s.static); err != nil {
		logging.Warnf("admin accounts page render error: %v", err)
	}
}

func (s *Server) handleAccountList(w http.ResponseWriter, r *http.Request) {
	if s.accounts == nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	rows, err := s.accounts.ListAccounts(r.Context(), AccountQuery{
		State: q.Get("state"), Search: q.Get("q"), Limit: 50, Offset: max(offset, 0),
	})
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, err)
		return
	}
	if rows == nil {
		rows = []AccountRow{}
	}
	writeJSON(w, rows)
}

func (s *Server) handleAccountDetail(w http.ResponseWriter, r *http.Request) {
	id, ok := s.accountID(w, r)
	if !ok {
		return
	}
	d, err := s.accounts.Account(r.Context(), id)
	if err != nil {
		writeAccountError(w, err)
		return
	}
	writeJSON(w, d)
}

// accountAction is the body of POST /api/accounts/{id}/{action}.
type accountAction struct {
	Days int    `json:"days"`
	Step string `json:"step"`
}

func (s *Server) handleAccountAction(w http.ResponseWriter, r *http.Request) {
	id, ok := s.accountID(w, r)
	if !ok {
		return
	}
	var body accountAction
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			writeJSONError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
			return
		}
	}
	action := r.PathValue("action")
	var err error
	switch action {
	case "disable":
		err = s.accounts.SetDisabled(r.Context(), id, true)
	case "enable":
		err = s.accounts.SetDisabled(r.Context(), id, false)
	case "adjust":
		if body.Days == 0 || body.Days < -3650 || body.Days > 3650 {
			writeJSONError(w, http.StatusBadRequest, errors.New("days must be between -3650 and 3650 and not 0"))
			return
		}
		err = s.accounts.AdjustAccess(r.Context(), id, body.Days)
	case "skip-step":
		err = s.accounts.SkipStep(r.Context(), id, body.Step)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeAccountError(w, err)
		return
	}
	logging.Infof("admin dashboard: account %d %s %+v by %s", id, action, body, r.RemoteAddr)
	d, err := s.accounts.Account(r.Context(), id)
	if err != nil {
		writeAccountError(w, err)
		return
	}
	writeJSON(w, d)
}

func (s *Server) accountID(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	if s.accounts == nil {
		http.NotFound(w, r)
		return 0, false
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		writeJSONError(w, http.StatusBadRequest, errors.New("invalid account id"))
		return 0, false
	}
	return id, true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logging.Warnf("admin dashboard encode error: %v", err)
	}
}

func writeJSONError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// writeAccountError maps an AccountAdmin error. Anything but not-found is the
// operator's to read: the dashboard is not public.
func writeAccountError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrAccountNotFound) {
		writeJSONError(w, http.StatusNotFound, err)
		return
	}
	writeJSONError(w, http.StatusConflict, err)
}
