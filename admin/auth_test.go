package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeAccounts is an AccountAdmin double holding one account.
type fakeAccounts struct {
	disabled bool
	days     int
	skipped  string
}

func (f *fakeAccounts) ListAccounts(context.Context, AccountQuery) ([]AccountRow, error) {
	return []AccountRow{{ID: 1, Username: "xena", State: "active"}}, nil
}
func (f *fakeAccounts) Account(_ context.Context, id uint64) (AccountDetail, error) {
	if id != 1 {
		return AccountDetail{}, ErrAccountNotFound
	}
	state := "active"
	if f.disabled {
		state = "disabled"
	}
	return AccountDetail{AccountRow: AccountRow{ID: 1, Username: "xena", State: state}}, nil
}
func (f *fakeAccounts) SetDisabled(_ context.Context, _ uint64, d bool) error {
	f.disabled = d
	return nil
}
func (f *fakeAccounts) AdjustAccess(_ context.Context, _ uint64, days int) error {
	f.days += days
	return nil
}
func (f *fakeAccounts) SkipStep(_ context.Context, _ uint64, step string) error {
	f.skipped = step
	return nil
}

func newAuthServer(user, pass string) (*Server, *fakeAccounts) {
	s := New(Config{Username: user, Password: pass}, StaticInfo{Name: "t"}, func() LiveStats { return LiveStats{} })
	fa := &fakeAccounts{}
	s.SetAccounts(fa)
	return s, fa
}

// do sends one request as if from remote; "" is loopback.
func do(s *Server, method, path, remote string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	var body *strings.Reader
	if method == http.MethodPost {
		body = strings.NewReader(`{"days":7,"step":"payment"}`)
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, "http://admin.local"+path, body)
	r.RemoteAddr = "127.0.0.1:5000"
	if remote != "" {
		r.RemoteAddr = remote
	}
	if mutate != nil {
		mutate(r)
	}
	w := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(w, r)
	return w
}

func TestIsLocalRequest(t *testing.T) {
	cases := []struct {
		remote, header string
		want           bool
	}{
		{"127.0.0.1:1", "", true},
		{"[::1]:1", "", true},
		{"127.0.0.1:1", "X-Forwarded-For", false},
		{"127.0.0.1:1", "Forwarded", false},
		{"192.0.2.7:1", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		if c.header != "" {
			r.Header.Set(c.header, "203.0.113.9")
		}
		got := IsLocalRequest(r)
		t.Logf("input: remote=%s proxyHeader=%q output: %v", c.remote, c.header, got)
		if got != c.want {
			t.Errorf("IsLocalRequest(%s, %q) = %v, want %v", c.remote, c.header, got, c.want)
		}
	}
}

func TestAdminAccessWithoutCredentials(t *testing.T) {
	s, _ := newAuthServer("", "")
	remote := "192.0.2.7:4000"
	cases := []struct {
		method, path, remote string
		want                 int
	}{
		{"GET", "/", remote, 200},
		{"GET", "/stats.json", remote, 200},
		{"GET", "/accounts", remote, 403},
		{"GET", "/api/accounts", remote, 403},
		{"GET", "/api/accounts", "", 200},
		{"GET", "/accounts", "", 200},
	}
	for _, c := range cases {
		code := do(s, c.method, c.path, c.remote, nil).Code
		t.Logf("input: no credentials, %s %s from %q output: %d", c.method, c.path, c.remote, code)
		if code != c.want {
			t.Errorf("%s %s from %q: %d, want %d", c.method, c.path, c.remote, code, c.want)
		}
	}
	// A loopback peer behind a proxy is not local.
	code := do(s, "GET", "/api/accounts", "", func(r *http.Request) { r.Header.Set("X-Forwarded-For", "203.0.113.9") }).Code
	if code != 403 {
		t.Errorf("proxied loopback request reached accounts: %d", code)
	}
}

func TestAdminAccessWithCredentials(t *testing.T) {
	s, _ := newAuthServer("root", "s3cret")
	remote := "192.0.2.7:4000"
	if w := do(s, "GET", "/", remote, nil); w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("remote without auth: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	if code := do(s, "GET", "/stats.json", remote, func(r *http.Request) { r.SetBasicAuth("root", "wrong") }).Code; code != 401 {
		t.Fatalf("wrong password: %d", code)
	}
	code := do(s, "GET", "/api/accounts", remote, func(r *http.Request) { r.SetBasicAuth("root", "s3cret") }).Code
	t.Logf("input: remote with the right credentials output: %d", code)
	if code != 200 {
		t.Fatalf("right credentials: %d", code)
	}
	if code := do(s, "GET", "/api/accounts", "", nil).Code; code != 200 {
		t.Fatalf("loopback needs no credentials, got %d", code)
	}
}

func TestAdminWritesNeedHeaderAndSameOrigin(t *testing.T) {
	s, fa := newAuthServer("", "")
	if code := do(s, "POST", "/api/accounts/1/disable", "", nil).Code; code != 403 || fa.disabled {
		t.Fatalf("write without %s: %d disabled=%v", adminWriteHeader, code, fa.disabled)
	}
	hdr := func(origin string) func(*http.Request) {
		return func(r *http.Request) {
			r.Header.Set(adminWriteHeader, "1")
			r.Header.Set("Content-Type", "application/json")
			if origin != "" {
				r.Header.Set("Origin", origin)
			}
		}
	}
	if code := do(s, "POST", "/api/accounts/1/disable", "", hdr("https://evil.example")).Code; code != 403 || fa.disabled {
		t.Fatalf("cross-origin write: %d disabled=%v", code, fa.disabled)
	}
	w := do(s, "POST", "/api/accounts/1/disable", "", hdr("http://admin.local"))
	var d AccountDetail
	_ = json.Unmarshal(w.Body.Bytes(), &d)
	t.Logf("input: same-origin disable output: %d state=%s", w.Code, d.State)
	if w.Code != 200 || !fa.disabled || d.State != "disabled" {
		t.Fatalf("same-origin disable: %d %s", w.Code, w.Body)
	}
	if code := do(s, "POST", "/api/accounts/1/adjust", "", hdr("")).Code; code != 200 || fa.days != 7 {
		t.Fatalf("adjust: %d days=%d", code, fa.days)
	}
	if code := do(s, "POST", "/api/accounts/1/skip-step", "", hdr("")).Code; code != 200 || fa.skipped != "payment" {
		t.Fatalf("skip-step: %d %q", code, fa.skipped)
	}
	if code := do(s, "POST", "/api/accounts/1/explode", "", hdr("")).Code; code != 404 {
		t.Fatalf("unknown action: %d", code)
	}
	if code := do(s, "POST", "/api/accounts/9/enable", "", hdr("")).Code; code != 404 {
		t.Fatalf("unknown account: %d", code)
	}
}

func TestAccountsPagesAbsentWithoutAccounts(t *testing.T) {
	s := New(Config{}, StaticInfo{Name: "t"}, func() LiveStats { return LiveStats{} })
	for _, p := range []string{"/accounts", "/api/accounts", "/api/accounts/1"} {
		code := do(s, "GET", p, "", nil).Code
		t.Logf("input: %s with accounts off output: %d", p, code)
		if code != 404 {
			t.Errorf("%s: %d, want 404", p, code)
		}
	}
}
