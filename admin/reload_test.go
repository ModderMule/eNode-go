package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// writeHdr marks a request as a dashboard write, as the page's fetch does.
func writeHdr(origin string) func(*http.Request) {
	return func(r *http.Request) {
		r.Header.Set(adminWriteHeader, "1")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
	}
}

func TestReloadConfigEndpoint(t *testing.T) {
	s, _ := newAuthServer("", "")
	calls := 0
	var fail error
	s.SetReloader(func() (ReloadResult, error) {
		calls++
		if fail != nil {
			return ReloadResult{}, fail
		}
		return ReloadResult{Applied: []string{"name", "gossip.enabled"}, RestartRequired: []string{"tcp.port"}}, nil
	})

	if code := do(s, "POST", "/api/reload-config", "", nil).Code; code != 403 || calls != 0 {
		t.Fatalf("reload without %s: %d calls=%d", adminWriteHeader, code, calls)
	}
	if code := do(s, "POST", "/api/reload-config", "", writeHdr("https://evil.example")).Code; code != 403 || calls != 0 {
		t.Fatalf("cross-origin reload: %d calls=%d", code, calls)
	}
	if code := do(s, "POST", "/api/reload-config", "203.0.113.4:999", writeHdr("")).Code; code != 403 || calls != 0 {
		t.Fatalf("off-box reload without credentials: %d calls=%d", code, calls)
	}
	if code := do(s, "GET", "/api/reload-config", "", nil).Code; code != 404 && code != 405 {
		t.Fatalf("GET must not reload: %d", code)
	}

	w := do(s, "POST", "/api/reload-config", "", writeHdr("http://admin.local"))
	var res ReloadResult
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	t.Logf("input: same-origin POST /api/reload-config from loopback")
	t.Logf("output: %d %s", w.Code, strings.TrimSpace(w.Body.String()))
	if w.Code != 200 || calls != 1 || len(res.Applied) != 2 || len(res.RestartRequired) != 1 {
		t.Fatalf("reload: %d calls=%d %+v", w.Code, calls, res)
	}

	fail = errors.New("config load failed: yaml: line 3: mapping values are not allowed in this context")
	w = do(s, "POST", "/api/reload-config", "", writeHdr(""))
	t.Logf("input: reload of an invalid config file")
	t.Logf("output: %d %s", w.Code, strings.TrimSpace(w.Body.String()))
	if w.Code != 422 || !strings.Contains(w.Body.String(), "config load failed") {
		t.Fatalf("failed reload: %d %s", w.Code, w.Body)
	}
}

// An unchanged file returns empty lists, not null: the page reads .length on both.
func TestReloadConfigEmptyResultIsLists(t *testing.T) {
	s, _ := newAuthServer("", "")
	s.SetReloader(func() (ReloadResult, error) { return ReloadResult{}, nil })
	w := do(s, "POST", "/api/reload-config", "", writeHdr(""))
	body := strings.TrimSpace(w.Body.String())
	t.Logf("input: reload with nothing changed output: %d %s", w.Code, body)
	if w.Code != 200 || body != `{"applied":[],"restartRequired":[]}` {
		t.Fatalf("unexpected body: %d %s", w.Code, body)
	}
}

func TestReloadConfigAbsentWithoutReloader(t *testing.T) {
	s, _ := newAuthServer("", "")
	code := do(s, "POST", "/api/reload-config", "", writeHdr("")).Code
	page := do(s, "GET", "/", "", nil).Body.String()
	t.Logf("input: no reloader set output: POST -> %d, button rendered=%t", code, strings.Contains(page, `id="reload"`))
	if code != 404 || strings.Contains(page, `id="reload"`) {
		t.Fatalf("reload must be absent: %d", code)
	}

	s.SetReloader(func() (ReloadResult, error) { return ReloadResult{}, nil })
	page = do(s, "GET", "/", "", nil).Body.String()
	t.Logf("input: reloader set output: button rendered=%t", strings.Contains(page, `id="reload"`))
	if !strings.Contains(page, `id="reload"`) || !strings.Contains(page, `id="msg"`) {
		t.Fatal("the dashboard must offer the reload button once a reloader is set")
	}
}

// A reload replaces the credentials and the rendered facts while the server runs.
func TestReloadReplacesCredentialsAndStatic(t *testing.T) {
	s, _ := newAuthServer("admin", "old")
	s.SetReloader(func() (ReloadResult, error) { return ReloadResult{}, nil })
	const remote = "203.0.113.4:999"
	auth := func(pass string) func(*http.Request) {
		return func(r *http.Request) { r.SetBasicAuth("admin", pass) }
	}

	before := do(s, "GET", "/", remote, auth("old")).Code
	s.SetCredentials("admin", "new")
	s.SetStatic(StaticInfo{Name: "renamed server"})
	oldPass := do(s, "GET", "/", remote, auth("old")).Code
	w := do(s, "GET", "/", remote, auth("new"))
	page := w.Body.String()
	t.Logf("input: password old -> new and name t -> %q", "renamed server")
	t.Logf("output: old password before=%d after=%d, new password=%d, name shown=%t, reload button kept=%t",
		before, oldPass, w.Code, strings.Contains(page, "renamed server"), strings.Contains(page, `id="reload"`))
	if before != 200 || oldPass != 401 || w.Code != 200 {
		t.Fatalf("credentials not replaced: %d %d %d", before, oldPass, w.Code)
	}
	if !strings.Contains(page, "renamed server") || !strings.Contains(page, `id="reload"`) {
		t.Fatal("SetStatic must replace the name and keep the Reload flag")
	}
	if code := do(s, "GET", "/accounts", "", nil).Code; code != 200 {
		t.Fatalf("SetStatic must keep the Accounts flag: /accounts -> %d", code)
	}
}
