package admin

import (
	"net/http"
	"strings"
	"testing"
)

// newPprofServer builds a dashboard with the profiler on or off.
func newPprofServer(pprof bool, user, pass string) *Server {
	return New(Config{Username: user, Password: pass, Pprof: pprof}, StaticInfo{Name: "t"}, func() LiveStats { return LiveStats{} })
}

// TestPprofServedToLoopback covers the profiler routes: served to loopback when on, a 404
// when off.
func TestPprofServedToLoopback(t *testing.T) {
	cases := []struct {
		pprof bool
		path  string
		want  int
	}{
		{true, "/debug/pprof/", http.StatusOK},
		{true, "/debug/pprof/heap", http.StatusOK},
		{true, "/debug/pprof/goroutine?debug=1", http.StatusOK},
		{true, "/debug/pprof/cmdline", http.StatusOK},
		{false, "/debug/pprof/", http.StatusNotFound},
		{false, "/debug/pprof/heap", http.StatusNotFound},
	}
	for _, c := range cases {
		w := do(newPprofServer(c.pprof, "", ""), http.MethodGet, c.path, "", nil)
		t.Logf("input: pprof=%v GET %s from loopback; output: %d (%d bytes)", c.pprof, c.path, w.Code, w.Body.Len())
		if w.Code != c.want {
			t.Errorf("pprof=%v %s = %d, want %d", c.pprof, c.path, w.Code, c.want)
		}
	}
	w := do(newPprofServer(true, "", ""), http.MethodGet, "/debug/pprof/", "", nil)
	if !strings.Contains(w.Body.String(), "heap") {
		t.Error("the profile index does not list the heap profile")
	}
}

// TestPprofGuardedOffBox: an off-box client needs the credentials when they are set, and
// is refused outright without them, like every sensitive admin route.
func TestPprofGuardedOffBox(t *testing.T) {
	const remote = "192.0.2.7:4000"
	cases := []struct {
		name       string
		user, pass string
		auth       bool
		want       int
	}{
		{"no credentials configured", "", "", false, http.StatusForbidden},
		{"credentials configured, none sent", "admin", "secret", false, http.StatusUnauthorized},
		{"credentials configured and sent", "admin", "secret", true, http.StatusOK},
	}
	for _, c := range cases {
		s := newPprofServer(true, c.user, c.pass)
		w := do(s, http.MethodGet, "/debug/pprof/heap", remote, func(r *http.Request) {
			if c.auth {
				r.SetBasicAuth(c.user, c.pass)
			}
		})
		t.Logf("input: %s, GET /debug/pprof/heap from %s; output: %d", c.name, remote, w.Code)
		if w.Code != c.want {
			t.Errorf("%s: %d, want %d", c.name, w.Code, c.want)
		}
	}
}

// TestPprofBrowserGetsDownloadPage covers a browser opening a binary profile: a page with
// a download link, not a nameless file download. curl, go tool pprof, the download link
// and the text view still get the profile itself.
func TestPprofBrowserGetsDownloadPage(t *testing.T) {
	browser := func(r *http.Request) { r.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8") }
	cases := []struct {
		path     string
		mutate   func(*http.Request)
		wantType string
		wantBody string
	}{
		{"/debug/pprof/heap", browser, "text/html", `href="?download=1"`},
		{"/debug/pprof/goroutine", browser, "text/html", "View as text"},
		{"/debug/pprof/profile?seconds=5", browser, "text/html", "download=1&amp;seconds=5"},
		{"/debug/pprof/heap?download=1", browser, "application/octet-stream", ""},
		{"/debug/pprof/heap?debug=1", browser, "text/plain", "heap profile"},
		{"/debug/pprof/heap", nil, "application/octet-stream", ""},
		{"/debug/pprof/", browser, "text/html", "Types of profiles available"},
		{"/debug/pprof/nosuch", browser, "text/plain", "Unknown profile"},
	}
	for _, c := range cases {
		w := do(newPprofServer(true, "", ""), http.MethodGet, c.path, "", c.mutate)
		ct := w.Header().Get("Content-Type")
		t.Logf("input: GET %s browser=%v; output: %d %s (%d bytes)", c.path, c.mutate != nil, w.Code, ct, w.Body.Len())
		if !strings.HasPrefix(ct, c.wantType) {
			t.Errorf("%s: Content-Type %q, want %s", c.path, ct, c.wantType)
		}
		if !strings.Contains(w.Body.String(), c.wantBody) {
			t.Errorf("%s: body lacks %q", c.path, c.wantBody)
		}
	}
}
