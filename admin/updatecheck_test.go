package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v0.3.4", "v0.3.3", true},
		{"v0.4.0", "v0.3.3", true},
		{"v1.0.0", "v0.3.3", true},
		{"v0.3.10", "v0.3.9", true},
		{"v0.3.3", "v0.3.3", false},
		{"v0.3.2", "v0.3.3", false},
		{"v0.2.9", "v0.3.0", false},
		{"0.3.4", "v0.3.3", false},
		{"v0.3", "v0.3.3", false},
		{"v0.3.4-rc1", "v0.3.3", false},
		{"v0.3.+4", "v0.3.3", false},
		{"", "v0.3.3", false},
		{"v0.3.4", "dev", false},
	}
	for _, c := range cases {
		got := newerVersion(c.latest, c.current)
		t.Logf("input: latest=%q current=%q output: newer=%v", c.latest, c.current, got)
		if got != c.want {
			t.Errorf("newerVersion(%q, %q)=%v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

func TestTagFromLocation(t *testing.T) {
	cases := []struct {
		location string
		wantTag  string
		ok       bool
	}{
		{ReleaseRepoURL + "/releases/tag/v0.3.3", "v0.3.3", true},
		{ReleaseRepoURL + "/releases", "", false},
		{ReleaseRepoURL + "/releases/tag/nightly", "", false},
		{ReleaseRepoURL + "/releases/tag/v0.3.3/../../evil", "", false},
		{"https://evil.example/ModderMule/eNode-go/releases/tag/v0.3.3", "", false},
		{"/ModderMule/eNode-go/releases/tag/v0.3.3", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		tag, url, ok := tagFromLocation(c.location, ReleaseRepoURL)
		t.Logf("input: %q output: tag=%q url=%q ok=%v", c.location, tag, url, ok)
		if ok != c.ok || tag != c.wantTag {
			t.Errorf("tagFromLocation(%q)=(%q, %v), want (%q, %v)", c.location, tag, ok, c.wantTag, c.ok)
		}
		if ok && url != c.location {
			t.Errorf("url=%q, want the Location itself %q", url, c.location)
		}
	}
}

// TestCheckAgainstFakeGitHub drives Check against a stand-in for github.com that
// answers /releases/latest the way GitHub does: a 302 to /releases/tag/<tag>.
func TestCheckAgainstFakeGitHub(t *testing.T) {
	var (
		status   atomic.Int32
		location atomic.Value
		followed atomic.Bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/releases/latest" {
			followed.Store(true)
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodHead {
			t.Errorf("method=%s, want HEAD", r.Method)
		}
		if loc, _ := location.Load().(string); loc != "" {
			w.Header().Set("Location", loc)
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()

	c := NewUpdateChecker("v0.3.3")
	c.repoURL = srv.URL
	if c.Info() != nil {
		t.Fatalf("Info() before any check = %+v, want nil", c.Info())
	}

	steps := []struct {
		name          string
		status        int
		location      string
		wantErr       bool
		wantLatest    string
		wantAvailable bool
	}{
		{"same version", http.StatusFound, srv.URL + "/releases/tag/v0.3.3", false, "v0.3.3", false},
		{"newer version", http.StatusFound, srv.URL + "/releases/tag/v0.3.4", false, "v0.3.4", true},
		// Failures keep the previous result rather than clearing the hint.
		{"not found", http.StatusNotFound, "", true, "v0.3.4", true},
		{"no releases page", http.StatusOK, "", true, "v0.3.4", true},
		{"foreign redirect", http.StatusFound, "https://evil.example/releases/tag/v9.9.9", true, "v0.3.4", true},
		{"older version", http.StatusFound, srv.URL + "/releases/tag/v0.3.2", false, "v0.3.2", false},
	}
	for _, s := range steps {
		status.Store(int32(s.status))
		location.Store(s.location)
		err := c.Check(context.Background())
		info := c.Info()
		t.Logf("input: %s status=%d location=%q output: err=%v info=%+v", s.name, s.status, s.location, err, info)
		if (err != nil) != s.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", s.name, err, s.wantErr)
		}
		if info == nil {
			t.Fatalf("%s: Info() = nil after a successful check", s.name)
		}
		if info.Latest != s.wantLatest || info.Available != s.wantAvailable {
			t.Errorf("%s: latest=%q available=%v, want %q %v", s.name, info.Latest, info.Available, s.wantLatest, s.wantAvailable)
		}
	}
	if followed.Load() {
		t.Errorf("checker followed the redirect; it must read Location only")
	}
}

func TestInfoNilChecker(t *testing.T) {
	var c *UpdateChecker
	info := c.Info()
	t.Logf("input: nil checker output: %+v", info)
	if info != nil {
		t.Errorf("nil checker Info()=%+v, want nil", info)
	}
}
