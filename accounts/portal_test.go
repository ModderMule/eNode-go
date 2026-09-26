package accounts

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var csrfPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// portalClient is a browser: a cookie jar and helpers that carry the CSRF field.
type portalClient struct {
	t    *testing.T
	base string
	http *http.Client
}

func newPortal(t *testing.T, steps ...*fakeStep) (*portalClient, *Service) {
	t.Helper()
	svc, _ := newTestService(t, steps...)
	srv := httptest.NewServer(NewWeb(svc, PortalConfig{ServerName: "test-server"}).Handler())
	t.Cleanup(srv.Close)
	svc.cfg.PublicURL = srv.URL
	jar, _ := cookiejar.New(nil)
	return &portalClient{t: t, base: srv.URL, http: &http.Client{Jar: jar}}, svc
}

func (c *portalClient) get(path string) (int, string) {
	c.t.Helper()
	resp, err := c.http.Get(c.base + path)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// post submits a form, taking the CSRF token from the page at formPath first.
func (c *portalClient) post(formPath, action string, form url.Values) (int, string, string) {
	c.t.Helper()
	_, page := c.get(formPath)
	if m := csrfPattern.FindStringSubmatch(page); m != nil && form.Get("csrf") == "" {
		form.Set("csrf", m[1])
	}
	resp, err := c.http.PostForm(c.base+action, form)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Request.URL.Path + "?" + resp.Request.URL.RawQuery, string(b)
}

func TestPortalRegisterLoginLogout(t *testing.T) {
	pay := &fakeStep{id: "payment", renewable: true, grantDays: 30}
	c, svc := newPortal(t, pay)

	code, body := c.get("/account")
	t.Logf("input: GET /account logged out output: %d, login form=%v", code, strings.Contains(body, `action="/account/login"`))
	if !strings.Contains(body, `action="/account/login"`) {
		t.Fatalf("logged-out /account did not lead to the login form")
	}

	_, landed, body := c.post("/account/register", "/account/register", url.Values{
		"username": {"frank"}, "email": {""}, "password": {"password1"}, "password2": {"password1"},
	})
	t.Logf("input: register frank output: landed on %s", landed)
	if !strings.HasPrefix(landed, "/account?n=account.registered") {
		t.Fatalf("register landed on %s", landed)
	}
	if !strings.Contains(body, "frank") || !strings.Contains(body, "/account/step/payment/") {
		t.Fatalf("account page lacks the user or the open payment step:\n%s", body)
	}
	if !strings.Contains(body, "Your account has been created.") {
		t.Fatalf("registration notice missing")
	}

	// A form without the CSRF field is refused.
	resp, err := c.http.PostForm(c.base+"/account/logout", url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	t.Logf("input: logout without csrf output: landed on %s", resp.Request.URL)
	if !strings.Contains(resp.Request.URL.RawQuery, CodeInvalidForm) {
		t.Fatalf("logout without CSRF was not refused: %s", resp.Request.URL)
	}
	if _, body := c.get("/account"); !strings.Contains(body, "frank") {
		t.Fatalf("session lost after a refused logout")
	}

	_, landed, _ = c.post("/account", "/account/logout", url.Values{})
	t.Logf("input: logout output: landed on %s", landed)
	if !strings.HasPrefix(landed, "/account/login?n=account.logged_out") {
		t.Fatalf("logout landed on %s", landed)
	}

	_, landed, body = c.post("/account/login", "/account/login", url.Values{"username": {"frank"}, "password": {"nope-nope"}})
	if !strings.Contains(body, "Wrong username or password.") {
		t.Fatalf("wrong password not reported (landed %s)", landed)
	}
	_, landed, _ = c.post("/account/login", "/account/login", url.Values{"username": {"Frank"}, "password": {"password1"}})
	t.Logf("input: login Frank output: landed on %s", landed)
	if landed != "/account?" {
		t.Fatalf("login landed on %s", landed)
	}

	// Completing the step activates the account on the next page view.
	acct, _ := svc.Store().AccountByUsername(t.Context(), "frank")
	pay.complete(acct.ID)
	_, body = c.get("/account")
	if !strings.Contains(body, `class="ok">active`) {
		t.Fatalf("account not shown active after the step completed:\n%s", body)
	}
	if !strings.Contains(body, "Renew or extend") {
		t.Fatalf("an active account with a paid period shows no renewal link")
	}
}

func TestPortalGermanAndHeaders(t *testing.T) {
	c, _ := newPortal(t)
	req, _ := http.NewRequest(http.MethodGet, c.base+"/account/register", nil)
	req.Header.Set("Accept-Language", "de-DE,de;q=0.9")
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	csp := resp.Header.Get("Content-Security-Policy")
	t.Logf("input: GET register, Accept-Language de output: german=%v csp=%q", strings.Contains(string(b), "Benutzername"), csp)
	if !strings.Contains(string(b), "Benutzername") || !strings.Contains(string(b), `lang="de"`) {
		t.Fatalf("page not in German")
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("security headers missing: csp=%q cache=%q", csp, resp.Header.Get("Cache-Control"))
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == csrfCookie && (!ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode) {
			t.Fatalf("csrf cookie flags: %+v", ck)
		}
	}
}

func TestPortalRejectsMismatchedPasswordsAndNoticeInjection(t *testing.T) {
	c, _ := newPortal(t)
	_, _, body := c.post("/account/register", "/account/register", url.Values{
		"username": {"gina"}, "password": {"password1"}, "password2": {"password2"},
	})
	if !strings.Contains(body, "The passwords do not match.") || !strings.Contains(body, `value="gina"`) {
		t.Fatalf("mismatch not reported or username not kept")
	}
	// Only known MsgCodes become notices: arbitrary text in ?n= is ignored.
	_, body = c.get("/account/login?n=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
	t.Logf("input: ?n=<script> output: reflected=%v", strings.Contains(body, "alert(1)"))
	if strings.Contains(body, "alert(1)") {
		t.Fatalf("an unknown notice code was reflected")
	}
}
