package accounts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"enode/internal/ratelimit"
	"enode/locales"
	"enode/logging"
	"enode/storage"
)

// The account website: register, log in, see the account and continue its open
// steps. Plain server-rendered HTML with no script, mounted under /account/ on the
// Meta API's HTTP listener. A step mounts its own pages under StepPath(id).

//go:embed html/*.html
var portalFS embed.FS

var portalTemplates = template.Must(template.ParseFS(portalFS, "html/*.html"))

const (
	sessionCookie = "enode_session"
	csrfCookie    = "enode_csrf"
	csrfField     = "csrf"
)

// PortalConfig is the website's own settings.
type PortalConfig struct {
	// ServerName is shown in the page title and footer.
	ServerName string
	// TrustForwardedFor takes client addresses from X-Forwarded-For.
	TrustForwardedFor bool
}

// Web serves the account website. It implements Portal for the steps' pages.
type Web struct {
	svc    *Service
	cfg    PortalConfig
	secure bool
	// Separate budgets: a sign-up flood must not lock existing users out of logging in.
	loginLimit    *ratelimit.Limiter
	registerLimit *ratelimit.Limiter
}

type csrfKey struct{}

// NewWeb returns the website for svc.
func NewWeb(svc *Service, cfg PortalConfig) *Web {
	return &Web{
		svc:           svc,
		cfg:           cfg,
		secure:        strings.HasPrefix(svc.PublicURL(), "https://"),
		loginLimit:    ratelimit.New(20),
		registerLimit: ratelimit.New(5),
	}
}

// Handler returns the website's routes, wrapped in its security headers and CSRF
// cookie handling. Mount it at /account/ (and /account).
func (w *Web) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /account", w.handleAccount)
	mux.HandleFunc("GET /account/{$}", w.handleAccount)
	mux.HandleFunc("GET /account/register", w.handleRegisterForm)
	mux.HandleFunc("POST /account/register", w.handleRegister)
	mux.HandleFunc("GET /account/login", w.handleLoginForm)
	mux.HandleFunc("POST /account/login", w.handleLogin)
	mux.HandleFunc("POST /account/logout", w.handleLogout)
	for _, step := range w.svc.Steps() {
		step.Routes(mux, w)
	}
	return w.middleware(mux)
}

// Account returns the logged-in account from the session cookie. Part of Portal.
func (w *Web) Account(r *http.Request) (storage.Account, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return storage.Account{}, false
	}
	acct, _, err := w.svc.Authenticate(r.Context(), c.Value)
	if err != nil {
		return storage.Account{}, false
	}
	return acct, true
}

// Lang negotiates the page language. Part of Portal.
func (w *Web) Lang(r *http.Request) string { return locales.Negotiate(r.Header.Get("Accept-Language")) }

// Render writes a page. Part of Portal.
func (w *Web) Render(rw http.ResponseWriter, r *http.Request, title string, body template.HTML, noticeCode string) {
	lang := w.Lang(r)
	acct, loggedIn := w.Account(r)
	data := map[string]any{
		"Lang":       lang,
		"Title":      title,
		"ServerName": w.cfg.ServerName,
		"Body":       body,
		"CSRF":       w.CSRFField(r),
		"LoggedIn":   loggedIn,
		"Username":   acct.Username,
		"T":          func(code string) string { return locales.T(lang, code) },
	}
	if noticeCode == "" {
		noticeCode = r.URL.Query().Get("n")
	}
	if noticeCode != "" && locales.Has(noticeCode) {
		data["Notice"] = locales.T(lang, noticeCode)
	}
	var buf bytes.Buffer
	if err := portalTemplates.ExecuteTemplate(&buf, "layout", data); err != nil {
		logging.Errorf("accounts: render %q: %v", title, err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = rw.Write(buf.Bytes())
}

// CSRFField is the hidden input carrying the request's CSRF token. Part of Portal.
func (w *Web) CSRFField(r *http.Request) template.HTML {
	token, _ := r.Context().Value(csrfKey{}).(string)
	return template.HTML(`<input type="hidden" name="` + csrfField + `" value="` + template.HTMLEscapeString(token) + `">`)
}

// CheckCSRF compares the form field with the cookie (double submit). Part of Portal.
func (w *Web) CheckCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	if err != nil || c.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostFormValue(csrfField))) == 1
}

// Redirect sends the browser to a site path with an optional notice. Part of Portal.
func (w *Web) Redirect(rw http.ResponseWriter, r *http.Request, path, noticeCode string) {
	if noticeCode != "" {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		path += sep + "n=" + url.QueryEscape(noticeCode)
	}
	http.Redirect(rw, r, path, http.StatusSeeOther)
}

// URL is the absolute public URL of a site path. Part of Portal.
func (w *Web) URL(path string) string { return w.svc.PublicURL() + path }

// ClientIP is the request's client address. Part of Portal.
func (w *Web) ClientIP(r *http.Request) string { return ratelimit.ClientIP(r, w.cfg.TrustForwardedFor) }

func (w *Web) handleRegisterForm(rw http.ResponseWriter, r *http.Request) {
	lang := w.Lang(r)
	if !w.svc.AllowRegistration() {
		w.Render(rw, r, locales.T(lang, "ui.register"), "", CodeRegistrationClosed)
		return
	}
	w.renderRegister(rw, r, "", "", "")
}

func (w *Web) handleRegister(rw http.ResponseWriter, r *http.Request) {
	username, email := r.PostFormValue("username"), r.PostFormValue("email")
	if !w.CheckCSRF(r) {
		w.renderRegister(rw, r, username, email, CodeInvalidForm)
		return
	}
	if !w.registerLimit.Allow(w.ClientIP(r)) {
		w.renderRegister(rw, r, username, email, CodeRateLimited)
		return
	}
	password := r.PostFormValue("password")
	if password != r.PostFormValue("password2") {
		w.renderRegister(rw, r, username, email, CodePasswordMismatch)
		return
	}
	if _, err := w.svc.Register(r.Context(), username, email, password); err != nil {
		w.logIfServerError("register", err)
		w.renderRegister(rw, r, username, email, AsError(err).MsgCode)
		return
	}
	if err := w.startSession(rw, r, username, password); err != nil {
		w.Redirect(rw, r, "/account/login", CodeRegistered)
		return
	}
	w.Redirect(rw, r, "/account", CodeRegistered)
}

func (w *Web) handleLoginForm(rw http.ResponseWriter, r *http.Request) {
	w.renderLogin(rw, r, "", "")
}

func (w *Web) handleLogin(rw http.ResponseWriter, r *http.Request) {
	username := r.PostFormValue("username")
	if !w.CheckCSRF(r) {
		w.renderLogin(rw, r, username, CodeInvalidForm)
		return
	}
	if !w.loginLimit.Allow(w.ClientIP(r)) {
		w.renderLogin(rw, r, username, CodeRateLimited)
		return
	}
	if err := w.startSession(rw, r, username, r.PostFormValue("password")); err != nil {
		w.logIfServerError("login", err)
		w.renderLogin(rw, r, username, AsError(err).MsgCode)
		return
	}
	w.Redirect(rw, r, "/account", "")
}

func (w *Web) handleLogout(rw http.ResponseWriter, r *http.Request) {
	if !w.CheckCSRF(r) {
		w.Redirect(rw, r, "/account", CodeInvalidForm)
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		if err := w.svc.Logout(r.Context(), c.Value); err != nil {
			logging.Warnf("accounts: logout: %v", err)
		}
	}
	http.SetCookie(rw, w.cookie(sessionCookie, "", -1))
	w.Redirect(rw, r, "/account/login", CodeLoggedOut)
}

func (w *Web) handleAccount(rw http.ResponseWriter, r *http.Request) {
	acct, ok := w.Account(r)
	if !ok {
		w.Redirect(rw, r, "/account/login", "")
		return
	}
	status, err := w.svc.Evaluate(r.Context(), &acct)
	if err != nil {
		w.logIfServerError("account page", err)
		w.Render(rw, r, locales.T(w.Lang(r), "ui.account"), "", CodeServerError)
		return
	}
	lang := w.Lang(r)
	type stepRow struct{ Title, Message, Path string }
	var pending, renewable []stepRow
	open := map[string]bool{}
	for _, p := range status.Pending {
		open[p.ID] = true
		pending = append(pending, stepRow{
			Title: w.stepTitle(p.ID, lang, p.Title), Message: locales.T(lang, p.MsgCode), Path: StepPath(p.ID),
		})
	}
	if status.Active() && !status.AccessUntil.IsZero() {
		for _, step := range w.svc.Steps() {
			if step.Renewable() && !open[step.ID()] {
				renewable = append(renewable, stepRow{Title: step.Title(lang), Path: StepPath(step.ID())})
			}
		}
	}
	accessUntil := ""
	if !status.AccessUntil.IsZero() {
		accessUntil = status.AccessUntil.UTC().Format("2006-01-02 15:04 UTC")
	}
	notice := ""
	if r.URL.Query().Get("n") == "" && status.MsgCode != "" && !status.Active() {
		notice = status.MsgCode
	}
	w.renderPage(rw, r, locales.T(lang, "ui.account"), "account", map[string]any{
		"Username":    acct.Username,
		"Active":      status.Active(),
		"StateKey":    "ui.state." + status.State.String(),
		"AccessUntil": accessUntil,
		"Pending":     pending,
		"Renewable":   renewable,
	}, notice)
}

func (w *Web) renderRegister(rw http.ResponseWriter, r *http.Request, username, email, notice string) {
	w.renderPage(rw, r, locales.T(w.Lang(r), "ui.register"), "register", map[string]any{
		"Username": username, "Email": email, "MinPassword": w.svc.MinPasswordLength(),
	}, notice)
}

func (w *Web) renderLogin(rw http.ResponseWriter, r *http.Request, username, notice string) {
	w.renderPage(rw, r, locales.T(w.Lang(r), "ui.login"), "login", map[string]any{
		"Username": username, "AllowRegistration": w.svc.AllowRegistration(),
	}, notice)
}

// renderPage executes one of the site's own body templates into the layout.
func (w *Web) renderPage(rw http.ResponseWriter, r *http.Request, title, name string, data map[string]any, notice string) {
	lang := w.Lang(r)
	data["T"] = func(code string) string { return locales.T(lang, code) }
	data["CSRF"] = w.CSRFField(r)
	var buf bytes.Buffer
	if err := portalTemplates.ExecuteTemplate(&buf, name, data); err != nil {
		logging.Errorf("accounts: render %s: %v", name, err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.Render(rw, r, title, template.HTML(buf.String()), notice)
}

// startSession logs in and sets the session cookie.
func (w *Web) startSession(rw http.ResponseWriter, r *http.Request, username, password string) error {
	token, sess, _, err := w.svc.Login(r.Context(), username, password, "web")
	if err != nil {
		return err
	}
	http.SetCookie(rw, w.cookie(sessionCookie, token, int(sess.ExpiresAt.Sub(w.svc.Now()).Seconds())))
	return nil
}

// middleware sets the security headers and makes sure the browser holds a CSRF
// cookie before any form is rendered.
func (w *Web) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		h := rw.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		token := ""
		if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) >= 32 {
			token = c.Value
		} else {
			token = randomToken()
			http.SetCookie(rw, w.cookie(csrfCookie, token, 0))
		}
		next.ServeHTTP(rw, r.WithContext(context.WithValue(r.Context(), csrfKey{}, token)))
	})
}

func (w *Web) cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: name, Value: value, Path: "/account", MaxAge: maxAge,
		HttpOnly: true, Secure: w.secure, SameSite: http.SameSiteLaxMode,
	}
}

func (w *Web) stepTitle(id, lang, fallback string) string {
	for _, step := range w.svc.Steps() {
		if step.ID() == id {
			return step.Title(lang)
		}
	}
	return fallback
}

func (w *Web) logIfServerError(what string, err error) {
	var e *Error
	if errors.As(err, &e) && e.Kind != KindUnavailable {
		return
	}
	logging.Errorf("accounts: %s: %v (cause: %v)", what, err, errors.Unwrap(err))
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
