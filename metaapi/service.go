// Package metaapi serves the client-facing Meta API of enode.meta.v1 — MetaApi and
// AccountApi — to eMuleQt: the .torrent or .nzb behind a meta search row, and,
// when the operator enables accounts, login status, login and the registration
// link. See docs/meta-api.md.
//
// It runs on up to two listeners: gRPC (and gRPC-Web), on whenever the API is; and
// an optional plain-HTTP one serving the Connect protocol, a raw metafile route and
// the account website.
package metaapi

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"enode/accounts"
	"enode/internal/ratelimit"
	"enode/locales"
	"enode/logging"
	"enode/storage"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connectproto"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
)

// ContractVersion is the enode.meta.v1 major version served.
const ContractVersion = 1

// basicCacheTTL is how long a verified Basic credential is remembered. A client
// sending Basic on every call would otherwise pay a memory-hard hash per download.
const basicCacheTTL = 5 * time.Minute

// Service implements metav1connect.MetaApiHandler and AccountApiHandler.
type Service struct {
	fetcher *Fetcher
	// accounts is nil when the API is public.
	accounts *accounts.Service
	// httpURL is the optional HTTP endpoint's base URL, for GetCaps.
	httpURL           string
	maxMetafileBytes  int
	trustForwardedFor bool

	// metafileLimits cap GetMetaFile; search has its own.
	metafileLimits limits
	loginLimit     *ratelimit.Limiter
	// search is nil when MetaApi.Search is not served.
	search *catalogSearch

	basicMu    sync.Mutex
	basicCache map[string]basicEntry

	stats ServiceStats
}

// ServiceStats are the API's own counters, for the dashboard.
type ServiceStats struct {
	RateLimited  atomic.Int64
	AuthFailures atomic.Int64
	Logins       atomic.Int64
	Searches     atomic.Int64
}

type basicEntry struct {
	accountID uint64
	expires   time.Time
}

// ServiceConfig configures a Service.
type ServiceConfig struct {
	HTTPURL             string
	MaxMetafileBytes    int
	PerIPPerMinute      int
	PerAccountPerMinute int
	TrustForwardedFor   bool
	// Search serves MetaApi.Search; nil answers it unimplemented.
	Search *SearchConfig
}

var (
	_ metav1connect.MetaApiHandler    = (*Service)(nil)
	_ metav1connect.AccountApiHandler = (*Service)(nil)
)

// NewService returns the API over fetcher; accts may be nil for a public API.
func NewService(cfg ServiceConfig, fetcher *Fetcher, accts *accounts.Service) *Service {
	s := &Service{
		fetcher:           fetcher,
		accounts:          accts,
		httpURL:           cfg.HTTPURL,
		maxMetafileBytes:  cfg.MaxMetafileBytes,
		trustForwardedFor: cfg.TrustForwardedFor,
		metafileLimits:    limits{ip: ratelimit.New(cfg.PerIPPerMinute), account: ratelimit.New(cfg.PerAccountPerMinute)},
		loginLimit:        ratelimit.New(20),
		basicCache:        map[string]basicEntry{},
	}
	if cfg.Search != nil && cfg.Search.Catalog != nil {
		s.search = &catalogSearch{
			cfg: *cfg.Search,
			limits: limits{
				ip:      ratelimit.New(cfg.Search.PerIPPerMinute),
				account: ratelimit.New(cfg.Search.PerAccountPerMinute),
			},
		}
	}
	return s
}

// Stats returns the counters.
func (s *Service) Stats() *ServiceStats { return &s.stats }

// AuthMode is the server's mode.
func (s *Service) AuthMode() metav1.AuthMode {
	if s.accounts == nil {
		return metav1.AuthMode_AUTH_MODE_PUBLIC
	}
	return metav1.AuthMode_AUTH_MODE_ACCOUNT_REQUIRED
}

// GetCaps describes the server. Never authenticated.
func (s *Service) GetCaps(context.Context, *metav1.GetCapsRequest) (*metav1.Caps, error) {
	caps := &metav1.Caps{
		ContractVersion:  ContractVersion,
		Kinds:            s.fetcher.Kinds(),
		AuthMode:         s.AuthMode(),
		MaxMetafileBytes: uint32(s.maxMetafileBytes),
		HttpUrl:          s.httpURL,
		Networks:         s.SearchNetworks(),
	}
	caps.SearchAvailable = len(caps.Networks) > 0
	caps.SearchRequiresAccount = caps.SearchAvailable && s.accounts != nil && s.search.cfg.RequireAccount
	if s.accounts != nil {
		caps.RegistrationUrl = s.accounts.RegistrationURL()
		caps.AccountUrl = s.accounts.AccountURL()
	}
	return caps, nil
}

// GetMetaFile returns the metafile behind a row, once the caller is allowed to.
func (s *Service) GetMetaFile(ctx context.Context, req *metav1.GetMetaFileRequest) (*metav1.MetaFile, error) {
	auth, ip := callAuth(ctx, s.trustForwardedFor)
	if _, err := s.Authorize(ctx, auth, ip); err != nil {
		return nil, err
	}
	mf, err := s.fetcher.Get(ctx, req.GetMetaHash(), req.GetCatalogId())
	if err != nil {
		return nil, s.toConnectError(err)
	}
	return mf, nil
}

// GetAuthStatus reports the caller's login state. It never fails for a missing or
// bad credential; it reports it.
func (s *Service) GetAuthStatus(ctx context.Context, _ *metav1.GetAuthStatusRequest) (*metav1.AuthStatus, error) {
	if s.accounts == nil {
		return &metav1.AuthStatus{AuthMode: metav1.AuthMode_AUTH_MODE_PUBLIC}, nil
	}
	auth, ip := callAuth(ctx, s.trustForwardedFor)
	out := &metav1.AuthStatus{
		AuthMode:        metav1.AuthMode_AUTH_MODE_ACCOUNT_REQUIRED,
		RegistrationUrl: s.accounts.RegistrationURL(),
		AccountUrl:      s.accounts.AccountURL(),
		MsgCode:         accounts.CodeAuthRequired,
	}
	if auth == "" {
		return out, nil
	}
	acct, err := s.resolve(ctx, auth, ip)
	if err != nil {
		out.MsgCode = accounts.AsError(err).MsgCode
		if accounts.AsError(err).Kind == accounts.KindUnavailable {
			return nil, s.toConnectError(err)
		}
		return out, nil
	}
	status, err := s.accounts.Evaluate(ctx, &acct)
	if err != nil {
		return nil, s.toConnectError(err)
	}
	s.fillStatus(ctx, out, acct, status)
	return out, nil
}

// Login exchanges a username and password for a bearer token.
func (s *Service) Login(ctx context.Context, req *metav1.LoginRequest) (*metav1.LoginResponse, error) {
	if s.accounts == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, "this server's Meta API is public: no login is needed")
	}
	_, ip := callAuth(ctx, s.trustForwardedFor)
	if !s.loginLimit.Allow(ip) {
		s.stats.RateLimited.Add(1)
		return nil, s.toConnectError(accounts.NewError(accounts.KindRateLimited, accounts.CodeRateLimited))
	}
	token, sess, acct, err := s.accounts.Login(ctx, req.GetUsername(), req.GetPassword(), req.GetClient())
	if err != nil {
		if accounts.AsError(err).Kind == accounts.KindUnauthenticated {
			s.stats.AuthFailures.Add(1)
		}
		return nil, s.toConnectError(err)
	}
	s.stats.Logins.Add(1)
	status, err := s.accounts.Evaluate(ctx, &acct)
	if err != nil {
		return nil, s.toConnectError(err)
	}
	out := &metav1.AuthStatus{
		AuthMode:        metav1.AuthMode_AUTH_MODE_ACCOUNT_REQUIRED,
		RegistrationUrl: s.accounts.RegistrationURL(),
		AccountUrl:      s.accounts.AccountURL(),
	}
	s.fillStatus(ctx, out, acct, status)
	logging.Infof("meta api: %q logged in from %s (%s)", acct.Username, ip, req.GetClient())
	return &metav1.LoginResponse{Token: token, TokenExpiresAtUnix: sess.ExpiresAt.Unix(), Status: out}, nil
}

// Logout revokes the bearer token of the call.
func (s *Service) Logout(ctx context.Context, _ *metav1.LogoutRequest) (*metav1.LogoutResponse, error) {
	if s.accounts == nil {
		return &metav1.LogoutResponse{}, nil
	}
	auth, _ := callAuth(ctx, s.trustForwardedFor)
	if token, ok := bearer(auth); ok {
		if err := s.accounts.Logout(ctx, token); err != nil {
			return nil, s.toConnectError(err)
		}
	}
	return &metav1.LogoutResponse{}, nil
}

// Authorize applies the metafile rate limits and, when accounts are on, requires an
// active account. auth is the Authorization header, ip the client address. It
// returns the account (zero when public) or a connect error carrying ErrorInfo.
func (s *Service) Authorize(ctx context.Context, auth, ip string) (storage.Account, error) {
	return s.authorize(ctx, auth, ip, s.metafileLimits, s.accounts != nil)
}

// resolve turns an Authorization header into an account: a bearer session token,
// or Basic username and password.
func (s *Service) resolve(ctx context.Context, auth, ip string) (storage.Account, error) {
	if token, ok := bearer(auth); ok {
		acct, _, err := s.accounts.Authenticate(ctx, token)
		if err != nil && accounts.AsError(err).Kind == accounts.KindUnauthenticated {
			s.stats.AuthFailures.Add(1)
		}
		return acct, err
	}
	user, pass, ok := basic(auth)
	if !ok {
		return storage.Account{}, accounts.NewError(accounts.KindUnauthenticated, accounts.CodeAuthRequired)
	}
	key := string(accounts.TokenHash(user + "\x00" + pass))
	s.basicMu.Lock()
	e, hit := s.basicCache[key]
	s.basicMu.Unlock()
	if hit && time.Now().Before(e.expires) {
		return s.accounts.Store().AccountByID(ctx, e.accountID)
	}
	if !s.loginLimit.Allow(ip) {
		s.stats.RateLimited.Add(1)
		return storage.Account{}, accounts.NewError(accounts.KindRateLimited, accounts.CodeRateLimited)
	}
	acct, err := s.accounts.CheckPassword(ctx, user, pass)
	if err != nil {
		if accounts.AsError(err).Kind == accounts.KindUnauthenticated {
			s.stats.AuthFailures.Add(1)
		}
		return storage.Account{}, err
	}
	s.basicMu.Lock()
	if len(s.basicCache) > 10000 {
		clear(s.basicCache)
	}
	s.basicCache[key] = basicEntry{accountID: acct.ID, expires: time.Now().Add(basicCacheTTL)}
	s.basicMu.Unlock()
	return acct, nil
}

// forbidden is the permission_denied error for a valid login whose account is not
// active, listing what is left to do.
func (s *Service) forbidden(ctx context.Context, status accounts.Status) error {
	info := s.errorInfo(status.MsgCode)
	info.PendingSteps = s.pendingSteps(ctx, status)
	e := connect.NewError(connect.CodePermissionDenied, locales.T(locales.Default, status.MsgCode))
	if d, err := connectproto.NewErrorDetail(info); err == nil {
		e = e.WithDetail(d)
	}
	return e
}

// toConnectError maps an accounts or fetch error onto a connect error with an
// ErrorInfo detail.
func (s *Service) toConnectError(err error) error {
	// Only an error that is already ours passes through as is. errors.As would also
	// find a daemon's connect error wrapped inside a FetchError, and hand its message
	// to the client instead of the MsgCode.
	if ce, ok := err.(*connect.Error); ok {
		return ce
	}
	var fe *FetchError
	if errors.As(err, &fe) {
		e := connect.NewError(fe.Code, locales.T(locales.Default, fe.MsgCode))
		if d, derr := connectproto.NewErrorDetail(&metav1.ErrorInfo{MsgCode: fe.MsgCode}); derr == nil {
			e = e.WithDetail(d)
		}
		return e
	}
	ae := accounts.AsError(err)
	code := connect.CodeUnavailable
	switch ae.Kind {
	case accounts.KindInvalid:
		code = connect.CodeInvalidArgument
	case accounts.KindUnauthenticated:
		code = connect.CodeUnauthenticated
	case accounts.KindForbidden:
		code = connect.CodePermissionDenied
	case accounts.KindConflict:
		code = connect.CodeAlreadyExists
	case accounts.KindRateLimited:
		code = connect.CodeResourceExhausted
	default:
		logging.Errorf("meta api: %v (cause: %v)", err, errors.Unwrap(ae))
	}
	e := connect.NewError(code, ae.Error())
	if d, derr := connectproto.NewErrorDetail(s.errorInfo(ae.MsgCode)); derr == nil {
		e = e.WithDetail(d)
	}
	return e
}

func (s *Service) errorInfo(code string) *metav1.ErrorInfo {
	info := &metav1.ErrorInfo{MsgCode: code}
	if s.accounts != nil {
		info.RegistrationUrl = s.accounts.RegistrationURL()
		info.AccountUrl = s.accounts.AccountURL()
	}
	return info
}

// callAuth reads the Authorization header and the client address of a connect call.
func callAuth(ctx context.Context, trustForwardedFor bool) (auth, ip string) {
	info, ok := connect.CallInfoForServerContext(ctx)
	if !ok {
		return "", ""
	}
	auth = info.RequestHeader().Get("Authorization")
	ip = ratelimit.PeerIP(info.PeerAddr)
	if trustForwardedFor {
		if fwd := info.RequestHeader().Get("X-Forwarded-For"); fwd != "" {
			ip = strings.TrimSpace(strings.SplitN(fwd, ",", 2)[0])
		}
	}
	return auth, ip
}

func (s *Service) fillStatus(ctx context.Context, out *metav1.AuthStatus, acct storage.Account, status accounts.Status) {
	out.LoggedIn = true
	out.Username = acct.Username
	out.State = metav1.AccountState(status.State)
	if !status.AccessUntil.IsZero() {
		out.ExpiresAtUnix = status.AccessUntil.Unix()
	}
	out.MsgCode = status.MsgCode
	out.PendingSteps = s.pendingSteps(ctx, status)
}

// pendingSteps lists the open steps, titled in the caller's Accept-Language.
func (s *Service) pendingSteps(ctx context.Context, status accounts.Status) []*metav1.PendingStep {
	lang := locales.Default
	if info, ok := connect.CallInfoForServerContext(ctx); ok {
		lang = locales.Negotiate(info.RequestHeader().Get("Accept-Language"))
	}
	out := make([]*metav1.PendingStep, 0, len(status.Pending))
	for _, p := range status.Pending {
		out = append(out, &metav1.PendingStep{
			Id: p.ID, Kind: metav1.StepKind(p.Kind), Title: s.accounts.StepTitle(p.ID, lang), Url: p.URL, MsgCode: p.MsgCode,
		})
	}
	return out
}

func bearer(auth string) (string, bool) {
	const prefix = "Bearer "
	if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
		return strings.TrimSpace(auth[len(prefix):]), true
	}
	return "", false
}

func basic(auth string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	return user, pass, ok
}

// authorize applies lim and, when required, demands an active account.
func (s *Service) authorize(ctx context.Context, auth, ip string, lim limits, required bool) (storage.Account, error) {
	if !lim.ip.Allow(ip) {
		s.stats.RateLimited.Add(1)
		return storage.Account{}, s.toConnectError(accounts.NewError(accounts.KindRateLimited, accounts.CodeRateLimited))
	}
	if !required {
		return storage.Account{}, nil
	}
	if auth == "" {
		return storage.Account{}, s.toConnectError(accounts.NewError(accounts.KindUnauthenticated, accounts.CodeAuthRequired))
	}
	acct, err := s.resolve(ctx, auth, ip)
	if err != nil {
		return storage.Account{}, s.toConnectError(err)
	}
	status, err := s.accounts.Authorize(ctx, &acct)
	if err != nil {
		return storage.Account{}, s.toConnectError(err)
	}
	if !status.Active() {
		return storage.Account{}, s.forbidden(ctx, status)
	}
	if !lim.account.Allow("a:" + acct.Username) {
		s.stats.RateLimited.Add(1)
		return storage.Account{}, s.toConnectError(accounts.NewError(accounts.KindRateLimited, accounts.CodeRateLimited))
	}
	return acct, nil
}
