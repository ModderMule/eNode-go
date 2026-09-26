package metaapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"enode/accounts"
	"enode/config"
	"enode/storage"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"connectrpc.com/connect/v2/connectproto"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
)

// stubStep is a registration step that is open until opened is false.
type stubStep struct{ open bool }

func (s *stubStep) ID() string              { return "payment" }
func (s *stubStep) Kind() accounts.StepKind { return accounts.StepKindPayment }
func (s *stubStep) Title(lang string) string {
	return map[string]string{"de": "Zahlung"}[lang] + "|" + lang
}
func (s *stubStep) Durable() bool                          { return false }
func (s *stubStep) Renewable() bool                        { return false }
func (s *stubStep) Routes(*http.ServeMux, accounts.Portal) {}
func (s *stubStep) Check(context.Context, storage.Account, storage.AccountStep) (accounts.StepResult, error) {
	if s.open {
		return accounts.StepResult{Status: storage.StepPending, MsgCode: "step.payment.required"}, nil
	}
	return accounts.StepResult{Status: storage.StepDone}, nil
}

type fixture struct {
	t       *testing.T
	server  *Server
	svc     *Service
	accts   *accounts.Service
	grpcURL string
	httpURL string
	file    []byte
	hashHex string
	hash    []byte
	// missing is a valid meta hash the catalogue has no release for.
	missing    []byte
	missingHex string
	h2cHTTP    *http.Client
	stepOpen   *stubStep
}

// start runs a Server on loopback ports with one torrent in the fake catalogue, and
// MetaApi.Search when search is given.
func start(t *testing.T, withAccounts, httpAPI bool, perIP int, search ...*SearchConfig) *fixture {
	t.Helper()
	file, hash := testTorrent(t, "Served.Release.2026")
	src := newFakeSource()
	src.files["cat-7"] = &metav1.MetaFile{Content: file}
	fetcher := newTestFetcher(src)

	_, missing := testTorrent(t, "Not.In.The.Catalogue")
	fx := &fixture{t: t, file: file, hash: hash[:], hashHex: hex.EncodeToString(hash[:]), stepOpen: &stubStep{},
		missing: missing[:], missingHex: hex.EncodeToString(missing[:])}
	var web *accounts.Web
	if withAccounts {
		reg := accounts.Registry{}
		reg.Register("stub", func(config.AccountStepConfig, accounts.Deps) (accounts.Step, error) { return fx.stepOpen, nil })
		svc, err := accounts.New(accounts.Config{PublicURL: "https://enode.example.org", AllowRegistration: true,
			SessionTTL: time.Hour, MinPasswordLength: 8}, storage.NewMemoryEngine(), reg,
			[]config.AccountStepConfig{{ID: "payment", Type: "stub", Enabled: true}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		fx.accts = svc
		web = accounts.NewWeb(svc, accounts.PortalConfig{ServerName: "t"})
	}
	cfg := ServerConfig{GRPCListen: "127.0.0.1:0", HTTPAPI: httpAPI, MaxMetafileBytes: 1 << 20}
	if httpAPI || withAccounts {
		cfg.HTTPListen = "127.0.0.1:0"
	}
	svcCfg := ServiceConfig{MaxMetafileBytes: 1 << 20, PerIPPerMinute: perIP}
	if len(search) > 0 {
		svcCfg.Search = search[0]
	}
	fx.svc = NewService(svcCfg, fetcher, fx.accts)
	srv, err := NewServer(cfg, fx.svc, web)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	fx.server = srv
	fx.grpcURL = "http://" + srv.GRPCAddr().String()
	if srv.HTTPAddr() != nil {
		fx.httpURL = "http://" + srv.HTTPAddr().String()
	}
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	fx.h2cHTTP = &http.Client{Transport: &http.Transport{Protocols: &protocols}}
	// Runs before srv.Close (cleanups are LIFO): a dialed but unused client connection
	// would otherwise hold Shutdown for its full 5 s grace.
	t.Cleanup(func() {
		http.DefaultClient.CloseIdleConnections()
		fx.h2cHTTP.CloseIdleConnections()
	})
	return fx
}

// grpcClients are real gRPC clients over h2c, with an optional Authorization value.
func (fx *fixture) grpcClients(auth string) (metav1connect.MetaApiClient, metav1connect.AccountApiClient) {
	var interceptors []connect.ClientInterceptor
	if auth != "" {
		interceptors = append(interceptors, func(next connect.ClientFunc) connect.ClientFunc {
			return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
				if info, ok := connect.CallInfoForClientContext(ctx); ok {
					info.RequestHeader().Set("Authorization", auth)
					info.RequestHeader().Set("Accept-Language", "de")
				}
				return next(ctx, spec)
			}
		})
	}
	c := connect.NewClient(connecthttp.NewTransport(fx.h2cHTTP, fx.grpcURL, connecthttp.WithGRPC()), interceptors...)
	return metav1connect.NewMetaApiClient(c), metav1connect.NewAccountApiClient(c)
}

func errorInfo(t *testing.T, err error) *metav1.ErrorInfo {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("not a connect error: %v", err)
	}
	for _, d := range ce.Details() {
		if msg, derr := connectproto.UnmarshalErrorDetail(d); derr == nil {
			if info, ok := msg.(*metav1.ErrorInfo); ok {
				return info
			}
		}
	}
	t.Fatalf("no ErrorInfo detail on %v", err)
	return nil
}

func TestPublicGRPC(t *testing.T) {
	fx := start(t, false, false, 0)
	api, acct := fx.grpcClients("")
	ctx := context.Background()

	caps, err := api.GetCaps(ctx, &metav1.GetCapsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: GetCaps over gRPC output: %v", caps)
	if caps.GetAuthMode() != metav1.AuthMode_AUTH_MODE_PUBLIC || caps.GetContractVersion() != 1 || len(caps.GetKinds()) != 2 || caps.GetHttpUrl() != "" {
		t.Fatalf("caps = %v", caps)
	}
	mf, err := api.GetMetaFile(ctx, &metav1.GetMetaFileRequest{MetaHash: fx.hash, CatalogId: "cat-7"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: GetMetaFile over gRPC output: %d bytes %s", len(mf.GetContent()), mf.GetContentType())
	if !bytes.Equal(mf.GetContent(), fx.file) {
		t.Fatalf("content mismatch")
	}
	// The cache is keyed by meta hash (its bytes are verified against it), so a
	// missing release needs a hash that was never served.
	_, err = api.GetMetaFile(ctx, &metav1.GetMetaFileRequest{MetaHash: fx.missing, CatalogId: "nope"})
	if connect.CodeOf(err) != connect.CodeNotFound || errorInfo(t, err).GetMsgCode() != CodeNotFound {
		t.Fatalf("missing release: %v", err)
	}
	st, err := acct.GetAuthStatus(ctx, &metav1.GetAuthStatusRequest{})
	if err != nil || st.GetAuthMode() != metav1.AuthMode_AUTH_MODE_PUBLIC {
		t.Fatalf("GetAuthStatus in public mode: %v %v", st, err)
	}
	if _, err := acct.Login(ctx, &metav1.LoginRequest{Username: "x", Password: "y"}); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("Login in public mode: %v", err)
	}
	if _, err := api.Search(ctx, &metav1.SearchRequest{Query: "x"}); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("Search: %v", err)
	}
	if fx.server.HTTPAddr() != nil {
		t.Fatalf("the HTTP listener runs although it is off")
	}
}

// TestGRPCListenerRefusesConnect checks the gRPC listener does not double as the
// optional HTTP endpoint the operator left off.
func TestGRPCListenerRefusesConnect(t *testing.T) {
	fx := start(t, false, false, 0)
	resp, err := http.Post(fx.grpcURL+"/enode.meta.v1.MetaApi/GetCaps", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	t.Logf("input: Connect JSON POST to the gRPC listener output: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status %d, want 415", resp.StatusCode)
	}
}

func TestHTTPEndpoint(t *testing.T) {
	fx := start(t, false, true, 0)

	// Connect protocol, JSON.
	resp, err := http.Post(fx.httpURL+"/enode.meta.v1.MetaApi/GetMetaFile", "application/json",
		strings.NewReader(`{"metaHash":"`+base64.StdEncoding.EncodeToString(fx.hash)+`","catalogId":"cat-7"}`))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Content     string `json:"content"`
		ContentType string `json:"contentType"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	got, _ := base64.StdEncoding.DecodeString(out.Content)
	t.Logf("input: Connect JSON GetMetaFile output: %d %s %d bytes", resp.StatusCode, out.ContentType, len(got))
	if resp.StatusCode != 200 || !bytes.Equal(got, fx.file) {
		t.Fatalf("Connect JSON GetMetaFile failed: %d", resp.StatusCode)
	}

	// /caps as JSON.
	resp, err = http.Get(fx.httpURL + "/caps")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("input: GET /caps output: %s", b)
	if !strings.Contains(string(b), `"authMode":"AUTH_MODE_PUBLIC"`) {
		t.Fatalf("caps JSON: %s", b)
	}

	// Raw bytes.
	resp, err = http.Get(fx.httpURL + "/meta/v1/" + fx.hashHex + "?id=cat-7")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("input: GET /meta/v1/%s output: %d %s %q", fx.hashHex, resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Disposition"))
	if resp.StatusCode != 200 || !bytes.Equal(raw, fx.file) || resp.Header.Get("Content-Type") != "application/x-bittorrent" {
		t.Fatalf("raw route failed")
	}
	resp, _ = http.Get(fx.httpURL + "/meta/v1/zz?id=cat-7")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad hex: %d", resp.StatusCode)
	}
	resp, _ = http.Get(fx.httpURL + "/meta/v1/" + fx.missingHex + "?id=missing")
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("input: raw route, unknown id output: %d %s", resp.StatusCode, b)
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(b), CodeNotFound) {
		t.Fatalf("missing release on the raw route: %d %s", resp.StatusCode, b)
	}
}

func TestAccountsRequired(t *testing.T) {
	fx := start(t, true, true, 0)
	ctx := context.Background()
	if _, err := fx.accts.Register(ctx, "pat", "", "password1"); err != nil {
		t.Fatal(err)
	}
	api, acct := fx.grpcClients("")

	caps, _ := api.GetCaps(ctx, &metav1.GetCapsRequest{})
	if caps.GetAuthMode() != metav1.AuthMode_AUTH_MODE_ACCOUNT_REQUIRED || caps.GetRegistrationUrl() != "https://enode.example.org/account/register" {
		t.Fatalf("caps = %v", caps)
	}

	// No credential: unauthenticated, with the registration link.
	_, err := api.GetMetaFile(ctx, &metav1.GetMetaFileRequest{MetaHash: fx.hash, CatalogId: "cat-7"})
	info := errorInfo(t, err)
	t.Logf("input: GetMetaFile without login output: %s %v", connect.CodeOf(err), info)
	if connect.CodeOf(err) != connect.CodeUnauthenticated || info.GetMsgCode() != accounts.CodeAuthRequired || info.GetRegistrationUrl() == "" {
		t.Fatalf("anonymous GetMetaFile: %v", err)
	}
	st, err := acct.GetAuthStatus(ctx, &metav1.GetAuthStatusRequest{})
	if err != nil || st.GetLoggedIn() || st.GetMsgCode() != accounts.CodeAuthRequired || st.GetRegistrationUrl() == "" {
		t.Fatalf("anonymous GetAuthStatus: %v %v", st, err)
	}

	if _, err := acct.Login(ctx, &metav1.LoginRequest{Username: "pat", Password: "wrong-one"}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong password: %v", err)
	}
	login, err := acct.Login(ctx, &metav1.LoginRequest{Username: "pat", Password: "password1", Client: "eMuleQt test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: Login pat output: token=%d chars state=%s", len(login.GetToken()), login.GetStatus().GetState())
	if login.GetStatus().GetState() != metav1.AccountState_ACCOUNT_STATE_ACTIVE {
		t.Fatalf("login status: %v", login.GetStatus())
	}

	authed, authedAcct := fx.grpcClients("Bearer " + login.GetToken())
	mf, err := authed.GetMetaFile(ctx, &metav1.GetMetaFileRequest{MetaHash: fx.hash, CatalogId: "cat-7"})
	if err != nil || !bytes.Equal(mf.GetContent(), fx.file) {
		t.Fatalf("GetMetaFile with a bearer token: %v", err)
	}
	st, _ = authedAcct.GetAuthStatus(ctx, &metav1.GetAuthStatusRequest{})
	if !st.GetLoggedIn() || st.GetUsername() != "pat" || st.GetState() != metav1.AccountState_ACCOUNT_STATE_ACTIVE {
		t.Fatalf("GetAuthStatus with a token: %v", st)
	}

	// Basic auth on the raw route.
	req, _ := http.NewRequest(http.MethodGet, fx.httpURL+"/meta/v1/"+fx.hashHex+"?id=cat-7", nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("raw route without auth: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	req.SetBasicAuth("PAT", "password1")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	t.Logf("input: raw route with Basic auth output: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("raw route with Basic auth: %d", resp.StatusCode)
	}

	// Logout revokes the token.
	if _, err := authedAcct.Logout(ctx, &metav1.LogoutRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := authed.GetMetaFile(ctx, &metav1.GetMetaFileRequest{MetaHash: fx.hash, CatalogId: "cat-7"}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("GetMetaFile after logout: %v", err)
	}

	// The website is on the HTTP listener.
	resp, err = http.Get(fx.httpURL + "/account/register")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), `action="/account/register"`) {
		t.Fatalf("registration page not served: %d", resp.StatusCode)
	}
}

// TestPendingAccountIsDenied checks a valid login whose registration is not
// finished is told what is left, with a translated step title.
func TestPendingAccountIsDenied(t *testing.T) {
	fx := start(t, true, false, 0)
	fx.stepOpen.open = true
	ctx := context.Background()
	if _, err := fx.accts.Register(ctx, "quinn", "", "password1"); err != nil {
		t.Fatal(err)
	}
	api, _ := fx.grpcClients("Basic " + base64.StdEncoding.EncodeToString([]byte("quinn:password1")))
	_, err := api.GetMetaFile(ctx, &metav1.GetMetaFileRequest{MetaHash: fx.hash, CatalogId: "cat-7"})
	info := errorInfo(t, err)
	t.Logf("input: pending account output: %s %v", connect.CodeOf(err), info)
	if connect.CodeOf(err) != connect.CodePermissionDenied || info.GetMsgCode() != accounts.CodePending || len(info.GetPendingSteps()) != 1 {
		t.Fatalf("pending account: %v", err)
	}
	step := info.GetPendingSteps()[0]
	if step.GetId() != "payment" || step.GetKind() != metav1.StepKind_STEP_KIND_PAYMENT || step.GetTitle() != "Zahlung|de" ||
		step.GetUrl() != "https://enode.example.org/account/step/payment/" || step.GetMsgCode() != "step.payment.required" {
		t.Fatalf("pending step: %v", step)
	}

	fx.stepOpen.open = false
	if _, err := api.GetMetaFile(ctx, &metav1.GetMetaFileRequest{MetaHash: fx.hash, CatalogId: "cat-7"}); err != nil {
		t.Fatalf("after the step completed: %v", err)
	}
}

func TestRateLimit(t *testing.T) {
	fx := start(t, false, false, 2)
	api, _ := fx.grpcClients("")
	var errs []error
	for i := 0; i < 3; i++ {
		_, err := api.GetMetaFile(context.Background(), &metav1.GetMetaFileRequest{MetaHash: fx.hash, CatalogId: "cat-7"})
		errs = append(errs, err)
	}
	t.Logf("input: 3 calls at 2/min output: %v", errs)
	if errs[0] != nil || errs[1] != nil || connect.CodeOf(errs[2]) != connect.CodeResourceExhausted || fx.svc.Stats().RateLimited.Load() != 1 {
		t.Fatalf("want two successes then resource_exhausted, got %v", errs)
	}
}
