package metaapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"enode/accounts"

	"connectrpc.com/connect/v2"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
)

// TestGlobalLimitCountsEveryRPC checks the global limit counts any mix of calls
// from one address, not just downloads.
func TestGlobalLimitCountsEveryRPC(t *testing.T) {
	fx := startWith(t, false, false, ServiceConfig{MaxMetafileBytes: 1 << 20, RequestsPerMinute: 3})
	api, acct := fx.grpcClients("")
	ctx := context.Background()
	calls := []struct {
		name string
		do   func() error
	}{
		{"GetCaps", func() error { _, err := api.GetCaps(ctx, &metav1.GetCapsRequest{}); return err }},
		{"GetAuthStatus", func() error { _, err := acct.GetAuthStatus(ctx, &metav1.GetAuthStatusRequest{}); return err }},
		{"GetMetaFile", func() error {
			_, err := api.GetMetaFile(ctx, &metav1.GetMetaFileRequest{MetaHash: fx.hash, CatalogId: "cat-7"})
			return err
		}},
		{"GetMetaFile", func() error {
			_, err := api.GetMetaFile(ctx, &metav1.GetMetaFileRequest{MetaHash: fx.missing, CatalogId: "cat-7"})
			return err
		}},
		{"Search", func() error { _, err := api.Search(ctx, &metav1.SearchRequest{}); return err }},
	}
	var codes []string
	for _, c := range calls {
		code := "ok"
		if err := c.do(); err != nil {
			code = connect.CodeOf(err).String()
		}
		codes = append(codes, c.name+"="+code)
	}
	t.Logf("input: 5 mixed RPCs at 3/min output: %v", codes)
	for i, c := range calls {
		limited := strings.HasSuffix(codes[i], "="+connect.CodeResourceExhausted.String())
		if limited != (i >= 3) {
			t.Fatalf("call %d (%s): limited=%v, want %v", i, c.name, limited, i >= 3)
		}
	}
	if got := fx.svc.Stats().RateLimited.Load(); got != 2 {
		t.Fatalf("RateLimited = %d, want 2", got)
	}
	_, err := api.GetCaps(ctx, &metav1.GetCapsRequest{})
	info := errorInfo(t, err)
	t.Logf("input: refused GetCaps output: %s %s", connect.CodeOf(err), info.GetMsgCode())
	if info.GetMsgCode() != accounts.CodeRateLimited {
		t.Fatalf("msg code = %q, want %q", info.GetMsgCode(), accounts.CodeRateLimited)
	}
}

// TestGlobalLimitHTTPRoutes checks the HTTP listener's own routes share the limit
// and answer 429, while /healthz and payment webhooks are never counted.
func TestGlobalLimitHTTPRoutes(t *testing.T) {
	fx := startWith(t, true, true, ServiceConfig{MaxMetafileBytes: 1 << 20, RequestsPerMinute: 3})
	var got []int
	for i := 0; i < 5; i++ {
		code, _, _ := httpGet(t, fx.httpURL+"/healthz")
		got = append(got, code)
	}
	for i := 0; i < 5; i++ {
		resp, err := http.Post(fx.httpURL+"/account/step/payment/hook/woocommerce", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("webhook call %d was rate limited", i)
		}
	}
	var counted []int
	for _, path := range []string{"/caps", "/account/register", "/caps", "/caps"} {
		code, _, _ := httpGet(t, fx.httpURL+path)
		counted = append(counted, code)
	}
	t.Logf("input: 5x /healthz, 5x webhook, then /caps /account/register /caps /caps at 3/min output: healthz=%v counted=%v", got, counted)
	for _, c := range got {
		if c != http.StatusOK {
			t.Fatalf("/healthz was limited: %v", got)
		}
	}
	if counted[0] != http.StatusOK || counted[1] != http.StatusOK || counted[2] != http.StatusOK || counted[3] != http.StatusTooManyRequests {
		t.Fatalf("counted routes: %v, want 200 200 200 429", counted)
	}
	// An RPC on the HTTP listener is counted once, by the service, not twice.
	api, _ := fx.grpcClients("")
	if _, err := api.GetCaps(context.Background(), &metav1.GetCapsRequest{}); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("RPC after the HTTP routes used the budget: %v", err)
	}
}

// TestGlobalLimitPerAccount checks one account spread over many addresses is
// still capped.
func TestGlobalLimitPerAccount(t *testing.T) {
	fx := startWith(t, true, true, ServiceConfig{MaxMetafileBytes: 1 << 20, RequestsPerMinute: 3, TrustForwardedFor: true})
	if _, err := fx.accts.Register(context.Background(), "pat", "", "password1"); err != nil {
		t.Fatal(err)
	}
	var got []int
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"} {
		req, _ := http.NewRequest(http.MethodGet, fx.httpURL+"/meta/v1/"+fx.hashHex+"?id=cat-7", nil)
		req.Header.Set("X-Forwarded-For", ip)
		req.SetBasicAuth("pat", "password1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		got = append(got, resp.StatusCode)
	}
	t.Logf("input: account pat from 4 addresses at 3/min output: %v", got)
	if got[0] != http.StatusOK || got[1] != http.StatusOK || got[2] != http.StatusOK || got[3] != http.StatusTooManyRequests {
		t.Fatalf("want 200 200 200 429, got %v", got)
	}
}

// TestGlobalLimitOff checks RequestsPerMinute 0 leaves calls unlimited.
func TestGlobalLimitOff(t *testing.T) {
	fx := startWith(t, false, false, ServiceConfig{MaxMetafileBytes: 1 << 20})
	api, _ := fx.grpcClients("")
	for i := 0; i < 50; i++ {
		if _, err := api.GetCaps(context.Background(), &metav1.GetCapsRequest{}); err != nil {
			t.Fatalf("call %d with the limit off: %v", i, err)
		}
	}
	t.Logf("input: 50 GetCaps with the limit off output: all served")
}
