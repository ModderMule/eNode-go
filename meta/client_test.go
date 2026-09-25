package meta

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
)

// TestNewClientOverHTTPWithToken runs NewClient against a real HTTP listener serving
// the daemon handler the way the crawlers mount it, behind a bearer-token check like
// theirs: the right token gets an answer, a missing one is refused as unauthenticated.
func TestNewClientOverHTTPWithToken(t *testing.T) {
	const token = "s3cret"
	d := &fakeDaemon{entries: []*metav1.MetaEntry{torrentEntry("over.http.mkv", 3)}}

	auth := func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			info, ok := connect.CallInfoForServerContext(ctx)
			if !ok || info.RequestHeader().Get("Authorization") != "Bearer "+token {
				return connect.NewError(connect.CodeUnauthenticated, "bad token")
			}
			return next(ctx, spec, stream)
		}
	}
	server := connect.NewServer(auth)
	metav1connect.RegisterMetaIngestHandler(server, d)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	listener := httptest.NewServer(mux)
	defer listener.Close()

	resp, err := NewClient(listener.URL+"/", token).Search(context.Background(), &metav1.SearchRequest{Query: "over"})
	t.Logf("input: Search over HTTP at %s with token; output: entries=%d err=%v", listener.URL, len(resp.GetEntries()), err)
	if err != nil || len(resp.GetEntries()) != 1 {
		t.Fatalf("err=%v entries=%d, want one entry", err, len(resp.GetEntries()))
	}

	_, err = NewClient(listener.URL, "").Search(context.Background(), &metav1.SearchRequest{Query: "over"})
	t.Logf("input: Search without token; output: code=%v err=%v", connect.CodeOf(err), err)
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("code %v, want unauthenticated", connect.CodeOf(err))
	}
}
