package meta

import (
	"context"
	"net/http"
	"strings"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
)

// NewClient returns a MetaIngest client for a catalogue daemon at baseURL, e.g.
// http://127.0.0.1:9701. A non-empty token is sent as `Authorization: Bearer <token>`
// on every call, which is how the daemons' ingest.auth_token is checked.
//
// It speaks the Connect protocol, which the daemons serve alongside gRPC and
// gRPC-Web from one handler, over HTTP/1.1 or HTTP/2 — no h2c or trailers needed.
// The HTTP client has no timeout: it would cut the Subscribe stream, which is meant
// to stay open for weeks. Unary calls are bounded by their context instead.
func NewClient(baseURL, token string) metav1connect.MetaIngestClient {
	transport := connecthttp.NewTransport(&http.Client{Transport: http.DefaultTransport}, strings.TrimRight(baseURL, "/"))
	var interceptors []connect.ClientInterceptor
	if token = strings.TrimSpace(token); token != "" {
		interceptors = append(interceptors, bearerToken(token))
	}
	return metav1connect.NewMetaIngestClient(connect.NewClient(transport, interceptors...))
}

// bearerToken sets the daemon's auth header on each call. The client attaches a
// fresh CallInfo before the interceptor chain runs, so the header always has a home.
func bearerToken(token string) connect.ClientInterceptor {
	value := "Bearer " + token
	return func(next connect.ClientFunc) connect.ClientFunc {
		return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
			if info, ok := connect.CallInfoForClientContext(ctx); ok {
				info.RequestHeader().Set("Authorization", value)
			}
			return next(ctx, spec)
		}
	}
}
