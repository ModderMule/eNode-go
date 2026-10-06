package serverlink

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"enode/internal/connectsrv"
	"enode/logging"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
)

// Message bounds. A request is a query or a page token; an answer is a page of
// files, which maxBrowseLimit keeps well under this.
const (
	maxRequestBytes  = 64 << 10
	maxResponseBytes = 4 << 20
)

// ServerConfig is where and how the listener runs.
type ServerConfig struct {
	Listen string
	// CertFile and KeyFile serve the listener over TLS; empty serves h2c.
	CertFile string
	KeyFile  string
}

// Server runs the ServerSearch listener. It speaks every protocol connect does
// (gRPC, gRPC-Web and Connect) on the one port.
type Server struct {
	tls  *tls.Config
	http *http.Server
	addr net.Addr
}

// NewServer builds the listener for svc.
func NewServer(cfg ServerConfig, svc *Service) (*Server, error) {
	tlsCfg, err := connectsrv.LoadTLS(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("serverSearch.tls: %w", err)
	}
	srv := connect.NewServer()
	metav1connect.RegisterServerSearchHandler(srv, svc)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, srv,
		connecthttp.WithReadMaxBytes(maxRequestBytes),
		connecthttp.WithSendMaxBytes(maxResponseBytes),
	)
	return &Server{tls: tlsCfg, http: connectsrv.NewHTTPServer(cfg.Listen, mux, tlsCfg)}, nil
}

// Start binds the listener, then serves it in the background. A bind failure is
// returned: the operator asked for the listener.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return fmt.Errorf("server search listen %s: %w", s.http.Addr, err)
	}
	s.addr = ln.Addr()
	go func() {
		var err error
		if s.tls != nil {
			err = s.http.ServeTLS(ln, "", "")
		} else {
			err = s.http.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logging.Errorf("server search listener %s stopped: %v", s.http.Addr, err)
		}
	}()
	return nil
}

// Addr is the bound address after Start, or nil.
func (s *Server) Addr() net.Addr { return s.addr }

// Close stops the listener, letting in-flight calls finish for a few seconds.
func (s *Server) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.http.Shutdown(ctx)
}

// Fingerprint returns "sha256/<base64>" of the certificate's SPKI, which a peer
// pins and gossip mode advertises, or "" without TLS.
func (s *Server) Fingerprint() string {
	return connectsrv.Fingerprint(s.tls)
}
