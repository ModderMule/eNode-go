package metaapi

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"enode/accounts"
	"enode/internal/connectsrv"
	"enode/internal/ratelimit"
	"enode/logging"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"connectrpc.com/connect/v2/connectproto"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
	"google.golang.org/protobuf/encoding/protojson"
)

// ServerConfig is where and how the listeners run.
type ServerConfig struct {
	// GRPCListen is the gRPC listener's address; empty disables it.
	GRPCListen string
	// HTTPListen is the HTTP listener's address; empty disables it.
	HTTPListen string
	// HTTPAPI mounts the API (Connect protocol and the raw route) on the HTTP
	// listener. Without it the HTTP listener serves only the account website.
	HTTPAPI bool
	// CertFile and KeyFile serve both listeners over TLS.
	CertFile string
	KeyFile  string
	// TrustForwardedFor takes client addresses from X-Forwarded-For.
	TrustForwardedFor bool
	// MaxMetafileBytes bounds a response.
	MaxMetafileBytes int
	// PublicStatus serves GET /status on the HTTP listener. GET /healthz is served
	// whenever that listener runs.
	PublicStatus bool
}

// Status is the body of GET /status. It carries only what the server already tells
// every eD2K client: the counts are the advertised ones of OP_SERVERSTATUS and
// OP_GLOBSERVSTATRES, not the dashboard's.
type Status struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	Version       string `json:"version"`
	Users         int    `json:"users"`
	LowIDUsers    int    `json:"lowIDUsers"`
	Files         int    `json:"files"`
	Servers       int    `json:"servers"`
	MaxUsers      uint32 `json:"maxUsers"`
	SoftFileLimit uint32 `json:"softFileLimit"`
	HardFileLimit uint32 `json:"hardFileLimit"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
	// Now is Unix seconds, generated per request: a body a proxy kept shows as a
	// timestamp that does not move.
	Now int64 `json:"now"`
}

// statusPerMinute caps GET /status per client address. The figures are cached, so
// this bounds noise, not cost.
const statusPerMinute = 60

// Server runs the listeners.
type Server struct {
	cfg  ServerConfig
	svc  *Service
	web  *accounts.Web
	tls  *tls.Config
	grpc *http.Server
	http *http.Server

	grpcAddr, httpAddr net.Addr

	// status is the source behind GET /status; see SetStatus.
	status      atomic.Pointer[func() Status]
	statusLimit *ratelimit.Limiter
}

// grpcContentTypes are what the gRPC listener accepts. The Connect protocol and its
// JSON form belong on the HTTP listener, which the operator may keep off.
var grpcContentTypes = connectsrv.GRPCContentTypes

// NewServer builds the listeners. web may be nil when accounts are off.
func NewServer(cfg ServerConfig, svc *Service, web *accounts.Web) (*Server, error) {
	s := &Server{cfg: cfg, svc: svc, web: web, statusLimit: ratelimit.New(statusPerMinute)}
	if cfg.CertFile != "" {
		tlsCfg, err := connectsrv.LoadTLS(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("metaApi.tls: %w", err)
		}
		s.tls = tlsCfg
	}
	if cfg.GRPCListen != "" {
		s.grpc = s.newHTTPServer(cfg.GRPCListen, onlyContentTypes(s.connectHandler(), grpcContentTypes))
	}
	if cfg.HTTPListen != "" {
		s.http = s.newHTTPServer(cfg.HTTPListen, s.httpHandler())
	}
	return s, nil
}

// Start binds every listener, then serves them in the background. A bind failure
// is returned: the operator asked for the listener.
func (s *Server) Start() error {
	for _, srv := range []*http.Server{s.grpc, s.http} {
		if srv == nil {
			continue
		}
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			s.Close()
			return fmt.Errorf("meta api listen %s: %w", srv.Addr, err)
		}
		if srv == s.grpc {
			s.grpcAddr = ln.Addr()
		} else {
			s.httpAddr = ln.Addr()
		}
		if s.tls != nil {
			ln = tls.NewListener(ln, srv.TLSConfig)
		}
		go func(srv *http.Server, ln net.Listener) {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logging.Errorf("meta api %s: %v", srv.Addr, err)
			}
		}(srv, ln)
	}
	return nil
}

// GRPCAddr is the bound gRPC address after Start, or nil.
func (s *Server) GRPCAddr() net.Addr { return s.grpcAddr }

// HTTPAddr is the bound HTTP address after Start, or nil.
func (s *Server) HTTPAddr() net.Addr { return s.httpAddr }

// Close stops the listeners, letting in-flight calls finish for a few seconds.
func (s *Server) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range []*http.Server{s.grpc, s.http} {
		if srv != nil {
			_ = srv.Shutdown(ctx)
		}
	}
}

// Fingerprint returns "sha256/<base64>" of the certificate's SPKI, the pin sent as
// ST_META_API_FP, or "" without TLS.
func (s *Server) Fingerprint() string {
	return connectsrv.Fingerprint(s.tls)
}

// SetStatus attaches the source of GET /status. It is separate from NewServer
// because the server is built before the eD2K runtime the figures come from. Until
// it is called the route answers 503. fn must not block on I/O.
func (s *Server) SetStatus(fn func() Status) {
	s.status.Store(&fn)
}

// connectHandler serves both services over every protocol connect speaks.
func (s *Server) connectHandler() http.Handler {
	srv := connect.NewServer()
	metav1connect.RegisterMetaApiHandler(srv, s.svc)
	metav1connect.RegisterAccountApiHandler(srv, s.svc)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, srv,
		connecthttp.WithReadMaxBytes(64<<10),
		connecthttp.WithSendMaxBytes(s.cfg.MaxMetafileBytes+(64<<10)),
	)
	return mux
}

// httpHandler is the plain-HTTP listener: the API when enabled, the account
// website when accounts are on, and the health and status routes either way.
func (s *Server) httpHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	if s.cfg.PublicStatus {
		mux.HandleFunc("GET /status", s.handleStatus)
	}
	if s.cfg.HTTPAPI {
		api := s.connectHandler()
		mux.Handle("/enode.meta.v1.MetaApi/", api)
		mux.Handle("/enode.meta.v1.AccountApi/", api)
		mux.HandleFunc("GET /caps", s.handleCaps)
		mux.HandleFunc("GET /meta/v1/{hash}", s.handleRawMetaFile)
	}
	if s.web != nil {
		site := s.web.Handler()
		mux.Handle("/account", site)
		mux.Handle("/account/", site)
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/account", http.StatusSeeOther)
		})
	}
	return mux
}

// handleCaps is GetCaps as plain JSON, for a client bootstrapping without a
// protobuf stack.
func (s *Server) handleCaps(w http.ResponseWriter, r *http.Request) {
	caps, _ := s.svc.GetCaps(r.Context(), &metav1.GetCapsRequest{})
	b, err := protojson.Marshal(caps)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// handleRawMetaFile serves GET /meta/v1/{hash hex}?id={catalog_id}: the metafile's
// bytes with no codec at all. Auth is the same as GetMetaFile's.
func (s *Server) handleRawMetaFile(w http.ResponseWriter, r *http.Request) {
	ip := ratelimit.ClientIP(r, s.cfg.TrustForwardedFor)
	if _, err := s.svc.Authorize(r.Context(), r.Header.Get("Authorization"), ip); err != nil {
		writeHTTPError(w, err)
		return
	}
	hash, err := hex.DecodeString(r.PathValue("hash"))
	if err != nil {
		writeHTTPError(w, connect.NewError(connect.CodeInvalidArgument, "the hash must be 32 hex digits"))
		return
	}
	mf, err := s.svc.fetcher.Get(r.Context(), hash, r.URL.Query().Get("id"))
	if err != nil {
		writeHTTPError(w, s.svc.toConnectError(err))
		return
	}
	ext := ".torrent"
	if mf.GetKind() == metav1.MetaKind_META_KIND_NZB {
		ext = ".nzb"
	}
	w.Header().Set("Content-Type", mf.GetContentType())
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ToLower(r.PathValue("hash"))+ext+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(mf.GetContent())
}

func (s *Server) newHTTPServer(addr string, h http.Handler) *http.Server {
	return connectsrv.NewHTTPServer(addr, h, s.tls)
}

// onlyContentTypes lets through requests whose Content-Type starts with one of
// types, and answers anything else 415.
func onlyContentTypes(next http.Handler, types []string) http.Handler {
	return connectsrv.OnlyContentTypes(next, types, "this listener speaks gRPC and gRPC-Web only")
}

// writeHTTPError answers a raw route with the connect error's HTTP status and its
// ErrorInfo as JSON.
func writeHTTPError(w http.ResponseWriter, err error) {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		ce = connect.NewError(connect.CodeUnavailable, "unavailable")
	}
	body := map[string]any{"code": ce.Code().String(), "message": ce.Message()}
	for _, d := range ce.Details() {
		if msg, derr := connectproto.UnmarshalErrorDetail(d); derr == nil {
			if info, ok := msg.(*metav1.ErrorInfo); ok {
				if b, jerr := protojson.Marshal(info); jerr == nil {
					body["info"] = json.RawMessage(b)
				}
			}
		}
	}
	status := httpStatus(ce.Code())
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="eNode Meta API", charset="UTF-8"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func httpStatus(code connect.Code) int {
	switch code {
	case connect.CodeInvalidArgument:
		return http.StatusBadRequest
	case connect.CodeUnauthenticated:
		return http.StatusUnauthorized
	case connect.CodePermissionDenied:
		return http.StatusForbidden
	case connect.CodeNotFound:
		return http.StatusNotFound
	case connect.CodeResourceExhausted:
		return http.StatusTooManyRequests
	case connect.CodeDataLoss:
		return http.StatusBadGateway
	case connect.CodeUnimplemented:
		return http.StatusNotImplemented
	default:
		return http.StatusServiceUnavailable
	}
}

// handleHealthz is liveness for a supervisor: it answers as long as the listener
// does, and reads nothing.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"status": "ok", "now": time.Now().Unix()})
}

// handleStatus serves GET /status to anyone, rate-limited per client address.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !s.statusLimit.Allow(ratelimit.ClientIP(r, s.cfg.TrustForwardedFor)) {
		writeHTTPError(w, connect.NewError(connect.CodeResourceExhausted, "too many requests"))
		return
	}
	fn := s.status.Load()
	if fn == nil {
		writeHTTPError(w, connect.NewError(connect.CodeUnavailable, "the server is starting"))
		return
	}
	st := (*fn)()
	st.Now = time.Now().Unix()
	writeJSON(w, st)
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}
