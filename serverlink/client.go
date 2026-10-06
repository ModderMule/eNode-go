package serverlink

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"enode/internal/connectsrv"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
)

// ErrFingerprint is the TLS failure of a peer whose certificate is not the
// pinned one.
var ErrFingerprint = errors.New("serverlink: the peer's certificate does not match the pinned fingerprint")

// ClientConfig is how another server's ServerSearch service is reached.
type ClientConfig struct {
	// URL is the peer's base URL.
	URL string
	// Token is sent as a bearer token when set.
	Token string
	// Fingerprint, "sha256/<base64>" of the peer certificate's SPKI, replaces
	// the certificate authorities: the peer is whoever holds that key. Empty
	// verifies the certificate the usual way.
	Fingerprint string
	// DialIP, when set, is the address every connection goes to, whatever the
	// URL's host resolves to; the URL still gives the port, the Host header and
	// the TLS server name. A peer found through gossip is dialled this way, at
	// the address gossip verified, so the URL it advertises cannot point this
	// server at a third party.
	DialIP net.IP
}

// NewClient returns a client for one peer. It speaks the Connect protocol, which
// the service serves next to gRPC on the same port and which needs no HTTP/2, so
// it also passes a proxy that speaks only HTTP/1.1. Calls are bounded by their
// context.
func NewClient(cfg ClientConfig) metav1connect.ServerSearchClient {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if cfg.DialIP != nil {
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(cfg.DialIP.String(), port))
		}
	}
	if pin := strings.TrimSpace(cfg.Fingerprint); pin != "" {
		// The chain is not verified because a pinned peer is usually self-signed;
		// the pin is checked in its place, and nothing is accepted without it.
		transport.TLSClientConfig.InsecureSkipVerify = true
		transport.TLSClientConfig.VerifyPeerCertificate = verifyFingerprint(pin)
	}
	var interceptors []connect.ClientInterceptor
	if token := strings.TrimSpace(cfg.Token); token != "" {
		interceptors = append(interceptors, bearerToken(token))
	}
	conn := connecthttp.NewTransport(&http.Client{Transport: transport}, strings.TrimRight(cfg.URL, "/"))
	return metav1connect.NewServerSearchClient(connect.NewClient(conn, interceptors...))
}

// -- internals ---------------------------------------------------------------

// verifyFingerprint accepts a handshake whose leaf certificate has the pinned
// SPKI fingerprint.
func verifyFingerprint(pin string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return ErrFingerprint
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return ErrFingerprint
		}
		if subtle.ConstantTimeCompare([]byte(connectsrv.CertFingerprint(leaf)), []byte(pin)) != 1 {
			return ErrFingerprint
		}
		return nil
	}
}

// bearerToken sets the Authorization header on each call.
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
