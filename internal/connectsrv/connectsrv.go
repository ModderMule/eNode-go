// Package connectsrv holds what the connect listeners of this server have in
// common: the HTTP/2 setup gRPC needs, the TLS configuration, and the SPKI
// fingerprint a peer pins a self-signed certificate by.
package connectsrv

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
)

// GRPCContentTypes are what a gRPC-only listener accepts.
var GRPCContentTypes = []string{"application/grpc", "application/grpc-web"}

// LoadTLS returns the server TLS configuration for a certificate and key, or nil
// when certFile is empty.
func LoadTLS(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

// Fingerprint returns "sha256/<base64>" of the SubjectPublicKeyInfo of cfg's
// certificate, or "" without one.
func Fingerprint(cfg *tls.Config) string {
	if cfg == nil || len(cfg.Certificates) == 0 || len(cfg.Certificates[0].Certificate) == 0 {
		return ""
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		return ""
	}
	return CertFingerprint(leaf)
}

// CertFingerprint returns "sha256/<base64>" of a certificate's
// SubjectPublicKeyInfo.
func CertFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(sum[:])
}

// NewHTTPServer returns a server for h on addr that speaks HTTP/1.1 and HTTP/2:
// over TLS when tlsCfg is set, and h2c otherwise, since gRPC needs HTTP/2.
func NewHTTPServer(addr string, h http.Handler, tlsCfg *tls.Config) *http.Server {
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	if tlsCfg != nil {
		protocols.SetHTTP2(true)
	} else {
		protocols.SetUnencryptedHTTP2(true)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		Protocols:         &protocols,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
	if tlsCfg != nil {
		cfg := tlsCfg.Clone()
		cfg.NextProtos = []string{"h2", "http/1.1"}
		srv.TLSConfig = cfg
	}
	return srv
}

// OnlyContentTypes lets through requests whose Content-Type starts with one of
// types, and answers anything else 415 with message.
func OnlyContentTypes(next http.Handler, types []string, message string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		for _, t := range types {
			if strings.HasPrefix(ct, t) {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, message, http.StatusUnsupportedMediaType)
	})
}
