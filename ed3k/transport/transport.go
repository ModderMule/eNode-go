// Package transport is the QUIC and TLS profile of the ed3k quic-obfs binding
// (Protocol.md §4.1, §11): QUIC v1 over the obfuscating socket of package obfs,
// TLS 1.3 with RFC 7250 Ed25519 raw public keys on both sides, ALPN ed3k/1, no
// SNI, no 0-RTT and no session tickets.
package transport

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"enode/ed3k/ident"
	quic "enode/internal/ed3k/iquic"
	tls "enode/internal/ed3k/itls/tls"
)

// ALPN is the application protocol of ed3k wire version 1.
const ALPN = "ed3k/1"

// Application close codes of Protocol.md §4.1.
const (
	CodeClosed    quic.ApplicationErrorCode = 0
	CodeNoKey     quic.ApplicationErrorCode = 1
	CodeWrongPeer quic.ApplicationErrorCode = 2
	CodeDenied    quic.ApplicationErrorCode = 3
	CodeProtocol  quic.ApplicationErrorCode = 4
	CodeBusy      quic.ApplicationErrorCode = 5
)

// Timeouts of Protocol.md §4.1 and §11.
const (
	// IdleIndex is the max_idle_timeout an index node sends; it sends no PING.
	IdleIndex = 300 * time.Second
	// IdleDefault is the max_idle_timeout between ordinary nodes.
	IdleDefault = 30 * time.Second
	// MaxStreams is the exchanges a peer may have open at once.
	MaxStreams = 64
)

// ErrNotEd25519 is a peer key that is not Ed25519.
var ErrNotEd25519 = errors.New("ed3k: peer key is not Ed25519")

// ServerTLS is the TLS configuration of the accepting side. Every client must
// present an Ed25519 raw public key; a handshake without one fails inside TLS
// with certificate_required, which §4.1 allows instead of NO_KEY.
func ServerTLS(priv ed25519.PrivateKey) (*tls.Config, error) {
	cfg, err := baseTLS(priv)
	if err != nil {
		return nil, err
	}
	cfg.ClientAuth = tls.RequireAnyClientCert
	cfg.VerifyConnection = func(st tls.ConnectionState) error {
		_, err := PeerKey(st)
		return err
	}
	return cfg, nil
}

// ClientTLS is the TLS configuration of a dialler that expects the node expect.
func ClientTLS(priv ed25519.PrivateKey, expect ident.NodeID) (*tls.Config, error) {
	cfg, err := baseTLS(priv)
	if err != nil {
		return nil, err
	}
	cfg.VerifyConnection = func(st tls.ConnectionState) error {
		pub, err := PeerKey(st)
		if err != nil {
			return err
		}
		if got := ident.NodeIDOf(pub); got != expect {
			return fmt.Errorf("ed3k: wrong peer %s, expected %s", got, expect)
		}
		return nil
	}
	return cfg, nil
}

// QUICConfig is the QUIC profile; idle is IdleIndex for an index node.
func QUICConfig(idle time.Duration) *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:          idle,
		KeepAlivePeriod:         0,
		HandshakeIdleTimeout:    10 * time.Second,
		InitialPacketSize:       1200,
		DisablePathMTUDiscovery: true,
		MaxIncomingStreams:      MaxStreams,
		MaxIncomingUniStreams:   -1,
	}
}

// PeerKey returns the peer's Ed25519 key from a finished handshake.
func PeerKey(st tls.ConnectionState) (ed25519.PublicKey, error) {
	if len(st.PeerCertificates) != 1 {
		return nil, ErrNotEd25519
	}
	pub, ok := st.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, ErrNotEd25519
	}
	return pub, nil
}

// PeerID is the node ID of a connection's peer.
func PeerID(c *quic.Conn) (ident.NodeID, error) {
	pub, err := PeerKey(c.ConnectionState().TLS)
	if err != nil {
		return ident.NodeID{}, err
	}
	return ident.NodeIDOf(pub), nil
}

func baseTLS(priv ed25519.PrivateKey) (*tls.Config, error) {
	cert, err := tls.RawPublicKeyCertificate(priv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		RawPublicKeys:          true,
		Certificates:           []tls.Certificate{cert},
		MinVersion:             tls.VersionTLS13,
		NextProtos:             []string{ALPN},
		InsecureSkipVerify:     true, // no chain: the key is checked in VerifyConnection
		SessionTicketsDisabled: true,
		ServerName:             "",
	}, nil
}
