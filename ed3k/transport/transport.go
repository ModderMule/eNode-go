// Package transport is the QUIC and TLS profile of the ed3k quic-obfs binding
// (Protocol.md §4.1, §11): QUIC v1 over the obfuscating socket of package obfs,
// TLS 1.3 with RFC 7250 Ed25519 raw public keys on both sides, ALPN ed3k/1, no
// SNI, no 0-RTT and no session tickets.
package transport

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
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

// ClientTLS is the TLS configuration of a dialler. It checks only that the
// peer has an Ed25519 key: whether it is the node the dialler expects is
// checked after the handshake (CheckPeer), so that the WRONG_PEER close goes
// out after the last handshake flight with its code intact (§4.1).
func ClientTLS(priv ed25519.PrivateKey) (*tls.Config, error) {
	cfg, err := baseTLS(priv)
	if err != nil {
		return nil, err
	}
	cfg.VerifyConnection = func(st tls.ConnectionState) error {
		_, err := PeerKey(st)
		return err
	}
	return cfg, nil
}

// ErrWrongPeer is a dialled node whose node ID is not the expected one.
var ErrWrongPeer = errors.New("ed3k: wrong peer")

// CheckPeer compares the node ID of a dialled connection's peer with expect,
// and closes the connection with WRONG_PEER when they differ (§4.1).
func CheckPeer(c *quic.Conn, expect ident.NodeID) error {
	got, err := PeerID(c)
	if err != nil {
		closeConfirmed(c, CodeNoKey)
		return err
	}
	if got != expect {
		closeConfirmed(c, CodeWrongPeer)
		return fmt.Errorf("%w: %s, expected %s", ErrWrongPeer, got, expect)
	}
	return nil
}

// confirmWait bounds how long a dialler waits for the handshake to be
// confirmed before it closes anyway.
const confirmWait = 5 * time.Second

// closeConfirmed closes a dialled connection once its handshake is confirmed:
// before that, QUIC also sends the close in Handshake packets, where the
// application code is lost (RFC 9000 §10.2.3, §4.1 of the spec).
func closeConfirmed(c *quic.Conn, code quic.ApplicationErrorCode) {
	t := time.NewTimer(confirmWait)
	defer t.Stop()
	select {
	case <-c.HandshakeConfirmed():
	case <-c.Context().Done():
	case <-t.C:
	}
	c.CloseWithError(code, "")
}

// Dial connects over pc to the node expect at addr and checks its node ID.
func Dial(ctx context.Context, pc net.PacketConn, addr net.Addr, priv ed25519.PrivateKey, expect ident.NodeID, qc *quic.Config) (*quic.Conn, error) {
	tlsConf, err := ClientTLS(priv)
	if err != nil {
		return nil, err
	}
	c, err := quic.Dial(ctx, pc, addr, tlsConf, qc)
	if err != nil {
		return nil, err
	}
	if err := CheckPeer(c, expect); err != nil {
		return nil, err
	}
	return c, nil
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
