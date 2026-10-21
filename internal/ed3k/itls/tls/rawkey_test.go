// ed3k: tests of the RFC 7250 patch. See docs/ed3k-tls-quic-forks.md.

package tls

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"
)

func rawConfig(t *testing.T, priv ed25519.PrivateKey, server bool) *Config {
	t.Helper()
	cert, err := RawPublicKeyCertificate(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		RawPublicKeys:          true,
		Certificates:           []Certificate{cert},
		MinVersion:             VersionTLS13,
		NextProtos:             []string{"ed3k/1"},
		InsecureSkipVerify:     true, // no chain; the key is checked in VerifyConnection
		SessionTicketsDisabled: true,
	}
	if server {
		cfg.ClientAuth = RequireAnyClientCert
	}
	return cfg
}

func handshakePair(t *testing.T, client, server *Config) (cs, ss ConnectionState, cerr, serr error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s, err := ln.Accept()
		if err != nil {
			serr = err
			return
		}
		defer s.Close()
		sc := Server(s, server)
		serr = sc.Handshake()
		ss = sc.ConnectionState()
		if serr == nil {
			sc.Write([]byte{1})
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cc := Client(c, client)
	cerr = cc.Handshake()
	cs = cc.ConnectionState()
	if cerr == nil {
		// In TLS 1.3 the client is done before the server has checked its key;
		// a refusal shows on the first read.
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, cerr = cc.Read(make([]byte, 1))
	}
	<-done
	return
}

func TestRawPublicKeyHandshake(t *testing.T) {
	cpub, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	spub, spriv, _ := ed25519.GenerateKey(rand.Reader)
	var sawServer, sawClient []byte
	ccfg := rawConfig(t, cpriv, false)
	ccfg.VerifyConnection = func(st ConnectionState) error {
		sawServer = st.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
		return nil
	}
	scfg := rawConfig(t, spriv, true)
	scfg.VerifyConnection = func(st ConnectionState) error {
		sawClient = st.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
		return nil
	}
	cs, _, cerr, serr := handshakePair(t, ccfg, scfg)
	t.Logf("client err=%v server err=%v alpn=%q", cerr, serr, cs.NegotiatedProtocol)
	if cerr != nil || serr != nil {
		t.Fatalf("handshake failed")
	}
	t.Logf("server key seen by client %x, client key seen by server %x", sawServer, sawClient)
	if !bytes.Equal(sawServer, spub) || !bytes.Equal(sawClient, cpub) {
		t.Fatal("peer keys differ")
	}
}

func TestRawPublicKeyRefusals(t *testing.T) {
	_, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	_, spriv, _ := ed25519.GenerateKey(rand.Reader)

	// A client that does not offer raw keys: unsupported_certificate.
	plain := rawConfig(t, cpriv, false)
	plain.RawPublicKeys = false
	_, _, cerr, serr := handshakePair(t, plain, rawConfig(t, spriv, true))
	t.Logf("x509 client: client err=%v server err=%v", cerr, serr)
	if serr == nil || !strings.Contains(serr.Error(), "raw public keys") {
		t.Fatalf("server accepted a client without raw keys")
	}

	// A client without a key: certificate_required.
	nokey := rawConfig(t, cpriv, false)
	nokey.Certificates = nil
	_, _, cerr, serr = handshakePair(t, nokey, rawConfig(t, spriv, true))
	t.Logf("keyless client: client err=%v server err=%v", cerr, serr)
	if serr == nil || cerr == nil || !strings.Contains(cerr.Error(), "certificate required") {
		t.Fatalf("keyless client not refused with certificate_required")
	}

	// A VerifyConnection that refuses the server key fails the client.
	wrong := rawConfig(t, cpriv, false)
	wrong.VerifyConnection = func(ConnectionState) error { return errWrongPeer }
	_, _, cerr, _ = handshakePair(t, wrong, rawConfig(t, spriv, true))
	t.Logf("wrong peer: client err=%v", cerr)
	if cerr != errWrongPeer {
		t.Fatalf("client did not refuse the wrong peer")
	}
}

var errWrongPeer = &wrongPeer{}

type wrongPeer struct{}

func (*wrongPeer) Error() string { return "wrong peer" }
