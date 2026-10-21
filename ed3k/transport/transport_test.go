package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"enode/ed3k/ident"
	"enode/ed3k/obfs"
	quic "enode/internal/ed3k/iquic"
)

// TestQUICOverObfs runs a QUIC handshake with raw keys through two obfuscating
// sockets, then echoes on one exchange.
func TestQUICOverObfs(t *testing.T) {
	for _, network := range []string{"", "ed3k test"} {
		t.Run("net="+network, func(t *testing.T) { runEcho(t, network) })
	}
}

func runEcho(t *testing.T, network string) {
	_, spriv, _ := ed25519.GenerateKey(rand.Reader)
	_, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	sid := ident.NodeIDOf(spriv.Public().(ed25519.PublicKey))
	netID := obfs.NetID(network)

	sudp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	sconn := obfs.NewServer(sudp, netID, sid.Obf())
	defer sconn.Close()
	stls, _ := ServerTLS(spriv)
	ln, err := quic.Listen(sconn, stls, QUICConfig(IdleIndex))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	gotClient := make(chan ident.NodeID, 1)
	go func() {
		c, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		id, _ := PeerID(c)
		gotClient <- id
		s, err := c.AcceptStream(context.Background())
		if err != nil {
			return
		}
		b, _ := io.ReadAll(s)
		s.Write(append([]byte("echo:"), b...))
		s.Close()
	}()

	cudp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	cconn := obfs.NewClient(cudp, netID, sid.Obf())
	defer cconn.Close()
	ctls, _ := ClientTLS(cpriv, sid)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := quic.Dial(ctx, cconn, sudp.LocalAddr(), ctls, QUICConfig(IdleIndex))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.CloseWithError(CodeClosed, "")
	s, err := c.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.Write([]byte("hello"))
	s.Close()
	b, err := io.ReadAll(s)
	t.Logf("network=%q answer=%q err=%v alpn=%s", network, b, err, c.ConnectionState().TLS.NegotiatedProtocol)
	if string(b) != "echo:hello" {
		t.Fatalf("echo %q", b)
	}
	cid := ident.NodeIDOf(cpriv.Public().(ed25519.PublicKey))
	if got := <-gotClient; got != cid {
		t.Fatalf("server saw %s, want %s", got, cid)
	}
	t.Logf("server dropped=%d held=%d; client dropped=%d", sconn.Dropped.Load(), sconn.Held.Load(), cconn.Dropped.Load())
}

// TestWrongPeer: a dialler that expects another node ID fails the handshake.
func TestWrongPeer(t *testing.T) {
	_, spriv, _ := ed25519.GenerateKey(rand.Reader)
	_, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	sid := ident.NodeIDOf(spriv.Public().(ed25519.PublicKey))
	sudp, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	sconn := obfs.NewServer(sudp, nil, sid.Obf())
	defer sconn.Close()
	stls, _ := ServerTLS(spriv)
	ln, _ := quic.Listen(sconn, stls, QUICConfig(IdleIndex))
	defer ln.Close()
	go ln.Accept(context.Background())

	other := sid
	other[15] ^= 1 // same obf_id, so the datagrams unmask, but another node ID
	cudp, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	cconn := obfs.NewClient(cudp, nil, other.Obf())
	defer cconn.Close()
	ctls, _ := ClientTLS(cpriv, other)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := quic.Dial(ctx, cconn, sudp.LocalAddr(), ctls, QUICConfig(IdleIndex))
	t.Logf("dial with a wrong expected id: %v", err)
	if err == nil {
		t.Fatal("handshake with the wrong peer succeeded")
	}
}
