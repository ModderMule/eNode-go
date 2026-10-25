package ed2k

import (
	"bytes"
	"encoding/binary"
	"testing"

	"enode/storage"
)

func TestBuildTCPFlags(t *testing.T) {
	// Only eMule-defined server bits are emitted; the client-side SRVCAP_* bits
	// (IPInLogin/AuxPort/Support/Require crypt) that used to leak into this word
	// are dropped. TCP obfuscation follows SupportCrypt, and IPv6 adds 0x4000.
	flags := BuildTCPFlags(TCPServerConfig{
		AuxiliarPort: true, RequireCrypt: true, RequestCrypt: true, SupportCrypt: true, IPInLogin: true, DualStack: true,
	})
	expected := FlagZlib + FlagNewTags + FlagUnicode + FlagLargeFiles + FlagTcpObfusc + FlagIPv6
	if flags != expected {
		t.Fatalf("flags mismatch: got 0x%x expected 0x%x", flags, expected)
	}
	t.Logf("corrected SRV_TCPFLG word = 0x%04x", flags)
}

func TestBuildTCPFlagsSupportCryptDrivesObfuscation(t *testing.T) {
	// A server that supports but does not request crypt still advertises TCP
	// obfuscation (0x0400) — the old build cleared it, so clients never learned of
	// the running obfuscated listener.
	flags := BuildTCPFlags(TCPServerConfig{SupportCrypt: true, RequestCrypt: false})
	if flags&FlagTcpObfusc == 0 {
		t.Fatalf("TCPOBFUSCATION must be set when SupportCrypt is on: 0x%04x", flags)
	}
	// Without crypt at all, no obfuscation bit and no IPv6 bit.
	plain := BuildTCPFlags(TCPServerConfig{})
	if plain&FlagTcpObfusc != 0 || plain&FlagIPv6 != 0 {
		t.Fatalf("unexpected bits on a plain server: 0x%04x", plain)
	}
	t.Logf("supportCrypt-only=0x%04x plain=0x%04x", flags, plain)
}

func TestBuildTCPFlagsNatRendezvous(t *testing.T) {
	// FlagNatRendezvous (0x40000) advertises PR_NAT for logged-in clients and is
	// orthogonal to the other bits. It must stay off ed2k-server's 0x8000
	// (accepts OP_IPV6_UPDATE) and 0x20000 (LowID hole punch), and off FlagServerSearch.
	if FlagNatRendezvous == 0x8000 || FlagNatRendezvous == 0x20000 || FlagNatRendezvous == FlagServerSearch {
		t.Fatalf("FlagNatRendezvous 0x%05x collides with an ed2k-server flag", FlagNatRendezvous)
	}
	on := BuildTCPFlags(TCPServerConfig{NatRendezvous: true})
	if on&FlagNatRendezvous == 0 {
		t.Fatalf("NatRendezvous bit must be set: 0x%05x", on)
	}
	off := BuildTCPFlags(TCPServerConfig{NatRendezvous: false})
	if off&FlagNatRendezvous != 0 {
		t.Fatalf("NatRendezvous bit must be clear when off: 0x%05x", off)
	}
	t.Logf("input: NatRendezvous on/off; output flags on=0x%05x off=0x%05x", on, off)
}

func TestBuildUDPFlags(t *testing.T) {
	flags := BuildUDPFlags(UDPServerConfig{
		GetSources: true, GetFiles: true, SupportCrypt: true, DualStack: true,
	})
	expected := FlagNewTags + FlagUnicode + FlagLargeFiles + FlagUdpExtSources + FlagUdpExtSrc2 + FlagUdpExtFiles + FlagUdpObfusc + FlagTcpObfusc + FlagIPv6
	if flags != expected {
		t.Fatalf("flags mismatch: got 0x%x expected 0x%x", flags, expected)
	}
	t.Logf("SRV_UDPFLG word = 0x%04x", flags)
	foreign := BuildUDPFlags(UDPServerConfig{ForeignCallback: true})
	t.Logf("input: ForeignCallback on, output: 0x%x", foreign)
	if foreign&FlagForeignCallback == 0 || flags&FlagForeignCallback != 0 || foreign&FlagNatRendezvous != 0 {
		t.Fatalf("FlagForeignCallback not driven by ForeignCallback: 0x%x / 0x%x", foreign, flags)
	}
	if foreign&0x100000 == 0 || foreign&0x400000 != 0 {
		t.Fatalf("foreign callback must be UDP bit 0x100000, not 0x400000: 0x%x", foreign)
	}
}

// The foreign callback bit goes out in every status reply, server probes (challenge
// 0x55AA....) included.
func TestStatResCarriesForeignCallbackFlag(t *testing.T) {
	flags := BuildUDPFlags(UDPServerConfig{SupportCrypt: true, NatCallback: true, ForeignCallback: true})
	rt := NewServerRuntime(TCPRuntimeConfig{Port: 4661}, UDPRuntimeConfig{UDPFlags: flags}, storage.NewMemoryEngine())
	for _, challenge := range []uint32{0x55AA1234, 0x12345678} {
		packet, err := rt.buildStatRes(challenge, 0x1111, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw := packet.Bytes()
		at := bytes.Index(raw, binary.LittleEndian.AppendUint32(nil, challenge))
		if at < 0 || at+28 > len(raw) {
			t.Fatalf("challenge 0x%x not found in % x", challenge, raw)
		}
		got := binary.LittleEndian.Uint32(raw[at+24:])
		t.Logf("input: challenge 0x%x, output: UDP flags 0x%x", challenge, got)
		if got&FlagForeignCallback == 0 {
			t.Fatalf("challenge 0x%x: flags 0x%x lack 0x100000", challenge, got)
		}
	}
}
