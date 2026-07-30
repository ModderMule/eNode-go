package ed2k

import (
	"encoding/binary"
	"net"
)

const (
	MagicValueUDPServerClient = 0xA5
	MagicValueUDPClientServer = 0x6B
	MagicValueUDPSyncClient   = 0x395F2EC1
	MagicValueUDPSyncServer   = 0x13EF24D5
)

type UDPCrypt struct {
	Status    int
	ServerKey uint32
}

func NewUDPCrypt(supportCrypt bool, serverKey uint32) *UDPCrypt {
	status := CsNone
	if supportCrypt {
		status = CsEncrypting
	}
	return &UDPCrypt{
		Status:    status,
		ServerKey: serverKey,
	}
}

func (u *UDPCrypt) rc4Key(magic byte, randomKey uint16) *RC4Key {
	key := make([]byte, 7)
	b := NewBufferFromBytes(key)
	_ = b.PutUInt32LE(u.ServerKey)
	_ = b.PutUInt8(magic)
	_ = b.PutUInt16LE(randomKey)
	return RC4CreateKey(MD5(key), false)
}

// Decrypt unwraps a datagram sent to us as a server by a client, using direction byte
// MAGICVALUE_UDP_CLIENTSERVER (0x6B). This is the receive path of the client-facing
// obfuscated listener, and also of inbound server-to-server gossip — a peer addressing us
// is in the client role, and encrypts with the ServerKey we published to it.
func (u *UDPCrypt) Decrypt(buffer []byte) []byte {
	return u.decrypt(buffer, MagicValueUDPClientServer)
}

// DecryptFromServer unwraps a datagram a *server* sent to us, using direction byte
// MAGICVALUE_UDP_SERVERCLIENT (0xA5).
//
// The mirror of EncryptAsClient, and needed for the same reason: this server also acts as a
// client during gossip. Specifically, the reply to the phase-2 bootstrap ping is encrypted
// by the peer in its server role and keyed on the *challenge we sent*, not on any
// ServerKey — we have none for that peer yet, which is the point of the exchange. Decrypt
// cannot read it, so a reply that fell through to the normal path was silently dropped and
// no peer ever got keyed. See srchybrid/UDPSocket.cpp:159-171.
func (u *UDPCrypt) DecryptFromServer(buffer []byte) []byte {
	return u.decrypt(buffer, MagicValueUDPServerClient)
}

func (u *UDPCrypt) decrypt(buffer []byte, direction byte) []byte {
	if u.Status != CsEncrypting {
		return buffer
	}
	b := NewBufferFromBytes(buffer)
	protocol, err := b.GetUInt8()
	if err != nil {
		return buffer
	}
	// For server UDP packets, plaintext starts with PR_ED2K.
	// Obfuscated marker byte can legally collide with other protocol constants
	// (e.g. PR_EMULE/PR_ZLIB), so only PR_ED2K should bypass decryption here.
	if protocol == PrED2K {
		b.Pos(0)
		return b.Bytes()
	}
	clientKey, err := b.GetUInt16LE()
	if err != nil {
		return buffer
	}
	data := b.Get()
	dec := RC4Crypt(data, len(data), u.rc4Key(direction, clientKey))
	db := NewBufferFromBytes(dec)
	sync, err := db.GetUInt32LE()
	if err != nil || sync != MagicValueUDPSyncServer {
		return buffer
	}
	padLength, err := db.GetUInt8()
	if err != nil {
		return buffer
	}
	// Only the low nibble is the padding length (0..15); the high nibble is
	// reserved and must be masked off. Then reject a packet whose remaining bytes
	// cannot cover the padding — matching eMule's decryptReceivedServer, which does
	// `byPadding[0] &= 0xf` and bails when `remaining <= padLen`
	// (srchybrid/EncryptedDatagramSocket.cpp:404-415). At this point db.Remaining()
	// equals eMule's `remaining` (datagram length minus the 8-byte crypt header).
	// On rejection return the original buffer: its first byte is not PrED2K, so the
	// dispatcher drops it, which is eMule's junk-passthrough behaviour.
	padLength &= 0x0f
	if db.Remaining() <= int(padLength) {
		return buffer
	}
	_ = db.Get(int(padLength))
	return db.Get()
}

// Encrypt wraps a datagram for the server-to-client direction: the reply path of the
// client-facing obfuscated listener. Direction byte MAGICVALUE_UDP_SERVERCLIENT (0xA5).
func (u *UDPCrypt) Encrypt(buffer []byte) []byte {
	return u.encrypt(buffer, MagicValueUDPServerClient)
}

// EncryptAsClient wraps a datagram for the client-to-server direction, with direction
// byte MAGICVALUE_UDP_CLIENTSERVER (0x6B).
//
// Needed because the two directions are not interchangeable and this server sends in
// both. Against its own clients it is the server (Encrypt, 0xA5). But in
// server-to-server gossip it is the *sender* addressing a peer, so it must use the
// direction byte that peer's receive path derives its key from — which is the same 0x6B
// our own Decrypt uses. Sending 0xA5 there produces a frame the peer cannot decrypt at
// all, and the failure is silent: the peer sees junk that fails its magic check and
// drops it.
//
// The sync magic stays MagicValueUDPSyncServer in both directions, matching Decrypt and
// the envelope the original binary emits; only the direction byte in the key derivation
// differs. See docs/server-gossip.md.
func (u *UDPCrypt) EncryptAsClient(buffer []byte) []byte {
	return u.encrypt(buffer, MagicValueUDPClientServer)
}

func (u *UDPCrypt) encrypt(buffer []byte, direction byte) []byte {
	if u.Status != CsEncrypting {
		return buffer
	}
	randomKey := uint16(Rand(0xffff))
	enc := NewBuffer(len(buffer) + 5)
	_ = enc.PutUInt32LE(MagicValueUDPSyncServer)
	_ = enc.PutUInt8(0)
	enc.PutBuffer(buffer)
	encrypted := RC4Crypt(enc.Bytes(), len(enc.Bytes()), u.rc4Key(direction, randomKey))

	out := NewBuffer(len(buffer) + 8)
	_ = out.PutUInt8(RandProtocol())
	_ = out.PutUInt16LE(randomKey)
	out.PutBuffer(encrypted)
	return out.Bytes()
}

// deriveUDPKey returns the per-client server-UDP obfuscation key: MD5(secret ‖
// clientIP) folded to a uint32. Binding the key to the source IP restores the
// anti-spoofing property a single global key gave up — eMule re-pings for a
// fresh key once its public IP changes (CServer::GetServerKeyUDP returns 0,
// srchybrid/Server.cpp:279-291). The value is opaque to the client (it stores
// and echoes whatever we send at reply offset +36), so any deterministic per-IP
// derivation works; being deterministic, the server recomputes the same key on
// every datagram from that IP with no per-client state. Keyed on IP only, not
// port, so a NAT port change does not invalidate it. Never returns 0 — a zero
// key means "no key" to the client (srchybrid/Server.cpp:281) and it would
// refuse to obfuscate.
func deriveUDPKey(secret uint32, ip net.IP) uint32 {
	var seed [4]byte
	binary.LittleEndian.PutUint32(seed[:], secret)
	norm := ip
	if v4 := ip.To4(); v4 != nil {
		norm = v4 // stable 4-byte form; v6 falls through to the 16-byte value
	}
	key := binary.LittleEndian.Uint32(MD5(append(seed[:], norm...)))
	if key == 0 {
		key = 1
	}
	return key
}
