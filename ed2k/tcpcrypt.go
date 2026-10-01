package ed2k

import (
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
)

const (
	MagicValueServer    = 203
	MagicValueRequester = 34
)

// TCPCrypt owns the obfuscation state machine for one connection.
//
// state/sendKey/recvKey are guarded by mu because they are read from goroutines
// other than the one driving the connection: writeRaw is reachable from the
// status ticker and from a peer's OP_CALLBACKREQUEST, while only the owning
// goroutine advances the state machine. RC4 is a stateful stream cipher, so a
// torn read of the key corrupts the rest of the stream, not just one packet.
type TCPCrypt struct {
	Packet *Packet

	mu      sync.RWMutex
	state   int
	sendKey *RC4Key
	recvKey *RC4Key
	// pending gathers a handshake stage until it is complete, like MFC's
	// m_nReceiveBytesWanted: TCP may split the key exchange or the padding
	// anywhere. In CsNegotiating it holds plaintext, each byte RC4-decrypted once
	// on arrival because the keystream only moves forward.
	pending []byte
}

const (
	// cryptRequestFixed is the client's opening, before its padding: marker (1),
	// DH public key (96), padding length (1).
	cryptRequestFixed = 1 + CryptPrimeSize + 1
	// cryptHandshakeFixed is the client's encrypted reply, before its padding:
	// sync magic (4), method (1), padding length (1).
	cryptHandshakeFixed = 4 + 1 + 1
)

func NewTCPCrypt(packet *Packet, supportCrypt bool) *TCPCrypt {
	status := CsNone
	if supportCrypt {
		status = CsUnknown
	}
	return &TCPCrypt{Packet: packet, state: status}
}

// ProcessData advances the handshake with the next chunk of the stream. It returns
// (nil, nil) while a stage is still incomplete. Completing the key exchange returns
// the server's answer, to be written raw; completing the client's reply returns the
// decrypted bytes that followed it, normally its login.
func (t *TCPCrypt) ProcessData(buffer *Buffer) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	data := buffer.Get()
	switch t.state {
	case CsNone:
		return nil, nil
	case CsUnknown:
		t.pending = append(t.pending, data...)
		need := cryptRequestFixed
		if len(t.pending) >= need {
			need += int(t.pending[need-1])
		}
		if len(t.pending) < need {
			return nil, nil
		}
		if len(t.pending) > need {
			// The client waits for the server's key before it sends anything else.
			return nil, errors.New("data before the key exchange completed")
		}
		resp, err := t.negotiate(t.pending[1 : 1+CryptPrimeSize])
		if err != nil {
			return nil, err
		}
		t.pending = nil
		t.Packet.Status = PsCryptNegotiating
		t.state = CsNegotiating
		return resp, nil
	case CsNegotiating:
		t.pending = append(t.pending, RC4Crypt(data, len(data), t.recvKey)...)
		rest, done, err := t.handshake()
		if err != nil || !done {
			return nil, err
		}
		t.pending = nil
		t.state = CsEncrypting
		t.Packet.Status = PsNew
		return rest, nil
	default:
		return nil, errors.New("unexpected crypt status")
	}
}

// Buffered reports how many bytes of an incomplete handshake stage are held.
func (t *TCPCrypt) Buffered() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.pending)
}

func (t *TCPCrypt) State() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.state
}

func (t *TCPCrypt) SetState(state int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state = state
}

// SendCipher returns the send key, and whether the stream is encrypting. Both
// are read under one lock: a caller that checked the state separately could
// pair a stale state with a freshly rotated key.
func (t *TCPCrypt) SendCipher() (*RC4Key, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sendKey, t.state == CsEncrypting
}

// RecvCipher mirrors SendCipher for the receive direction.
func (t *TCPCrypt) RecvCipher() (*RC4Key, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.recvKey, t.state == CsEncrypting
}

func (t *TCPCrypt) StatusValue() int {
	return t.State()
}

func (t *TCPCrypt) CryptStatus() int {
	return t.State()
}

// negotiate answers the client's DH public key aBytes (the marker and padding around
// it are already consumed) with the server's key and its encrypted sync block.
func (t *TCPCrypt) negotiate(aBytes []byte) ([]byte, error) {
	g := big.NewInt(2)
	p := new(big.Int).SetBytes(CryptPrime)
	A := new(big.Int).SetBytes(aBytes)
	bRaw, err := RandBuf(CryptDhaSize)
	if err != nil {
		return nil, err
	}
	b := new(big.Int).SetBytes(bRaw)

	B := new(big.Int).Exp(g, b, p)
	K := new(big.Int).Exp(A, b, p)

	kBuf := make([]byte, CryptPrimeSize+1)
	kBytes := K.Bytes()
	copy(kBuf[CryptPrimeSize-len(kBytes):CryptPrimeSize], kBytes)

	kBuf[CryptPrimeSize] = MagicValueServer
	t.sendKey = RC4CreateKey(MD5(kBuf), true)
	kBuf[CryptPrimeSize] = MagicValueRequester
	t.recvKey = RC4CreateKey(MD5(kBuf), true)

	pad, err := RandBuf(Rand(16))
	if err != nil {
		return nil, err
	}

	rc4Buf := NewBuffer(4 + 1 + 1 + 1 + len(pad))
	_ = rc4Buf.PutUInt32LE(MagicValueSync)
	_ = rc4Buf.PutUInt8(uint8(EmSupported))
	_ = rc4Buf.PutUInt8(uint8(EmPreferred))
	_ = rc4Buf.PutUInt8(uint8(len(pad)))
	rc4Buf.PutBuffer(pad)
	enc := RC4Crypt(rc4Buf.Bytes(), len(rc4Buf.Bytes()), t.sendKey)

	BBytes := B.Bytes()
	bout := make([]byte, CryptPrimeSize)
	copy(bout[CryptPrimeSize-len(BBytes):], BBytes)
	return append(bout, enc...), nil
}

// handshake checks the client's decrypted reply gathered in pending. done is false
// until the reply and its padding are complete; rest is what followed them. It is
// called from ProcessData with t.mu already held.
func (t *TCPCrypt) handshake() (rest []byte, done bool, err error) {
	if len(t.pending) < 4 {
		return nil, false, nil
	}
	if binary.LittleEndian.Uint32(t.pending) != MagicValueSync {
		return nil, false, errors.New("wrong MAGICVALUE_SYNC")
	}
	if len(t.pending) < cryptHandshakeFixed {
		return nil, false, nil
	}
	if t.pending[4] != uint8(EmObfuscate) {
		return nil, false, errors.New("encryption method not supported")
	}
	need := cryptHandshakeFixed + int(t.pending[cryptHandshakeFixed-1])
	if len(t.pending) < need {
		return nil, false, nil
	}
	return t.pending[need:], true, nil
}

func (t *TCPCrypt) Decrypt(buffer []byte) []byte {
	if key, encrypting := t.RecvCipher(); encrypting {
		return RC4Crypt(buffer, len(buffer), key)
	}
	return buffer
}

func (t *TCPCrypt) ProcessForPacket(buffer *Buffer) error {
	_, err := t.ProcessData(buffer)
	return err
}

func (t *TCPCrypt) Process(buffer *Buffer) error {
	_, err := t.ProcessData(buffer)
	return err
}
