package ed2k

import (
	"encoding/binary"
	"errors"
)

const (
	// cryptAnswerFixed is the fixed part of an obfuscation handshake answer once
	// decrypted: sync magic (4), method (1), padding length (1).
	cryptAnswerFixed = 6

	MagicValueSync = 0x835E6FC4
	MagicValue203  = 203
	MagicValue34   = 34
)

type ClientConfig struct {
	EnableCrypt       bool
	Address           string
	TCPPort           uint16
	ConnectionTimeout int
	Hash              []byte
}

type Client struct {
	Config      ClientConfig
	CryptStatus int
	CryptMethod int
	Hash        []byte
	SendKey     *RC4Key
	RecvKey     *RC4Key
	// negotiation holds the decrypted handshake answer while it arrives in pieces.
	// Each received byte is RC4-decrypted exactly once, as the keystream advances.
	negotiation []byte
}

type HelloAnswer struct {
	Hash          []byte
	ID            uint32
	Port          uint16
	Tags          map[string]any
	ServerAddress uint32
	ServerPort    uint16
}

func NewClient(cfg ClientConfig) *Client {
	status := CsNone
	if cfg.EnableCrypt {
		status = CsUnknown
	}
	return &Client{
		Config:      cfg,
		CryptStatus: status,
	}
}

func (c *Client) BuildHandshake(randomProtocol uint8, randomKey uint32, pad []byte) ([]byte, error) {
	key := make([]byte, 21)
	if len(c.Hash) != 16 {
		return nil, ErrInvalidHashLength
	}
	copy(key, c.Hash)
	key[16] = MagicValue34
	binary.LittleEndian.PutUint32(key[17:], randomKey)
	sendSeed := MD5(key)

	// Both keys hash all 21 bytes (userhash 16 + magic 1 + randomKey 4); only the
	// magic byte differs. See EncryptedStreamSocket.cpp:
	//   SendKey    = MD5(<UserHash 16><MAGICVALUE_34 1><RandomKeyPart 4>)
	//   ReceiveKey = MD5(<UserHash 16><MAGICVALUE_203 1><RandomKeyPart 4>)
	// key[17:21] still holds randomKey here: the copy below rewrites only key[0:16].
	copy(key, c.Hash)
	key[16] = MagicValue203
	recvSeed := MD5(key)

	c.SendKey = RC4CreateKey(sendSeed, true)
	c.RecvKey = RC4CreateKey(recvSeed, true)

	enc := NewBuffer(4 + 1 + 1 + 1 + len(pad))
	_ = enc.PutUInt32LE(MagicValueSync)
	_ = enc.PutUInt8(uint8(EmSupported))
	_ = enc.PutUInt8(uint8(EmPreferred))
	_ = enc.PutUInt8(uint8(len(pad)))
	enc.PutBuffer(pad)
	encPayload := RC4Crypt(enc.Bytes(), len(enc.Bytes()), c.SendKey)

	out := NewBuffer(1 + 4 + len(encPayload))
	_ = out.PutUInt8(randomProtocol)
	_ = out.PutUInt32LE(randomKey)
	out.PutBuffer(encPayload)
	c.CryptStatus = CsNegotiating
	return out.Bytes(), nil
}

// Decrypt feeds received bytes through the client's crypt state. While the
// handshake answer is incomplete it buffers and returns (nil, false, nil); TCP may
// split the answer anywhere, padding included. When the answer completes it returns
// the bytes that followed it, already decrypted, and done=true.
func (c *Client) Decrypt(data []byte) ([]byte, bool, error) {
	switch c.CryptStatus {
	case CsEncrypting:
		return RC4Crypt(data, len(data), c.RecvKey), false, nil
	case CsNegotiating:
		c.negotiation = append(c.negotiation, RC4Crypt(data, len(data), c.RecvKey)...)
		if len(c.negotiation) < cryptAnswerFixed {
			return nil, false, nil
		}
		if binary.LittleEndian.Uint32(c.negotiation) != MagicValueSync {
			c.CryptStatus = CsNone
			return nil, false, errors.New("bad handshake answer received")
		}
		need := cryptAnswerFixed + int(c.negotiation[cryptAnswerFixed-1])
		if len(c.negotiation) < need {
			return nil, false, nil
		}
		c.CryptMethod = int(c.negotiation[4])
		rest := c.negotiation[need:]
		c.negotiation = nil
		c.CryptStatus = CsEncrypting
		return rest, true, nil
	case CsNone:
		return data, false, nil
	default:
		return data, false, nil
	}
}

func (c *Client) BuildHelloPacket() (*Buffer, error) {
	// The hello's own-IP field is informational to the probe target and is 0 when
	// the bind address is not a dotted-quad IPv4 — e.g. the dual-stack wildcard ""
	// or an IPv6 bind. Erroring here would break the reachability probe from a
	// v6-only or wildcard bind; eMule likewise sends 0 when it does not know its IP.
	addr, err := IPv4ToInt32LE(c.Config.Address)
	if err != nil {
		addr = 0
	}
	tags := []Tag{
		{Type: TypeString, Code: TagName, Data: ENodeName},
		{Type: TypeUint32, Code: TagVersion, Data: uint32(ENodeVersionInt)},
	}
	items := []PacketItem{
		{Type: TypeUint8, Value: OpHello},
		{Type: TypeUint8, Value: uint8(16)},
		{Type: TypeHash, Value: c.Config.Hash},
		{Type: TypeUint32, Value: addr},
		{Type: TypeUint16, Value: c.Config.TCPPort},
		{Type: TypeTags, Value: tags},
		{Type: TypeUint32, Value: addr},
		{Type: TypeUint16, Value: c.Config.TCPPort},
	}
	return MakePacket(PrED2K, items)
}

func ReadOpHelloAnswer(data *Buffer) (HelloAnswer, error) {
	out := HelloAnswer{Tags: map[string]any{}}
	hash := data.Get(16)
	if len(hash) != 16 {
		return out, ErrOutOfBounds
	}
	out.Hash = append([]byte(nil), hash...)
	id, err := data.GetUInt32LE()
	if err != nil {
		return out, err
	}
	out.ID = id
	port, err := data.GetUInt16LE()
	if err != nil {
		return out, err
	}
	out.Port = port
	tags, err := data.GetTags()
	if err != nil {
		return out, err
	}
	for _, t := range tags {
		out.Tags[t.Name] = t.Value
	}
	serverAddress, err := data.GetUInt32LE()
	if err != nil {
		return out, err
	}
	out.ServerAddress = serverAddress
	serverPort, err := data.GetUInt16LE()
	if err != nil {
		return out, err
	}
	out.ServerPort = serverPort
	return out, nil
}
