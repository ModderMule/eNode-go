package ed2k

const (
	PrED2K  uint8 = 0xe3
	PrEMule uint8 = 0xc5
	PrZlib  uint8 = 0xd4
	PrNat   uint8 = 0xf1
)

const (
	OpLoginRequest     uint8 = 0x01
	OpHello            uint8 = 0x01
	OpHelloAnswer      uint8 = 0x4c
	OpServerMessage    uint8 = 0x38
	OpServerStatus     uint8 = 0x34
	OpIDChange         uint8 = 0x40
	OpGetServerList    uint8 = 0x14
	OpOfferFiles       uint8 = 0x15
	OpServerList       uint8 = 0x32
	OpServerIdent      uint8 = 0x41
	OpGetSources       uint8 = 0x19
	OpFoundSources     uint8 = 0x42
	OpSearchRequest    uint8 = 0x16
	OpSearchResult     uint8 = 0x33
	OpCallbackRequest  uint8 = 0x1c
	OpCallbackReqd     uint8 = 0x35
	OpCallbackFailed   uint8 = 0x36
	OpGetSourcesObfu   uint8 = 0x23
	OpFoundSourcesObfu uint8 = 0x44
	OpGlobSearchReq3   uint8 = 0x90
	OpGlobSearchReq2   uint8 = 0x92
	OpGlobGetSources2  uint8 = 0x94
	OpGlobServStatReq  uint8 = 0x96
	OpGlobServStatRes  uint8 = 0x97
	OpGlobSearchReq    uint8 = 0x98
	OpGlobSearchRes    uint8 = 0x99
	OpGlobGetSources   uint8 = 0x9a
	OpGlobFoundSources uint8 = 0x9b
	OpServerDescReq    uint8 = 0xa2
	OpServerDescRes    uint8 = 0xa3
	OpDisconnect       uint8 = 0x18
	// OpQueryMoreResult is the client's "More" button: an empty-payload request for the
	// next page of a search whose reply set the more-results flag
	// (srchybrid/SearchResultsWnd.cpp:1282).
	OpQueryMoreResult uint8 = 0x21
)

// Server-to-server gossip opcodes (srchybrid/Opcodes.h:201-205). These are the
// classic Lugdunum peer-exchange set, carried over UDP under PR_ED2K:
//
//	OpServerListReq  (0xa0)  "register me" — <ip 4 network order><port 2 LE>, and
//	                         Lugdunum treats it as an implicit list request too.
//	OpServerListRes  (0xa1)  the peer list — <count 1> then count × (<ip 4><port 2 LE>).
//	OpServerListReq2 (0xa4)  explicit "send me your list", empty payload.
//
// Both 0xa0 and 0xa1 are accepted only from the obfuscated gossip channel: the
// original binary logs "ignore non obfuscated OP_SERVER_LIST_REQ/_RES from %s" and
// drops the plaintext forms. 0xa1 is also overloaded — mldonkey *clients* emit it
// with an unrelated payload — so it is never trusted from a sender that has not
// completed the handshake (eserver: "received a servlist from unknown server %s:%d").
const (
	OpServerListReq  uint8 = 0xa0
	OpServerListRes  uint8 = 0xa1
	OpServerListReq2 uint8 = 0xa4
)

// IPv6 gossip opcodes (eNode-go extension). Lugdunum's OP_SERVER_LIST_RES is
// strictly IPv4 — <count 1> then count × (<ip 4><port 2>) — with no version field
// and no room to widen it, so IPv6 peers travel in their own request/response pair
// and 0xa1 stays byte-identical to what a real eserver emits.
//
//	OpServerListReqIPv6 (0xa7)  empty payload, the v6 analogue of 0xa4.
//	OpServerListResIPv6 (0xa8)  <count 1> then count × (<ipv6 16 network order><port 2 LE>).
//
// 0xa7/0xa8 are free in the *server↔client* namespace: srchybrid/Opcodes.h ends that
// block at OP_SERVER_LIST_REQ2 0xa4, and the OP_FWCHECKUDPREQ 0xa7 /
// OP_KAD_FWTCPCHECK_ACK 0xa8 at :283-284 live in the separate client↔client block.
// That is the same reasoning that allocated OpGlobGetSourcesIPv6 0xa5 / 0xa6 above,
// which likewise coexist with client↔client OP_CHATCAPTCHAREQ/RES. Sent only to a
// peer that advertised FlagIPv6 in its OP_GLOBSERVSTATRES udpflags, so a stock
// eserver never sees them.
const (
	OpServerListReqIPv6 uint8 = 0xa7
	OpServerListResIPv6 uint8 = 0xa8
)

// IPv6 source-exchange opcodes (eNode-go extension).
//
// These carry the richer tag-block source format (§Format 2 of the IPv6 plan): a
// client opts in by sending the request opcode, and the server answers in the
// extended layout only to such a client. The values are virgin space above the
// classic high-water marks (OP_GETSOURCES_OBFU 0x23, OP_SERVER_LIST_REQ2 0xa4)
// and are free across every surveyed eMule tree, so a legacy client never emits
// them and its ProcessPacket drops them with a harmless default case.
const (
	OpGetSourcesIPv6       uint8 = 0x24
	OpFoundSourcesIPv6     uint8 = 0x25
	OpGlobGetSourcesIPv6   uint8 = 0xa5
	OpGlobFoundSourcesIPv6 uint8 = 0xa6
)

// OpCallbackReqdIPv6 is the IPv6 form of OP_CALLBACKREQUESTED (0x35): the server
// sends it to a v6-capable, firewalled callback target so it can call back to a
// requester that has no usable IPv4 but a reachable public IPv6. The payload is
// <ipv6:16><port:2> — the classic packet widened from a uint32 IP to a 16-byte
// in6_addr, no crypt trailer (matching eNode-go's classic emitter). 0x26 is the
// next value after the IPv6 source opcodes 0x24/0x25 and is free across every
// surveyed eMule tree, so a legacy client drops it in its ProcessPacket default.
const OpCallbackReqdIPv6 uint8 = 0x26

// SentinelIPv6ID is the ClientID value that marks an IPv6-only source inside the
// classic OP_FOUNDSOURCES list: eMule reads 0xffffffff and then consumes 16 raw
// in6_addr bytes that follow the port (and, for _OBFU, the crypt fields). Only
// emitted to a session known to parse it — see the gating rule in the plan.
const SentinelIPv6ID uint32 = 0xffffffff

const (
	OpNatSync       uint8 = 0xe1
	OpNatPing       uint8 = 0xe2
	OpNatRegisterEx uint8 = 0xe3
	OpNatRegister   uint8 = 0xe4
	OpNatFailed     uint8 = 0xe5
	OpNatKeepAlive  uint8 = 0xe6
	OpNatSyncEx     uint8 = 0xe7
	OpNatReping     uint8 = 0xe8
	OpNatSync2      uint8 = 0xe9
	OpNatData       uint8 = 0xea
	OpNatAck        uint8 = 0xeb
	OpNatRst        uint8 = 0xef
)

// IPv6 NAT-traversal opcodes (eNode-go extension). These are the widened forms of
// the register-ack and the peer-sync used to hole-punch between two firewalled
// IPv6 peers — the v6 analogue of the classic IPv4 LowID↔LowID hole-punch. They
// live in the free PR_NAT (0xf1) opcode space above the classic high-water mark
// (0xeb, plus 0xef for RST) and are only ever interpreted after the 0xf1 protocol
// byte, so they never collide with the PR_ED2K opcodes 0x24/0x25/0x26. See
// docs/ipv6-client-implementation-spec.md §9.
const (
	OpNatRegisterIPv6 uint8 = 0xec // server→client REGISTER ack: [port:2 BE][ipv6:16]
	OpNatSyncIPv6     uint8 = 0xed // server→client: [ipv6:16][port:2 BE][hash:16][connAck:4][version:1]
)

const (
	TypeHash   uint8 = 0x01
	TypeString uint8 = 0x02
	TypeUint32 uint8 = 0x03
	TypeFloat  uint8 = 0x04
	TypeBool   uint8 = 0x05
	TypeBlob   uint8 = 0x07
	TypeUint16 uint8 = 0x08
	TypeUint8  uint8 = 0x09
	TypeBsob   uint8 = 0x0a
	TypeUint64 uint8 = 0x0b
	TypeTags   uint8 = 0x0f
)

const (
	PsNew              = 1
	PsReady            = 2
	PsWaitingData      = 3
	PsCryptNegotiating = 4
)

// MaxTCPPacketSize bounds the payload size a peer may declare in a TCP packet
// header. Without it, the 4-byte size field is allocated verbatim, so a 6-byte
// header can reserve ~4 GiB. eMule applies the same ceiling and drops the
// connection past it: see src/core/net/EMSocket.cpp, kMaxReadBuffer / kErrTooBig.
const MaxTCPPacketSize = 2_000_000

// maxHelloAnswerBytes caps what the firewall probe will accumulate from the
// peer it is probing.
//
// Defence in depth, not the primary bound: while readHelloAnswer rejects a
// declared size above MaxTCPPacketSize, every packet completes and is consumed
// once 5+size bytes arrive, so the reassembly buffer cannot exceed roughly
// MaxTCPPacketSize plus one read. This ceiling only matters if that size check
// is ever relaxed — which is exactly when it would be missed.
const maxHelloAnswerBytes = 4 * MaxTCPPacketSize

const (
	CsNone        = 0
	CsUnknown     = 1
	CsNegotiating = 4
	CsEncrypting  = 5
)

const (
	TagName            uint8 = 0x01
	TagSize            uint8 = 0x02
	TagType            uint8 = 0x03
	TagFormat          uint8 = 0x04
	TagVersion         uint8 = 0x11
	TagVersion2        uint8 = 0x91
	TagPort            uint8 = 0x0f
	TagDescription     uint8 = 0x0b
	TagDynIP           uint8 = 0x85
	TagSources         uint8 = 0x15
	TagCompleteSources uint8 = 0x30
	TagMuleVersion     uint8 = 0xfb
	TagFlags           uint8 = 0x20
	TagRating          uint8 = 0xf7
	TagSizeHi          uint8 = 0x3a
	TagMediaArtist     uint8 = 0xd0
	TagMediaAlbum      uint8 = 0xd1
	TagMediaTitle      uint8 = 0xd2
	TagMediaLength     uint8 = 0xd3
	TagMediaBitrate    uint8 = 0xd4
	TagMediaCodec      uint8 = 0xd5
	TagSearchTree      uint8 = 0x0e
	TagEmuleUDPPorts   uint8 = 0xf9
	TagEmuleOptions1   uint8 = 0xfa
	TagEmuleOptions2   uint8 = 0xfe
	TagAuxPortsList    uint8 = 0x93
	// IPv6 MOD tags, allocated by eMuleAI (Opcodes.h) and reused here verbatim.
	// CT_MOD_IP_V6 carries a client's public IPv6 as a 16-byte HASH tag in
	// OP_LOGINREQUEST; CT_MOD_SVR_IP_V6 carries the server's own IPv6 as a HASH tag
	// in OP_SERVERIDENT.
	TagModIPv6    uint8 = 0xae
	TagModSvrIPv6 uint8 = 0xaf
	// TagModYourIP is CT_MOD_YOUR_IP, already allocated by eMuleAI (Opcodes.h:585)
	// for "the address I see you coming from" — a uint32 for an IPv4 peer, a 16-byte
	// HASH for an IPv6 one, written into the client-to-client hello
	// (UpDownClient.cpp:1195-1201). eNode-go emits the HASH form in OP_SERVERIDENT so
	// a client learns which of its addresses actually reached the server; with RFC
	// 4941 temporary addresses and multiple prefixes it cannot know that locally.
	// Only ever the observed peer address, never an echo of the client's own
	// CT_MOD_IP_V6 claim. See docs/ipv6-client-implementation-spec.md §3a.
	TagModYourIP uint8 = 0xad
	// TagNatPort is an eNode-go OP_SERVERIDENT extension: the server's NAT-rendezvous
	// UDP port as a uint16, so a client learns where to REGISTER/SYNC2 without
	// assuming the default 2004. 0x9D is free across the ST_* server-tag, CT_* client
	// -tag and OP_* opcode namespaces in both surveyed C++ trees (ST_ tags end at
	// 0x98, CT_ tags start at 0xA0); eMule's OP_SERVERIDENT tag loop consumes unknown
	// name-IDs without disconnecting. Emitted only when natTraversal.serverIndependent
	// is on. See docs/ipv6-client-implementation-spec.md §9.
	TagNatPort uint8 = 0x9d
	// TagIPv6Status is an eNode-go OP_SERVERIDENT extension: an IPv6Status* bitfield
	// (uint8) telling the session what the server knows about its IPv6 — whether it
	// holds one, whether that address is treated as reachable, and whether that
	// verdict came from a real dial-back. Complements TagModYourIP: reflection only
	// happens on a v6-connected session, whereas this reaches a v4-connected client
	// that advertised CT_MOD_IP_V6 and would otherwise never learn whether it is
	// being published as a v6 source. 0xAB is free across the ST_*, CT_* and OP_*
	// namespaces in both surveyed C++ trees. See docs/ipv6-client-implementation-spec.md §3a.
	TagIPv6Status uint8 = 0xab
)

// IPv6Status* are the bits of the TagIPv6Status (0xab) bitfield. Unset bits mean
// "no", never "unknown" — the tag is omitted entirely when the server has no
// verdict to report, so a client that sees it can trust every bit.
const (
	// IPv6StatusHave is set when the server holds a public IPv6 for this session,
	// from the CT_MOD_IP_V6 login tag or from a v6 connection.
	IPv6StatusHave uint8 = 0x01
	// IPv6StatusReachable is set when that address is treated as reachable on the
	// client's advertised port, i.e. the client is published as an IPv6 source.
	IPv6StatusReachable uint8 = 0x02
	// IPv6StatusProbed is set when the reachability verdict came from an actual
	// dial-back rather than a trust default (a v6-connected session, or tcp.probeIPv6
	// turned off). Without this bit a client must not report "verified" to its user.
	IPv6StatusProbed uint8 = 0x04
)

const (
	ValPartialID    uint32 = 0xfcfcfcfc
	ValPartialPort  uint16 = 0xfcfc
	ValCompleteID   uint32 = 0xfbfbfbfb
	ValCompletePort uint16 = 0xfbfb
)

const (
	FlagZlib          uint32 = 0x0001
	FlagIPInLogin     uint32 = 0x0002
	FlagAuxPort       uint32 = 0x0004
	FlagNewTags       uint32 = 0x0008
	FlagUnicode       uint32 = 0x0010
	FlagLargeFiles    uint32 = 0x0100
	FlagSupportCrypt  uint32 = 0x0200
	FlagRequestCrypt  uint32 = 0x0400
	FlagRequireCrypt  uint32 = 0x0800
	FlagUdpExtSources uint32 = 0x0001
	FlagUdpExtFiles   uint32 = 0x0002
	FlagUdpExtSrc2    uint32 = 0x0020
	FlagUdpObfusc     uint32 = 0x0200
	FlagTcpObfusc     uint32 = 0x0400
	// FlagIPv6 advertises IPv6 support in the SRV_TCPFLG_* / SRV_UDPFLG_* word.
	// No eMule tree defines any server flag >= 0x1000; the only occupants are
	// ed2kNET's unofficial 0x1000/0x2000 (chacha20/aes256), so 0x4000 is the first
	// clean bit. Clients ignore unknown bits, so this is display/verify metadata.
	FlagIPv6 uint32 = 0x4000
	// FlagNatRendezvous advertises that this server offers server-independent
	// (cross-server / serverless) PR_NAT hole-punch rendezvous — it will pair two
	// registered clients regardless of which eD2K server (if any) they are logged
	// into. 0x8000 is the next clean bit above FlagIPv6 (0x4000); eMule's SrvTcpFlag
	// word tops out at TCPOBFUSCATION 0x400, so nothing collides. Clients ignore
	// unknown bits. Advertised only when natTraversal.serverIndependent is on. See
	// docs/ipv6-client-implementation-spec.md §9.
	FlagNatRendezvous uint32 = 0x8000
)

const (
	ENodeVersionStr = "v0.1.0"
	ENodeVersionInt = 0x00000003
	ENodeName       = "eNode-go"
)
