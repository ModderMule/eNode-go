package ed2k

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"enode/logging"
)

func LogTCPPacket(module string, dir string, remote string, protocol uint8, opcode uint8, payload []byte) {
	if !logging.DebugEnabled() {
		return
	}
	size := uint32(len(payload) + 1)
	logging.Debugf(formatLogLine(module, "tcp", dir, remote, protocolName(protocol), opcodeName(opcode, dir),
		fmt.Sprintf("%d", size), fmt.Sprintf("%d", len(payload))))
}

func LogTCPRaw(module string, dir string, remote string, raw []byte) {
	if !logging.DebugEnabled() {
		return
	}
	proto, size, opcode, payload, ok := parseTCPRaw(raw)
	if !ok {
		logging.Debugf(formatLogLine(module, "tcp", dir, remote, "-", "-", "-", "-"))
		return
	}
	logging.Debugf(formatLogLine(module, "tcp", dir, remote, protocolName(proto), opcodeName(opcode, dir),
		fmt.Sprintf("%d", size), fmt.Sprintf("%d", len(payload))))
}

func LogUDPRaw(module string, dir string, remote string, raw []byte) {
	if !logging.DebugEnabled() {
		return
	}
	proto, opcode, payload, ok := parseUDPRaw(raw)
	if !ok {
		logging.Debugf(formatLogLine(module, "udp", dir, remote, "-", "-", "-", "-"))
		return
	}
	logging.Debugf(formatLogLine(module, "udp", dir, remote, protocolName(proto), opcodeName(opcode, dir),
		"-", fmt.Sprintf("%d", len(payload))))
}

func LogNATRaw(module string, dir string, remote string, raw []byte) {
	if !logging.DebugEnabled() {
		return
	}
	proto, size, opcode, payload, ok := parseNATRaw(raw)
	if !ok {
		logging.Debugf(formatLogLine(module, "nat", dir, remote, "-", "-", "-", "-"))
		return
	}
	base := formatLogLine(module, "nat", dir, remote, protocolName(proto), opcodeName(opcode, dir),
		fmt.Sprintf("%d", size), fmt.Sprintf("%d", len(payload)))
	logging.Debugf("%s, payload=%s", base, formatKV(formatNATPayload(opcode, payload)))
}

func parseTCPRaw(raw []byte) (uint8, uint32, uint8, []byte, bool) {
	if len(raw) < 6 {
		return 0, 0, 0, nil, false
	}
	proto := raw[0]
	size := binary.LittleEndian.Uint32(raw[1:5])
	if size == 0 {
		return proto, size, 0, nil, false
	}
	if int(5+size) > len(raw) {
		return proto, size, 0, nil, false
	}
	opcode := raw[5]
	payload := raw[6 : 5+size]
	return proto, size, opcode, payload, true
}

func parseUDPRaw(raw []byte) (uint8, uint8, []byte, bool) {
	if len(raw) < 2 {
		return 0, 0, nil, false
	}
	return raw[0], raw[1], raw[2:], true
}

func parseNATRaw(raw []byte) (uint8, uint32, uint8, []byte, bool) {
	if len(raw) < 6 {
		return 0, 0, 0, nil, false
	}
	if raw[0] != PrNat {
		return raw[0], 0, 0, nil, false
	}
	size := binary.LittleEndian.Uint32(raw[1:5])
	if size == 0 {
		return PrNat, size, 0, nil, false
	}
	if int(5+size) > len(raw) {
		return PrNat, size, 0, nil, false
	}
	opcode := raw[5]
	payload := raw[6 : 5+size]
	return PrNat, size, opcode, payload, true
}

func protocolName(p uint8) string {
	switch p {
	case PrED2K:
		return "PR_ED2K(0xe3)"
	case PrEMule:
		return "PR_EMULE(0xc5)"
	case PrZlib:
		return "PR_ZLIB(0xd4)"
	case PrNat:
		return "PR_NAT(0xf1)"
	default:
		return fmt.Sprintf("0x%02x", p)
	}
}

func opcodeName(op uint8, dir string) string {
	switch op {
	case OpLoginRequest:
		if dir == "recv" || dir == "recv-decompressed" {
			return "OP_LOGINREQUEST(0x01) login/session registration"
		}
		return "OP_HELLO(0x01) handshake check client path"
	case OpHelloAnswer:
		return "OP_HELLOANSWER(0x4c)"
	case OpServerMessage:
		return "OP_SERVERMESSAGE(0x38)"
	case OpServerStatus:
		return "OP_SERVERSTATUS(0x34)"
	case OpIDChange:
		return "OP_IDCHANGE(0x40)"
	case OpGetServerList:
		return "OP_GETSERVERLIST(0x14)"
	case OpOfferFiles:
		return "OP_OFFERFILES(0x15)"
	case OpServerList:
		return "OP_SERVERLIST(0x32)"
	case OpServerIdent:
		return "OP_SERVERIDENT(0x41)"
	case OpGetSources:
		return "OP_GETSOURCES(0x19)"
	case OpFoundSources:
		return "OP_FOUNDSOURCES(0x42)"
	case OpSearchRequest:
		return "OP_SEARCHREQUEST(0x16)"
	case OpSearchResult:
		return "OP_SEARCHRESULT(0x33)"
	case OpCallbackRequest:
		return "OP_CALLBACKREQUEST(0x1c)"
	case OpCallbackReqd:
		return "OP_CALLBACKREQD(0x35)"
	case OpCallbackFailed:
		return "OP_CALLBACKFAILED(0x36)"
	case OpGetSourcesObfu:
		return "OP_GETSOURCES_OBFU(0x23)"
	case OpFoundSourcesObfu:
		return "OP_FOUNDSOURCES_OBFU(0x44)"
	case OpGlobSearchReq3:
		return "OP_GLOBSEARCHREQ3(0x90)"
	case OpGlobSearchReq2:
		return "OP_GLOBSEARCHREQ2(0x92)"
	case OpGlobGetSources2:
		return "OP_GLOBGETSOURCES2(0x94)"
	case OpGlobServStatReq:
		return "OP_GLOBSERVSTATREQ(0x96)"
	case OpGlobServStatRes:
		return "OP_GLOBSERVSTATRES(0x97)"
	case OpGlobSearchReq:
		return "OP_GLOBSEARCHREQ(0x98)"
	case OpGlobSearchRes:
		return "OP_GLOBSEARCHRES(0x99)"
	case OpGlobGetSources:
		return "OP_GLOBGETSOURCES(0x9a)"
	case OpGlobFoundSources:
		return "OP_GLOBFOUNDSOURCES(0x9b)"
	case OpServerDescReq:
		return "OP_SERVERDESCREQ(0xa2)"
	case OpServerDescRes:
		return "OP_SERVERDESCRES(0xa3)"
	case OpNatSync:
		return "OP_NATSYNC(0xe1)"
	case OpNatPing:
		return "OP_NATPING(0xe2)"
	case OpNatRegisterEx:
		return "OP_NATREGISTER_EX(0xe3)"
	case OpNatRegister:
		return "OP_NATREGISTER(0xe4)"
	case OpNatFailed:
		return "OP_NATFAILED(0xe5)"
	case OpNatKeepAlive:
		return "OP_NATKEEPALIVE(0xe6)"
	case OpNatSyncEx:
		return "OP_NATSYNC_EX(0xe7)"
	case OpNatReping:
		return "OP_NATREPING(0xe8)"
	case OpNatSync2:
		return "OP_NATSYNC2(0xe9)"
	case OpNatData:
		return "OP_NATDATA(0xea)"
	case OpNatAck:
		return "OP_NATACK(0xeb)"
	case OpNatRst:
		return "OP_NATRST(0xef)"
	default:
		return fmt.Sprintf("0x%02x", op)
	}
}

func formatLogLine(module, proto, dir, remote, protocol, opcode, size, payloadLen string) string {
	return fmt.Sprintf(
		"[module=%s] proto=%s, dir=%s, remote=%s, protocol=%s, opcode=%s, size=%s, payloadLen=%s",
		formatModule(module),
		formatKV(proto),
		formatKV(dir),
		formatKV(remote),
		formatKV(protocol),
		formatKV(opcode),
		formatKV(size),
		formatKV(payloadLen),
	)
}

func formatKV(v string) string {
	if v == "" {
		return `""`
	}
	for _, ch := range v {
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '"' {
			return strconv.Quote(v)
		}
	}
	return v
}

func formatModule(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}
