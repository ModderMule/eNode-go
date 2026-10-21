package obfs

import (
	"net/netip"
	"time"
)

// Fragment reassembly bounds of Protocol.md §4.4 (all initial values).
const (
	fragPerSource = 4
	fragTimeout   = 3 * time.Second
	fragMaxSize   = 1500
	fragMaxBytes  = 4 << 20
	fragMaxMsgs   = 65536
)

type fragKey struct {
	from netip.AddrPort
	id   byte
}

type fragMsg struct {
	key     fragKey
	total   int
	pieces  [][]byte
	have    int
	size    int
	started time.Time
}

// reassembler keeps incomplete fragment sets. It is not safe for concurrent
// use; Conn holds its lock.
type reassembler struct {
	msgs   map[fragKey]*fragMsg
	order  []*fragMsg // oldest first
	perSrc map[netip.AddrPort]int
	bytes  int
}

func newReassembler() *reassembler {
	return &reassembler{msgs: map[fragKey]*fragMsg{}, perSrc: map[netip.AddrPort]int{}}
}

// add takes one FRAGMENT body (msg_id ‖ frag ‖ piece) and returns the whole
// datagram once every piece has arrived.
func (r *reassembler) add(from netip.AddrPort, body []byte, now time.Time) []byte {
	id, frag, piece := body[0], body[1], body[2:]
	idx, total := int(frag>>4), int(frag&0x0f)
	if total < 2 || idx >= total {
		return nil
	}
	k := fragKey{from, id}
	m := r.msgs[k]
	if m != nil && now.Sub(m.started) > fragTimeout {
		r.drop(m)
		m = nil
	}
	if m == nil {
		if r.perSrc[from] >= fragPerSource {
			r.dropOldestOf(from)
		}
		m = &fragMsg{key: k, total: total, pieces: make([][]byte, total), started: now}
		r.msgs[k] = m
		r.order = append(r.order, m)
		r.perSrc[from]++
	}
	if total != m.total || m.pieces[idx] != nil {
		return nil
	}
	if m.size+len(piece) > fragMaxSize {
		r.drop(m)
		return nil
	}
	m.pieces[idx] = append([]byte{}, piece...)
	m.have++
	m.size += len(piece)
	r.bytes += len(piece)
	for r.bytes > fragMaxBytes || len(r.msgs) > fragMaxMsgs {
		r.drop(r.order[0])
	}
	if m.have < m.total || r.msgs[k] != m {
		return nil
	}
	out := make([]byte, 0, m.size)
	for _, p := range m.pieces {
		out = append(out, p...)
	}
	r.drop(m)
	return out
}

func (r *reassembler) expire(now time.Time) {
	for len(r.order) > 0 && now.Sub(r.order[0].started) > fragTimeout {
		r.drop(r.order[0])
	}
}

func (r *reassembler) dropOldestOf(from netip.AddrPort) {
	for _, m := range r.order {
		if m.key.from == from {
			r.drop(m)
			return
		}
	}
}

func (r *reassembler) drop(m *fragMsg) {
	if r.msgs[m.key] != m {
		return
	}
	delete(r.msgs, m.key)
	r.bytes -= m.size
	if r.perSrc[m.key.from]--; r.perSrc[m.key.from] <= 0 {
		delete(r.perSrc, m.key.from)
	}
	for i, x := range r.order {
		if x == m {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
}
