package main

import (
	"context"
	"encoding/binary"
	"net"
	"time"

	"enode/ed3k"
	"enode/storage"
)

// ed3kBridgeEngine adds bridged ed3k nodes to the sources the engine answers
// (spec docs/ed2k-tags.md §6). The node is paired with the eD2K session of its
// CT_ED3K login only when that session comes from the node's own address; the
// user hash and crypt options of the source come from it, else none are sent.
type ed3kBridgeEngine struct {
	storage.Engine
	node    *ed3k.Node
	max     int
	pairing func([16]byte) ([16]byte, byte, net.IP, bool)
}

// Unwrap returns the engine underneath, for storage.UnwrapEngine.
func (e *ed3kBridgeEngine) Unwrap() storage.Engine { return e.Engine }

// GetSources adds the bridged nodes of the file to the engine's sources.
func (e *ed3kBridgeEngine) GetSources(hash []byte, size uint64) []storage.Source {
	return e.add(hash, e.Engine.GetSources(hash, size))
}

// GetSourcesByHash adds the bridged nodes of the file to the engine's sources.
func (e *ed3kBridgeEngine) GetSourcesByHash(hash []byte) []storage.Source {
	return e.add(hash, e.Engine.GetSourcesByHash(hash))
}

func (e *ed3kBridgeEngine) add(hash []byte, srcs []storage.Source) []storage.Source {
	if len(hash) != 16 {
		return srcs
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	bridged := e.node.BridgeSources(ctx, [16]byte(hash), e.max)
	if len(bridged) == 0 {
		return srcs
	}
	have := make(map[[6]byte]bool, len(srcs))
	for _, s := range srcs {
		have[sourceKey(s.ID, s.Port)] = true
	}
	for _, b := range bridged {
		ip := b.EP4.Addr().As4()
		id := binary.LittleEndian.Uint32(ip[:])
		if have[sourceKey(id, b.EP4.Port())] {
			continue
		}
		s := storage.Source{ID: id, Port: b.EP4.Port()}
		if e.pairing != nil {
			if userHash, crypt, sessIP, ok := e.pairing(b.NodeID); ok && sessIP != nil && sessIP.Equal(net.IP(ip[:])) {
				s.UserHash, s.CryptOptions = userHash[:], crypt
			}
		}
		srcs = append(srcs, s)
	}
	return srcs
}

func sourceKey(id uint32, port uint16) [6]byte {
	var k [6]byte
	binary.LittleEndian.PutUint32(k[:4], id)
	binary.LittleEndian.PutUint16(k[4:], port)
	return k
}
