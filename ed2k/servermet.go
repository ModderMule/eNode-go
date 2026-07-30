package ed2k

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// server.met persistence for the gossip peer table.
//
// This writes the real eMule/eserver format rather than an internal one, for two
// reasons that both cost nothing: an operator can point an eMule at the file to see
// what the server actually learned, and eserver's own autoservlist output can be fed
// in as a seed list. The format (srchybrid/ServerList.cpp:142-160 reader,
// :597-640 writer) is:
//
//	uint8   version      0xE0 (or MET_HEADER 0x0E)
//	uint32  count
//	count × {
//	    uint32  ip        eD2K packed order; 0 for a dynIP server
//	    uint16  port
//	    uint32  tagcount
//	    tagcount × tag    old-format tags: type(1) namelen(2)=1 code(1) value
//	}
//
// Buffer.PutTags/GetTags already emit and consume exactly that per-entry tag block —
// a uint32 count followed by 1-byte-named tags — so no separate .met tag codec is
// needed here.

// serverMetVersion is the header byte eMule writes. It also accepts 0x0E
// (MET_HEADER); we always write 0xE0 and accept both on read.
const serverMetVersion uint8 = 0xE0

// serverMetVersionAlt is MET_HEADER, the other value eMule's reader tolerates.
const serverMetVersionAlt uint8 = 0x0E

// maxServerMetEntries bounds what a single file may declare, so a corrupt or hostile
// count field cannot drive an allocation. Far above eserver's 4096 maxservers, since
// the point is to reject absurdity rather than to enforce policy — the caller's
// maxServers does that.
const maxServerMetEntries = 65536

// ServerMetEntry is one persisted peer.
//
// Name and Description are carried because eserver records them per peer — its
// console shows them and its ipfilter.srv screens on them — and because a file with
// names in it is far easier to read back by hand. Nothing else is persisted: user and
// file counts, ports and ServerKeys are all re-learned on the next gossip round
// (within gossip.intervalSeconds), so writing them would only create a way for the
// file to disagree with reality after a restart.
type ServerMetEntry struct {
	IP          net.IP
	Port        uint16
	Name        string
	Description string
}

// WriteServerMet writes entries to path in eMule server.met format.
//
// The file is written to a temporary name in the same directory and renamed into
// place. The peer table is rewritten wholesale on a timer, so a crash mid-write would
// otherwise leave a truncated file that the next startup reads as a short (or
// unparseable) peer list — losing the mesh this file exists to preserve. A rename is
// atomic, so the file on disk is always a complete generation.
//
// A non-IPv4 entry is skipped: the format's address field is four bytes wide, and
// eMule's own writer stores 0 for a server whose address it does not want to pin. Our
// IPv6 peers are still persisted, but as an eNode-go sidecar — see
// WriteServerMetIPv6.
func WriteServerMet(path string, entries []ServerMetEntry) error {
	if path == "" {
		return fmt.Errorf("server.met path is empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	v4 := make([]ServerMetEntry, 0, len(entries))
	for _, e := range entries {
		if e.IP.To4() != nil {
			v4 = append(v4, e)
		}
	}

	buf := NewBuffer(serverMetSize(v4))
	if err := buf.PutUInt8(serverMetVersion); err != nil {
		return err
	}
	if err := buf.PutUInt32LE(uint32(len(v4))); err != nil {
		return err
	}
	for _, e := range v4 {
		if err := buf.PutUInt32LE(uint32FromV4(e.IP.To4())); err != nil {
			return err
		}
		if err := buf.PutUInt16LE(e.Port); err != nil {
			return err
		}
		if err := buf.PutTags(serverMetTags(e)); err != nil {
			return err
		}
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp server.met: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed

	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write server.met: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close server.met: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install server.met: %w", err)
	}
	return nil
}

// ReadServerMet parses an eMule server.met. A missing file is reported as
// (nil, nil): "no peer file yet" is the normal first-boot state, not an error, and the
// caller falls back to its configured seeds.
//
// An entry whose IP field is 0 is skipped rather than kept. eMule writes 0 for a
// dynIP server deliberately ("don't write potentially outdated IPs of dynIP-servers",
// ServerList.cpp:605), and we have no hostname field to resolve it from, so such an
// entry carries no address we could contact.
func ReadServerMet(path string) ([]ServerMetEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	b := NewBufferFromBytes(raw)

	version, err := b.GetUInt8()
	if err != nil {
		return nil, fmt.Errorf("%s: empty file", path)
	}
	if version != serverMetVersion && version != serverMetVersionAlt {
		return nil, fmt.Errorf("%s: bad version byte 0x%02x, want 0x%02x or 0x%02x",
			path, version, serverMetVersion, serverMetVersionAlt)
	}
	count, err := b.GetUInt32LE()
	if err != nil {
		return nil, fmt.Errorf("%s: truncated before the entry count", path)
	}
	if count > maxServerMetEntries {
		return nil, fmt.Errorf("%s: declares %d entries, refusing above %d", path, count, maxServerMetEntries)
	}
	// Each entry is at least 10 bytes (ip 4 + port 2 + tagcount 4), so a count that
	// cannot possibly fit is a corrupt file. Checked before allocating, not after.
	if int(count)*10 > b.Remaining() {
		return nil, fmt.Errorf("%s: declares %d entries but only %d bytes remain", path, count, b.Remaining())
	}

	out := make([]ServerMetEntry, 0, count)
	for i := range count {
		packedIP, err := b.GetUInt32LE()
		if err != nil {
			return nil, fmt.Errorf("%s: truncated at entry %d", path, i)
		}
		port, err := b.GetUInt16LE()
		if err != nil {
			return nil, fmt.Errorf("%s: truncated at entry %d port", path, i)
		}
		tags, err := b.GetTags()
		if err != nil {
			return nil, fmt.Errorf("%s: entry %d tags: %w", path, i, err)
		}
		if packedIP == 0 {
			// dynIP placeholder, no usable address. Tags were consumed above so the
			// stream stays aligned for the following entries.
			continue
		}
		entry := ServerMetEntry{IP: v4FromUint32(packedIP), Port: port}
		for _, t := range tags {
			switch t.Name {
			case "name":
				if s, ok := t.Value.(string); ok {
					entry.Name = s
				}
			case "description":
				if s, ok := t.Value.(string); ok {
					entry.Description = s
				}
			}
		}
		out = append(out, entry)
	}
	return out, nil
}

// v4FromUint32 unpacks the eD2K address convention (first octet in the low byte) back
// into a 4-byte net.IP. The inverse of uint32FromV4.
func v4FromUint32(v uint32) net.IP {
	return net.IP{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

// serverMetTags builds the per-entry tag block. Only non-empty values are written, as
// eMule's writer does, so an entry we know nothing about beyond its address costs the
// 4-byte zero tag count and nothing more.
func serverMetTags(e ServerMetEntry) []Tag {
	tags := make([]Tag, 0, 4)
	if e.Name != "" {
		tags = append(tags, Tag{Type: TypeString, Code: TagName, Data: e.Name})
	}
	if e.Description != "" {
		tags = append(tags, Tag{Type: TypeString, Code: TagDescription, Data: e.Description})
	}
	return tags
}

// serverMetSize computes the exact buffer size, so NewBuffer allocates once. Buffer is
// fixed-length (PutUInt* fail past the end rather than growing), so this must be
// right, not merely close.
func serverMetSize(entries []ServerMetEntry) int {
	size := 1 + 4 // version + count
	for _, e := range entries {
		size += 4 + 2 + 4 // ip + port + tagcount
		for _, t := range serverMetTags(e) {
			// type(1) + namelen(2) + code(1), then the value.
			size += 4
			switch t.Type {
			case TypeString:
				s, _ := t.Data.(string)
				size += 2 + len(s) // length prefix + bytes
			case TypeUint32:
				size += 4
			}
		}
	}
	return size
}
