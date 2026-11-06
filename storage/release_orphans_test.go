package storage

import (
	"bytes"
	"testing"
)

func TestMemoryReleaseOrphans(t *testing.T) {
	m := NewMemoryEngine()
	keep := bytes.Repeat([]byte{0x11}, 16)
	gone := bytes.Repeat([]byte{0x22}, 16)
	for i, h := range [][]byte{keep, gone} {
		c := ClientInfo{Hash: h, ID: uint32(0x01000000 + i), Port: 4662}
		id, err := m.Connect(c)
		if err != nil {
			t.Fatal(err)
		}
		c.StoreID = id
		m.AddFile(File{Hash: bytes.Repeat([]byte{byte(0x30 + i)}, 16), Size: 100, Name: "f.bin"}, c)
	}

	released, err := m.ReleaseOrphans(func(h []byte) bool { return bytes.Equal(h, keep) })
	if err != nil {
		t.Fatal(err)
	}
	if len(released) != 1 || !bytes.Equal(released[0], gone) {
		t.Fatalf("released=%x want [%x]", released, gone)
	}
	if !m.IsConnected(ClientInfo{Hash: keep}) || m.IsConnected(ClientInfo{Hash: gone}) {
		t.Fatal("wrong client released")
	}
	if n := len(m.GetSourcesByHash(bytes.Repeat([]byte{0x31}, 16))); n != 0 {
		t.Fatalf("released client still sources its file (%d)", n)
	}
}

func TestMemoryDisconnectByHash(t *testing.T) {
	m := NewMemoryEngine()
	h := bytes.Repeat([]byte{0x33}, 16)
	if _, err := m.Connect(ClientInfo{Hash: h, ID: 0x01000000, Port: 4662}); err != nil {
		t.Fatal(err)
	}
	m.Disconnect(ClientInfo{Hash: h})
	if m.IsConnected(ClientInfo{Hash: h}) {
		t.Fatal("disconnect by hash left the client online")
	}
}
