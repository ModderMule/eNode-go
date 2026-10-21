package wire

import (
	"bytes"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"enode/ed3k/ed3kpb"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		msg  *ed3kpb.Hello
		z    bool
	}{
		{"small, plain", &ed3kpb.Hello{Caps: 4, Agent: "eNode"}, false},
		{"large, compressed", &ed3kpb.Hello{Caps: 4, Agent: "eNode", Nick: strings.Repeat("ab", 32), Observed: bytes.Repeat([]byte{7}, 200)}, true},
	}
	for _, c := range cases {
		b, err := AppendFrame(nil, TypeHello, c.msg)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: frame %d bytes, tag=%#x", c.name, len(b), b[0])
		if (b[0]&1 == 1) != c.z {
			t.Errorf("%s: z bit %v", c.name, b[0]&1)
		}
		f, err := ReadFrame(NewReader(bytes.NewReader(b)))
		if err != nil || f.Type != TypeHello {
			t.Fatalf("%s: read %v type %d", c.name, err, f.Type)
		}
	}
}

func TestHeaderErrors(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"11-byte varint", bytes.Repeat([]byte{0x80}, 11), ErrHeader},
		{"len above 1 MiB", []byte{0x02, 0x81, 0x80, 0x40}, ErrHeader},
		{"ends in header", []byte{0x02}, ErrHeader},
		{"ends in body", []byte{0x02, 0x05, 1, 2}, ErrShort},
		{"long varint accepted", []byte{0x82, 0x00, 0x00}, nil},
	}
	for _, c := range cases {
		_, err := ReadFrame(NewReader(bytes.NewReader(c.in)))
		t.Logf("%s: % x -> %v", c.name, c.in, err)
		if err != c.want {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
}

func TestCompressProfile(t *testing.T) {
	body := bytes.Repeat([]byte("ed3k index node "), 400)
	c, ok := Compress(body)
	if !ok {
		t.Fatal("did not compress")
	}
	var h zstd.Header
	if err := h.Decode(append(append([]byte{}, zstdMagic...), c...)); err != nil {
		t.Fatal(err)
	}
	t.Logf("in=%d out=%d fcs=%v checksum=%v window=%d dict=%d", len(body), len(c), h.HasFCS, h.HasCheckSum, h.WindowSize, h.DictionaryID)
	if h.HasFCS || h.HasCheckSum || h.SingleSegment || h.WindowSize > MaxBody || h.WindowSize < uint64(len(body)) {
		t.Fatal("frame breaks the §5.3 profile")
	}
	out, err := Decompress(c)
	if err != nil || !bytes.Equal(out, body) {
		t.Fatalf("round trip: %v", err)
	}
	if _, ok := Compress([]byte("short")); ok {
		t.Fatal("compressed a body under 64 bytes")
	}
}

func TestDecompressRejects(t *testing.T) {
	plain := bytes.Repeat([]byte("x"), 5000)
	std, _ := zstd.NewWriter(nil, zstd.WithEncoderCRC(true))
	withCRC := std.EncodeAll(plain, nil)[4:] // content size and checksum: accepted
	two := append(append([]byte{}, withCRC...), std.EncodeAll(plain, nil)...)
	big := std.EncodeAll(make([]byte, MaxBody+1), nil)[4:]
	dictEnc, _ := zstd.NewWriter(nil, zstd.WithEncoderDictRaw(1, bytes.Repeat([]byte("dict"), 64)))
	withDict := dictEnc.EncodeAll(plain, nil)[4:]
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"content size and checksum", withCRC, nil},
		{"two frames", two, ErrNotOneFrame},
		{"trailing byte", append(append([]byte{}, withCRC...), 0), ErrNotOneFrame},
		{"window above 1 MiB", big, ErrWindow},
		{"dictionary", withDict, ErrNeedDict},
		{"garbage", []byte{1, 2, 3}, ErrNotOneFrame},
	}
	for _, c := range cases {
		_, err := Decompress(c.in)
		t.Logf("%s: %d bytes -> %v", c.name, len(c.in), err)
		if err != c.want {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
}
