package ed2k

import (
	"bytes"
	"testing"

	"github.com/ModderMule/enodemeta/tags"
)

// TestServerIdentAdvertisesMetaAPI checks the enode.meta.v1 discovery tags
// (ST_META_API 0x9e, ST_META_API_VER 0x9f, ST_META_API_FP 0x9c) are appended to
// OP_SERVERIDENT when the Meta API is on, the fingerprint only when set, and that
// nothing changes when it is off.
func TestServerIdentAdvertisesMetaAPI(t *testing.T) {
	if TagMetaAPI != tags.STMetaAPI || TagMetaAPIVersion != tags.STMetaAPIVersion || TagMetaAPIFingerprint != tags.STMetaAPIFingerprint {
		t.Fatalf("Meta API tag ids differ from the contract: ours 0x%02x/0x%02x/0x%02x, contract 0x%02x/0x%02x/0x%02x",
			TagMetaAPI, TagMetaAPIVersion, TagMetaAPIFingerprint, tags.STMetaAPI, tags.STMetaAPIVersion, tags.STMetaAPIFingerprint)
	}
	base := ServerConfig{
		Name: "eNode", Description: "test", Address: "192.0.2.1",
		Hash: bytes.Repeat([]byte{0x01}, 16), TCPPort: 5555,
	}
	off, err := BuildServerIdentPacket(base)
	if err != nil {
		t.Fatal(err)
	}

	conf := base
	conf.MetaAPI = MetaAPIAdvert{URL: "https://enode.example.org:4671", Version: 1, Fingerprint: "sha256/AAAA"}
	buf, err := BuildServerIdentPacket(conf)
	if err != nil {
		t.Fatal(err)
	}
	got := parseServerIdentTags(t, buf)
	t.Logf("input: MetaAPI=%+v output: metaapi=%v metaapiver=%v metaapifp=%v", conf.MetaAPI, got["metaapi"], got["metaapiver"], got["metaapifp"])
	if got["metaapi"] != conf.MetaAPI.URL {
		t.Errorf("metaapi = %v, want %s", got["metaapi"], conf.MetaAPI.URL)
	}
	// The decoder widens every integer tag to uint64.
	if v, ok := got["metaapiver"].(uint64); !ok || v != 1 {
		t.Errorf("metaapiver = %v (%T), want 1", got["metaapiver"], got["metaapiver"])
	}
	if got["metaapifp"] != "sha256/AAAA" {
		t.Errorf("metaapifp = %v, want sha256/AAAA", got["metaapifp"])
	}

	conf.MetaAPI.Fingerprint = ""
	buf, err = BuildServerIdentPacket(conf)
	if err != nil {
		t.Fatal(err)
	}
	got = parseServerIdentTags(t, buf)
	if _, ok := got["metaapifp"]; ok {
		t.Errorf("metaapifp present without a fingerprint")
	}
	if _, ok := got["metaapi"]; !ok {
		t.Errorf("metaapi missing without a fingerprint")
	}

	again, err := BuildServerIdentPacket(base)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(off.Bytes(), again.Bytes()) {
		t.Fatalf("OP_SERVERIDENT differs between two builds with the API off")
	}
	for _, name := range []string{"metaapi", "metaapiver", "metaapifp"} {
		if _, ok := parseServerIdentTags(t, off)[name]; ok {
			t.Errorf("%s present with the Meta API off", name)
		}
	}
	t.Logf("input: MetaAPI off output: %d-byte packet without meta api tags", len(off.Bytes()))
}
