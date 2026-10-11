package contentfilter

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func testHash(b byte) []byte { return bytes.Repeat([]byte{b}, HashSize) }

func testHashLine(b byte) string { return hex.EncodeToString(testHash(b)) }

// TestParseHashListLineForms covers every line form the update service's files carry,
// and the malformed ones that must be skipped rather than fail the list.
func TestParseHashListLineForms(t *testing.T) {
	input := strings.Join([]string{
		"# Layer 3 ban list",
		"",
		testHashLine(0x01),
		"  " + strings.ToUpper(testHashLine(0x02)) + "  ",
		testHashLine(0x03) + " ; 700 MB, 12 names, \"Some File.avi\"",
		testHashLine(0x04) + ";\xff\xfe not UTF-8 \x80",
		"; a comment-only line",
		testHashLine(0x01),            // duplicate
		"0123456789abcdef",            // too short
		testHashLine(0x05) + "00",     // too long
		"zz" + testHashLine(0x06)[2:], // not hex
	}, "\n")
	list, err := ParseHashList(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: %d lines output: len=%d parsed=%d skipped=%d", strings.Count(input, "\n")+1, list.Len(), list.Parsed, list.Skipped)

	if list.Len() != 4 || list.Parsed != 5 || list.Skipped != 3 {
		t.Fatalf("len=%d parsed=%d skipped=%d, want 4/5/3", list.Len(), list.Parsed, list.Skipped)
	}
	for b := byte(1); b <= 4; b++ {
		if !list.Contains(testHash(b)) {
			t.Errorf("hash %02x.. missing", b)
		}
	}
	for _, b := range []byte{5, 6} {
		if list.Contains(testHash(b)) {
			t.Errorf("hash %02x.. came from a malformed line and must not be listed", b)
		}
	}
}

func TestHashListContainsRejectsOddInput(t *testing.T) {
	list, err := ParseHashList(strings.NewReader(testHashLine(0x01)))
	if err != nil {
		t.Fatal(err)
	}
	var none *HashList
	t.Logf("input: short hash, nil hash, nil list output: %t %t %t len=%d",
		list.Contains([]byte{1, 2, 3}), list.Contains(nil), none.Contains(testHash(1)), none.Len())
	if list.Contains([]byte{1, 2, 3}) || list.Contains(nil) {
		t.Fatal("only a 16-byte hash can be listed")
	}
	if none.Contains(testHash(1)) || none.Len() != 0 {
		t.Fatal("a nil list holds nothing")
	}
}

func TestLoadHashListMissingFileIsAnError(t *testing.T) {
	_, err := LoadHashList(t.TempDir() + "/absent.txt")
	t.Logf("input: absent file output: err=%v", err)
	if err == nil {
		t.Fatal("a missing list must be an error, not an empty list")
	}
}
