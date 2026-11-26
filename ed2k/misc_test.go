package ed2k

import "testing"

func TestExtAndType(t *testing.T) {
	if Ext("Movie.MKV") != "mkv" {
		t.Fatalf("ext mismatch")
	}
	if GetFileType("Movie.MKV") != "Video" {
		t.Fatalf("type mismatch")
	}
	if GetFileType("song.mp3") != "Audio" {
		t.Fatalf("type mismatch")
	}
	if GetFileType("a.unknown") != "" {
		t.Fatalf("unexpected type")
	}
}

func TestHex(t *testing.T) {
	if Hex(10, 4) != "000a" {
		t.Fatalf("hex mismatch: %s", Hex(10, 4))
	}
}

func TestIPv4ToInt32LE(t *testing.T) {
	v, err := IPv4ToInt32LE("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if v != 0x04030201 {
		t.Fatalf("value mismatch: 0x%x", v)
	}
}

// TestIPv4ToInt32LEForms pins what the parser accepts, and that a valid address
// parses without allocating (it runs for every OP_SERVERIDENT).
func TestIPv4ToInt32LEForms(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
		ok   bool
	}{
		{"255.0.10.1", 0x010a00ff, true},
		{"010.001.0.7", 0x0700010a, true},
		{"0.0.0.0", 0, true},
		{"1.2.3", 0, false},
		{"1.2.3.4.", 0, false},
		{"1.2.3.4.5", 0, false},
		{"1..3.4", 0, false},
		{"256.1.1.1", 0, false},
		{"-1.1.1.1", 0, false},
		{"::1", 0, false},
		{"", 0, false},
	}
	for _, tc := range cases {
		got, err := IPv4ToInt32LE(tc.in)
		t.Logf("input: %q, output: 0x%08x err=%v", tc.in, got, err)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("IPv4ToInt32LE(%q) = 0x%08x, %v; want 0x%08x ok=%t", tc.in, got, err, tc.want, tc.ok)
		}
	}
	allocs := testing.AllocsPerRun(100, func() { _, _ = IPv4ToInt32LE("198.51.100.7") })
	t.Logf("input: \"198.51.100.7\", output: %.0f allocations", allocs)
	if allocs != 0 {
		t.Fatalf("IPv4ToInt32LE allocated %.0f times", allocs)
	}
}

func TestIsProtocolAndBox(t *testing.T) {
	if !IsProtocol(PrED2K) || IsProtocol(0xff) {
		t.Fatalf("protocol mismatch")
	}
	if Box("x") != "+---+\n| x |\n+---+" {
		t.Fatalf("box mismatch: %q", Box("x"))
	}
}
