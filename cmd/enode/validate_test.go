package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateConfigFile(t *testing.T) {
	cases := []struct {
		name     string
		yaml     string
		wantErr  bool
		contains []string
	}{
		{
			name: "minimal dual-stack config is clean",
			yaml: "address: \"\"\ndynIp: auto\n",
		},
		{
			name:     "unknown key is an error",
			yaml:     "adress: \"\"\n",
			wantErr:  true,
			contains: []string{"field adress not found"},
		},
		{
			name:     "IPv6 in dynIp is an error",
			yaml:     "dynIp: \"2001:db8::1\"\n",
			wantErr:  true,
			contains: []string{"dynIp \"2001:db8::1\" must be"},
		},
		{
			name:     "non-public dynIp6 is an error",
			yaml:     "ipv6:\n  dynIp6: \"fe80::1\"\n",
			wantErr:  true,
			contains: []string{"ipv6.dynIp6 \"fe80::1\" is not a public IPv6"},
		},
		{
			name:     "IPv4 bind with IPv6 on warns",
			yaml:     "address: \"203.0.113.5\"\nipv6:\n  dynIp6: \"2a00:1450::1\"\n  address: \"2a00:1450::1\"\n",
			contains: []string{"bind IPv4 only", "nothing listens on IPv6", "ipv6.address \"2a00:1450::1\" is ignored"},
		},
		{
			name:     "two listeners on one port is an error",
			yaml:     "tcp:\n  port: 5555\n  portObfuscated: 5555\n",
			wantErr:  true,
			contains: []string{"tcp.port and tcp.portObfuscated both use tcp port 5555"},
		},
		{
			name:     "udp port off the tcp+4 offset warns",
			yaml:     "tcp:\n  port: 5555\nudp:\n  port: 5560\n",
			contains: []string{"udp.port is 5560, not tcp.port+4 (5559)"},
		},
		{
			name:     "bad server list entry is an error",
			yaml:     "servers:\n  - ip: \"not-an-ip\"\n    port: 4661\n",
			wantErr:  true,
			contains: []string{"servers entry \"not-an-ip\":4661"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err := runValidate(path, &out)
			t.Logf("input:\n%s", tc.yaml)
			t.Logf("output:\n%s", out.String())
			t.Logf("err: %v", err)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			for _, want := range tc.contains {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output lacks %q", want)
				}
			}
			if len(tc.contains) == 0 && strings.Contains(out.String(), "warning ") {
				t.Errorf("expected no findings")
			}
		})
	}
}

// The shipped config must always validate without findings.
func TestValidateShippedConfig(t *testing.T) {
	path := filepath.Join("..", "..", "enode.config.yaml")
	var out bytes.Buffer
	err := runValidate(path, &out)
	t.Logf("input: %s", path)
	t.Logf("output:\n%s", out.String())
	if err != nil {
		t.Fatalf("shipped config: %v", err)
	}
	if strings.Contains(out.String(), "warning ") {
		t.Errorf("shipped config has warnings")
	}
}
