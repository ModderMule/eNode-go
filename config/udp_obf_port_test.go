package config

import "testing"

// The obfuscated UDP port must default to tcp.port+12 — the port eMule hardwires
// for the server-UDP crypt-ping and the only source port it accepts the reply from
// on first contact (srchybrid/ServerList.cpp:294, GetServerByIPUDP :563-576).
func TestUDPObfuscatedPortDefaultsToTCPPlus12(t *testing.T) {
	cases := []struct {
		name string
		body string
		want uint16
	}{
		{
			name: "omitted → tcp default(5555)+12",
			body: "name: t\naddress: \"127.0.0.1\"\n",
			want: 5567,
		},
		{
			name: "omitted follows a custom tcp port",
			body: "name: t\naddress: \"127.0.0.1\"\ntcp:\n  port: 4661\n",
			want: 4673, // 4661 + 12
		},
		{
			name: "explicit value wins",
			body: "name: t\naddress: \"127.0.0.1\"\nudp:\n  portObfuscated: 9999\n",
			want: 9999,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(writeTempConfig(t, tc.body))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("input: %q", tc.body)
			t.Logf("output: tcp.port=%d udp.portObfuscated=%d", cfg.TCP.Port, cfg.UDP.PortObfuscated)
			if cfg.UDP.PortObfuscated != tc.want {
				t.Fatalf("udp.portObfuscated=%d, want %d", cfg.UDP.PortObfuscated, tc.want)
			}
		})
	}
}

// tcp.port+12 is uint16 arithmetic: 65524 wrapped the derived port to 0 and 65530 to
// 6. Such a tcp.port is refused unless udp.portObfuscated is set explicitly. The gossip
// port at tcp.port+14 has the same guard, so it is set explicitly where the case is about
// the obfuscated port alone.
func TestUDPObfuscatedPortDoesNotWrap(t *testing.T) {
	for _, tc := range []struct {
		body    string
		wantErr bool
	}{
		{"name: t\naddress: \"127.0.0.1\"\ntcp:\n  port: 65523\nudp:\n  portGossip: 6002\n", false},
		{"name: t\naddress: \"127.0.0.1\"\ntcp:\n  port: 65524\nudp:\n  portGossip: 6002\n", true},
		{"name: t\naddress: \"127.0.0.1\"\ntcp:\n  port: 65530\nudp:\n  portObfuscated: 6000\n  portGossip: 6002\n", false},
	} {
		cfg, err := Load(writeTempConfig(t, tc.body))
		t.Logf("input: %q, output: udp.portObfuscated=%d err=%v", tc.body, cfg.UDP.PortObfuscated, err)
		if (err != nil) != tc.wantErr {
			t.Fatalf("err=%v, wantErr=%t", err, tc.wantErr)
		}
	}
}
