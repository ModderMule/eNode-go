package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestFilterDaemonArgs(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "no daemon args",
			in:   []string{"-config", "enode.config.yaml"},
			want: []string{"-config", "enode.config.yaml"},
		},
		{
			name: "remove daemon flags",
			in:   []string{"-daemon", "-config", "enode.config.yaml", "--daemon=true"},
			want: []string{"-config", "enode.config.yaml"},
		},
		{
			name: "remove daemon false variants",
			in:   []string{"--daemon=false", "-daemon=false", "-config", "x.yaml"},
			want: []string{"-config", "x.yaml"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterDaemonArgs(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("filterDaemonArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveDynIPValue_Auto(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("8.8.4.4\n"))
	}))
	defer server.Close()

	value, source, err := resolveDynIPValue("auto", []string{server.URL}, time.Second)
	if err != nil {
		t.Fatalf("resolveDynIPValue() error = %v", err)
	}
	if value != "8.8.4.4" {
		t.Fatalf("resolveDynIPValue() value = %q, want %q", value, "8.8.4.4")
	}
	if source != server.URL {
		t.Fatalf("resolveDynIPValue() source = %q, want %q", source, server.URL)
	}
}

func TestResolveDynIPValue_AutoFallback(t *testing.T) {
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1.1.1.1"))
	}))
	defer goodServer.Close()

	value, source, err := resolveDynIPValue("auto", []string{"https://127.0.0.1:1", goodServer.URL}, time.Second)
	if err != nil {
		t.Fatalf("resolveDynIPValue() error = %v", err)
	}
	if value != "1.1.1.1" {
		t.Fatalf("resolveDynIPValue() value = %q, want %q", value, "1.1.1.1")
	}
	if source != goodServer.URL {
		t.Fatalf("resolveDynIPValue() source = %q, want %q", source, goodServer.URL)
	}
}

func TestResolveDynIPValue_Passthrough(t *testing.T) {
	value, source, err := resolveDynIPValue(" 203.0.113.10 ", nil, time.Second)
	if err != nil {
		t.Fatalf("resolveDynIPValue() error = %v", err)
	}
	if value != "203.0.113.10" {
		t.Fatalf("resolveDynIPValue() value = %q, want %q", value, "203.0.113.10")
	}
	if source != "" {
		t.Fatalf("resolveDynIPValue() source = %q, want empty", source)
	}
}

func TestEd2kServerLinks(t *testing.T) {
	v6 := net.ParseIP("2001:db8::1").To16()
	tests := []struct {
		name string
		ip   string
		v6   []byte
		port uint16
		want []string
	}{
		{name: "ipv4 only", ip: "203.0.113.5", port: 4661, want: []string{"ed2k://|server|203.0.113.5|4661|/"}},
		{name: "dual stack", ip: "203.0.113.5", v6: v6, port: 4242, want: []string{
			"ed2k://|server|203.0.113.5|4242|/",
			"ed2k://|server|[2001:db8::1]|4242|/",
		}},
		{name: "ipv6 only", ip: "", v6: v6, port: 4661, want: []string{"ed2k://|server|[2001:db8::1]|4661|/"}},
		{name: "unspecified", ip: "0.0.0.0", port: 4661, want: nil},
		{name: "hostname ignored", ip: "example.org", port: 4661, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ed2kServerLinks(tt.ip, tt.v6, tt.port)
			t.Logf("input ip=%q v6=%v port=%d -> %v", tt.ip, tt.v6, tt.port, got)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
