package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// writePIDFile records this process's id at path, atomically, so a reader never
// sees a half-written number. update.sh reads it to find the server to hand over.
func writePIDFile(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op once renamed
	if _, err := fmt.Fprintf(tmp, "%d\n", os.Getpid()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// removePIDFile removes the file at path if it still names this process. After a
// handover it names the successor, which must keep it.
func removePIDFile(path string) {
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if pid, err := strconv.Atoi(string(bytes.TrimSpace(raw))); err == nil && pid == os.Getpid() {
		_ = os.Remove(path)
	}
}

// sdNotify sends a state line to systemd when the server runs as a notify service
// (NOTIFY_SOCKET set); otherwise it does nothing. A handover's successor reports
// MAINPID with it, which keeps systemd from taking the predecessor's exit for the
// service's. See docs/server-handoff.md.
func sdNotify(state string) {
	name := os.Getenv("NOTIFY_SOCKET")
	if name == "" {
		return
	}
	if strings.HasPrefix(name, "@") {
		name = "\x00" + name[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(state))
}
