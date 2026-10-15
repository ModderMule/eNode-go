// Package handoff moves a running server to a new process without dropping a
// client: the listening sockets, every live TCP session and the storage state that
// belongs to those sessions are passed to a successor, which carries on serving
// them. See docs/server-handoff.md.
//
// This file is the part every platform builds: the registry of listening sockets.
// Everything that binds a client-facing socket goes through Listen or ListenUDP,
// so the registry knows what to pass on, and so a successor started by a handover
// gets its predecessor's sockets back instead of failing to bind a port the
// predecessor still holds.
package handoff

import (
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
)

// fileSocket is a socket that can hand out a duplicate of its descriptor:
// *net.TCPListener, *net.UDPConn and *net.UnixListener all do.
type fileSocket interface {
	File() (*os.File, error)
}

// registry tracks the sockets this process listens on, and holds the ones a
// predecessor passed in until the code that binds them asks for them.
type registry struct {
	mu sync.Mutex
	// live is every socket bound or adopted through Listen/ListenUDP, by key. A
	// closed one stays until the next files() call notices File() failing.
	live map[string]fileSocket
	// inherited are the predecessor's sockets nobody has claimed yet.
	inherited map[string]*os.File
}

var sockets = &registry{
	live:      map[string]fileSocket{},
	inherited: map[string]*os.File{},
}

// Listen is net.Listen, except that a socket a predecessor passed in under the same
// network and address is adopted instead of bound again.
func Listen(network, address string) (net.Listener, error) {
	k := socketKey(network, address)
	if f := sockets.take(k); f != nil {
		ln, err := net.FileListener(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("adopt inherited listener %s: %w", k, err)
		}
		sockets.add(k, ln)
		return ln, nil
	}
	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	sockets.add(k, ln)
	return ln, nil
}

// ListenUDP binds a UDP socket like net.ListenUDP, or adopts the one a predecessor
// passed in under the same network and address. address is the host:port string the
// caller would resolve, so both processes key it the same way.
func ListenUDP(network, address string) (*net.UDPConn, error) {
	k := socketKey(network, address)
	if f := sockets.take(k); f != nil {
		pc, err := net.FilePacketConn(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("adopt inherited socket %s: %w", k, err)
		}
		conn, ok := pc.(*net.UDPConn)
		if !ok {
			_ = pc.Close()
			return nil, fmt.Errorf("adopt inherited socket %s: not a UDP socket", k)
		}
		sockets.add(k, conn)
		return conn, nil
	}
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP(network, addr)
	if err != nil {
		return nil, err
	}
	sockets.add(k, conn)
	return conn, nil
}

// CloseUnclaimed closes every inherited socket nothing bound. The successor calls it
// once it serves: a socket the predecessor had and this configuration does not
// use — a port changed in the config, a feature turned off — would otherwise stay
// bound, unserved, for the life of the process.
func CloseUnclaimed() []string {
	sockets.mu.Lock()
	defer sockets.mu.Unlock()
	keys := make([]string, 0, len(sockets.inherited))
	for k, f := range sockets.inherited {
		_ = f.Close()
		keys = append(keys, k)
	}
	clear(sockets.inherited)
	sort.Strings(keys)
	return keys
}

func (r *registry) add(key string, s any) {
	fs, ok := s.(fileSocket)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.live[key] = fs
}

func (r *registry) take(key string) *os.File {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.inherited[key]
	delete(r.inherited, key)
	return f
}

func (r *registry) inherit(key string, f *os.File) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inherited[key] = f
}

// files duplicates every live socket for a successor, in key order. A socket that
// has been closed since it was registered fails File() and is dropped.
func (r *registry) files() (keys []string, files []*os.File) {
	r.mu.Lock()
	defer r.mu.Unlock()
	all := make([]string, 0, len(r.live))
	for k := range r.live {
		all = append(all, k)
	}
	sort.Strings(all)
	for _, k := range all {
		f, err := r.live[k].File()
		if err != nil {
			delete(r.live, k)
			continue
		}
		keys = append(keys, k)
		files = append(files, f)
	}
	return keys, files
}

// liveSockets returns the registered sockets, for restoring their blocking mode
// after a spawn; see restoreNonblock.
func (r *registry) liveSockets() []fileSocket {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]fileSocket, 0, len(r.live))
	for _, s := range r.live {
		out = append(out, s)
	}
	return out
}

// socketKey names a socket by what its owner asked to bind, which both processes
// derive from the same config. The network is part of it: "tcp4" and "tcp" on one
// port are different sockets.
func socketKey(network, address string) string {
	return network + " " + address
}
