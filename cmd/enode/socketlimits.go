package main

import (
	"fmt"

	"enode/logging"
)

// socketLimitFloor is the session count the open-file check plans for when
// tcp.maxConnections is higher or unlimited: the 10k+ sockets of
// docs/memory-footprint.local.md §2.5, with room to spare. A higher floor would warn
// on every macOS machine, whose per-process limit is 24,576.
const socketLimitFloor = 16384

// socketFDReserve is what the server needs besides sessions: listeners, UDP sockets,
// log and database files, and one dial-back per login in flight.
const socketFDReserve = 256

// minListenBacklog is the somaxconn below which a reconnect burst after a restart
// overflows the accept queue. Linux defaults to 4096 since 5.4, to 128 before.
const minListenBacklog = 4096

// logSocketLimits reports at startup the OS limits that cap how many sockets the
// server can hold. Go has already raised the open-file soft limit to the hard limit
// by the time main runs, so what is logged is what the process gets.
func logSocketLimits(maxConnections int) {
	fdLimit, somaxconn := openFileLimit(), listenBacklogLimit()
	if fdLimit > 0 {
		logging.Infof("socket limits: open files %d, listen backlog %d (0 = not known here)", fdLimit, somaxconn)
	}
	for _, w := range socketLimitWarnings(maxConnections, fdLimit, somaxconn) {
		logging.Warnf("%s", w)
	}
}

// socketLimitWarnings returns a line for each limit set below what maxConnections
// sessions need. A limit of 0 is one the platform does not report and is skipped.
func socketLimitWarnings(maxConnections int, fdLimit uint64, somaxconn int) []string {
	var out []string
	sessions := socketLimitFloor
	if maxConnections > 0 && maxConnections < sessions {
		sessions = maxConnections
	}
	if need := uint64(sessions + socketFDReserve); fdLimit > 0 && fdLimit < need {
		out = append(out, fmt.Sprintf("open file limit is %d, below the %d that %d sessions need: "+
			"new connections fail with EMFILE past it. Raise LimitNOFILE in the systemd unit, or ulimit -n",
			fdLimit, need, sessions))
	}
	if somaxconn > 0 && somaxconn < minListenBacklog {
		out = append(out, fmt.Sprintf("net.core.somaxconn is %d, below %d: clients reconnecting after a "+
			"restart overflow the accept queue and retry for seconds. Raise it with sysctl",
			somaxconn, minListenBacklog))
	}
	return out
}
