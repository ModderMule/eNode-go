package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"

	"enode/config"
	"enode/ed2k"
	"enode/logging"
	"enode/storage"
)

// handoffDeps is what a handover needs from run(), on either side of it.
type handoffDeps struct {
	runtime *ed2k.ServerRuntime
	engine  storage.Engine
	// tcpGate holds every ed2k TCP accept loop, udpGate every UDP read loop.
	tcpGate *ed2k.Gate
	udpGate *ed2k.Gate
	// cancel ends run() once this process has handed over, and handedOff tells
	// its defers why: nothing is to be released or flushed that the successor now
	// owns.
	cancel    context.CancelFunc
	handedOff *atomic.Bool
	pidFile   string
	// configPath is read again on SIGUSR2 for handoff.memory, so the mode can be
	// changed for one handover without a restart; boot is the fallback if the file
	// no longer loads.
	configPath string
	boot       config.Config
}

// errHandoffOff refuses a handover that handoff.memory turned off.
var errHandoffOff = errors.New(`handoff.memory is "off" and the memory engine is in use: restart enode to run a new binary`)

// handoffPlan is how a handover moves the memory engine's index: through a file
// at file, or over the handover socket when file is empty.
type handoffPlan struct {
	file string
}

// planHandoff decides from the config as it now is whether a handover may run and
// how the index moves. Only the memory engine is affected: a database engine moves
// almost nothing.
func planHandoff(d handoffDeps) (handoffPlan, error) {
	cfg, err := config.Load(d.configPath)
	if err != nil {
		logging.Warnf("handoff: %s does not load, using handoff settings from boot: %v", d.configPath, err)
		cfg = d.boot
	}
	if _, memory := d.engine.(*storage.MemoryEngine); !memory {
		return handoffPlan{}, nil
	}
	switch cfg.Handoff.Memory {
	case config.HandoffMemoryOff:
		return handoffPlan{}, errHandoffOff
	case config.HandoffMemoryFile:
		return handoffPlan{file: cfg.HandoffFilePath()}, nil
	}
	return handoffPlan{}, nil
}

// handoffStatusPath is where a handover that did not happen leaves its reason, for
// update.sh to report instead of waiting out its timeout.
func handoffStatusPath(pidFile string) string { return pidFile + ".handoff" }

// writeHandoffStatus records why the handover asked for did not happen.
func writeHandoffStatus(pidFile string, cause error) {
	if pidFile == "" {
		return
	}
	if err := os.WriteFile(handoffStatusPath(pidFile), []byte(cause.Error()+"\n"), 0o644); err != nil {
		logging.Warnf("handoff: status file not written: %v", err)
	}
}

// bootExecutable is the path this process was started from, resolved at startup.
// An update replaces the file there, so it is what a handover starts. Resolved
// early because on Linux the running image's path reads "... (deleted)" once the
// file has been replaced.
var bootExecutable = func() string {
	exe, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return strings.TrimSuffix(exe, " (deleted)")
}()

// successorArgs are this process's arguments as the successor gets them: without
// -daemon, since it is started detached already, and without -reindex-manticore,
// which would drop and rebuild the index on every handover.
func successorArgs(args []string) []string {
	args = filterDaemonArgs(args)
	out := make([]string, 0, len(args))
	for _, arg := range args {
		switch strings.TrimLeft(arg, "-") {
		case "reindex-manticore", "reindex-manticore=true", "reindex-manticore=false":
			continue
		}
		out = append(out, arg)
	}
	return out
}
