//go:build unix

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"enode/ed2k"
	"enode/internal/handoff"
	"enode/logging"
	"enode/storage"
)

// parkTimeout bounds how long a handover waits for busy sessions to reach their
// next read. A login waiting on its dial-back probes is the slowest common case.
const parkTimeout = 15 * time.Second

// sessionExporter adapts the runtime and the storage engine to handoff.Exporter.
type sessionExporter struct {
	d        handoffDeps
	plan     handoffPlan
	parked   *ed2k.ParkedSessions
	quiesced time.Time
	sessions int
	// filed is set once the memory engine's index is in plan.file and no longer in
	// the engine.
	filed bool
}

func (e *sessionExporter) Quiesce() error {
	e.quiesced = time.Now()
	e.d.tcpGate.Close()
	e.parked = e.d.runtime.ParkSessions(parkTimeout)
	if e.parked.Stragglers > 0 {
		logging.Warnf("handoff: %d session(s) did not park within %s and were dropped", e.parked.Stragglers, parkTimeout)
	}
	return nil
}

func (e *sessionExporter) Sessions() ([][]byte, []*os.File, error) {
	states, files, err := e.parked.Export()
	if err != nil {
		return nil, nil, err
	}
	out := make([][]byte, 0, len(states))
	for _, st := range states {
		raw, err := ed2k.EncodeSessionState(st)
		if err != nil {
			for _, f := range files {
				_ = f.Close()
			}
			return nil, nil, err
		}
		out = append(out, raw)
	}
	e.sessions = len(out)
	return out, files, nil
}

func (e *sessionExporter) ExportStorage(w io.Writer) error {
	if e.plan.file == "" {
		return storage.ExportHandoff(e.d.engine, w)
	}
	start := time.Now()
	before := heapInUse()
	ok, err := storage.ExportHandoffFile(e.d.engine, w, e.plan.file)
	if !ok {
		return storage.ExportHandoff(e.d.engine, w)
	}
	if err != nil {
		return err
	}
	e.filed = true
	logging.Infof("handoff: index written to %s and released in %s (heap in use %d → %d MiB)",
		e.plan.file, time.Since(start).Round(time.Millisecond), before>>20, heapInUse()>>20)
	return nil
}

func (e *sessionExporter) Resume() {
	// The index comes back before the sessions do, so none of them is answered
	// from an empty one.
	if e.filed {
		start := time.Now()
		if err := e.d.engine.(storage.HandoffFiler).RestoreHandoffFile(e.plan.file); err != nil {
			logging.Errorf("handoff: index not read back from %s, serving without it until clients re-offer: %v", e.plan.file, err)
		} else {
			logging.Infof("handoff: index read back from %s in %s", e.plan.file, time.Since(start).Round(time.Millisecond))
		}
		e.filed = false
	}
	if e.parked != nil {
		e.parked.Resume()
	}
	e.d.tcpGate.Open()
}

func (e *sessionExporter) Release() {
	e.parked.HandOff()
	// The successor read the file before it reported the import.
	if e.filed {
		_ = os.Remove(e.plan.file)
	}
}

// sessionImporter adapts the runtime and the storage engine to handoff.Importer.
type sessionImporter struct {
	d        handoffDeps
	restored *ed2k.RestoredSessions
}

func (i *sessionImporter) ImportStorage(r io.Reader) error {
	return storage.ImportHandoff(i.d.engine, r)
}

func (i *sessionImporter) Restore(states [][]byte, files []*os.File) error {
	decoded := make([]ed2k.SessionState, 0, len(states))
	for n, raw := range states {
		st, err := ed2k.DecodeSessionState(raw)
		if err != nil {
			for _, f := range files {
				_ = f.Close()
			}
			return fmt.Errorf("session %d: %w", n, err)
		}
		decoded = append(decoded, st)
	}
	restored, err := i.d.runtime.RestoreSessions(decoded, files)
	if err != nil {
		return err
	}
	i.restored = restored
	return nil
}

func (i *sessionImporter) Start() {
	i.restored.Start()
	i.d.tcpGate.Open()
	i.d.udpGate.Open()
	if unused := handoff.CloseUnclaimed(); len(unused) > 0 {
		logging.Infof("handoff: closed inherited sockets this configuration does not use: %v", unused)
	}
}

func (i *sessionImporter) Abort() {
	if i.restored != nil {
		i.restored.Close()
	}
}

// watchHandoff hands the server over to a new process of bootExecutable on
// SIGUSR2. A handover that fails leaves this process serving as before, and the
// signal can be sent again.
func watchHandoff(ctx context.Context, d handoffDeps) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGUSR2)
	go func() {
		defer signal.Stop(sig)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				_ = os.Remove(handoffStatusPath(d.pidFile))
				if err := handOver(d); err != nil {
					logging.Errorf("handoff failed, still serving: %v", err)
					writeHandoffStatus(d.pidFile, err)
					continue
				}
				d.handedOff.Store(true)
				d.cancel()
				return
			}
		}
	}()
}

// handOver starts the successor and moves everything to it.
func handOver(d handoffDeps) error {
	plan, err := planHandoff(d)
	if err != nil {
		return err
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	logging.Infof("handoff: SIGUSR2 received, starting %s", bootExecutable)
	succ, err := handoff.Spawn(handoff.SpawnConfig{
		Path:   bootExecutable,
		Args:   successorArgs(os.Args[1:]),
		Env:    append(os.Environ(), backgroundEnvKey+"=1"),
		Dir:    dir,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	})
	if err != nil {
		return err
	}
	exp := &sessionExporter{d: d, plan: plan}
	if err := handoff.Handover(succ, exp, handoff.DefaultTimeouts); err != nil {
		return err
	}
	logging.Infof("handoff: %d session(s) handed over to pid %d, clients paused %s; exiting",
		exp.sessions, succ.Pid(), time.Since(exp.quiesced).Round(time.Millisecond))
	return nil
}

// takeOver is the successor's side, run once everything is bound — behind closed
// gates — and before anything is served. An error means the process must exit.
func takeOver(d handoffDeps) error {
	ch := handoff.ParentChannel()
	if ch == nil {
		return nil
	}
	start := time.Now()
	imp := &sessionImporter{d: d}
	if err := handoff.Takeover(ch, imp, handoff.DefaultTimeouts); err != nil {
		return fmt.Errorf("handoff: taking over failed: %w", err)
	}
	logging.Infof("handoff: took over %d session(s) from the previous process in %s",
		imp.restored.Len(), time.Since(start).Round(time.Millisecond))
	return nil
}

// heapInUse is the Go heap in use, for the log line that shows what releasing the
// index gave back.
func heapInUse() uint64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse
}
