//go:build unix

package handoff

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// ProtocolVersion is the handover protocol this build speaks. The predecessor
// refuses a successor that speaks another: it keeps serving and the operator
// restarts instead. The session state itself is gob, which tolerates fields being
// added or dropped between builds, so only a change to the sequence below, or to
// what a field means, needs a bump.
const ProtocolVersion = 1

// Exporter is the predecessor's side of a handover.
type Exporter interface {
	// Quiesce stops serving clients: no new connection is accepted and every
	// session is parked between two reads, with nothing written to it.
	Quiesce() error
	// Sessions returns the parked sessions, one encoded state and one socket each,
	// in the same order. A session that cannot be handed over is closed here, so
	// the storage export that follows no longer holds it.
	Sessions() (states [][]byte, files []*os.File, err error)
	// ExportStorage writes the storage state the sessions need.
	ExportStorage(w io.Writer) error
	// Resume undoes Quiesce after a handover that failed.
	Resume()
	// Release lets go of the handed-over sessions without closing them on the client.
	Release()
}

// Importer is the successor's side of a handover.
type Importer interface {
	ImportStorage(r io.Reader) error
	// Restore rebuilds the sessions, without serving them yet. It owns files.
	Restore(states [][]byte, files []*os.File) error
	// Start serves the restored sessions and opens the listeners.
	Start()
	// Abort drops what Restore built without touching storage: the predecessor
	// still owns those sessions.
	Abort()
}

// Timeouts bound each step that waits on the other process.
type Timeouts struct {
	// Ready is how long the successor may take to boot.
	Ready time.Duration
	// Transfer bounds sending the state and the successor importing it.
	Transfer time.Duration
}

// DefaultTimeouts are generous: a successor rebuilding a large memory index, or one
// whose GeoIP or Manticore setup is slow, is still a successor worth waiting for,
// and the predecessor serves normally while it boots.
var DefaultTimeouts = Timeouts{Ready: 5 * time.Minute, Transfer: 10 * time.Minute}

// Handover hands this process's sessions to succ. On success the caller shuts down,
// without releasing the sessions in storage: they live on in the successor. On
// failure the successor is killed and the caller has been put back to serving.
func Handover(succ *Successor, exp Exporter, t Timeouts) (err error) {
	succ.SetDeadline(time.Now().Add(t.Ready))
	version, err := succ.ExpectUint32(MsgReady)
	if err != nil {
		succ.Kill()
		return fmt.Errorf("successor did not get ready: %w", err)
	}
	if version != ProtocolVersion {
		_ = succ.Send(MsgAbort, []byte("protocol version mismatch"))
		succ.Kill()
		return fmt.Errorf("successor speaks handoff protocol %d, this process %d: restart instead", version, ProtocolVersion)
	}

	succ.SetDeadline(time.Now().Add(t.Transfer))
	if err := exp.Quiesce(); err != nil {
		_ = succ.Send(MsgAbort, []byte("predecessor could not quiesce"))
		succ.Kill()
		exp.Resume()
		return fmt.Errorf("quiesce: %w", err)
	}
	abort := func(cause error) error {
		_ = succ.Send(MsgAbort, []byte(cause.Error()))
		succ.Kill()
		exp.Resume()
		return cause
	}

	states, files, err := exp.Sessions()
	if err != nil {
		return abort(fmt.Errorf("collect sessions: %w", err))
	}
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	if err := succ.SendUint32(MsgBegin, uint32(len(states))); err != nil {
		return abort(err)
	}
	if err := exp.ExportStorage(succ.DataWriter()); err != nil {
		return abort(fmt.Errorf("export storage: %w", err))
	}
	if err := succ.EndData(); err != nil {
		return abort(err)
	}
	for _, st := range states {
		if err := succ.Send(MsgSession, st); err != nil {
			return abort(err)
		}
	}
	if err := succ.SendFiles(files); err != nil {
		return abort(err)
	}
	if _, err := succ.Expect(MsgImported); err != nil {
		return abort(fmt.Errorf("successor did not import: %w", err))
	}
	// Past this point the successor serves the sessions as soon as it reads the
	// commit, so there is no going back: a failed send leaves it waiting for a
	// commit that never comes, and it gives up and exits on its own deadline.
	if err := succ.Send(MsgCommit, nil); err != nil {
		return abort(err)
	}
	exp.Release()
	_ = succ.Close()
	return nil
}

// Takeover is the successor's side: it announces itself, imports what the
// predecessor sends and starts serving once the predecessor has let go. An error
// means this process must exit without serving anything.
func Takeover(ch *Channel, imp Importer, t Timeouts) error {
	defer ch.Close()
	ch.SetDeadline(time.Now().Add(t.Transfer))
	if err := ch.SendUint32(MsgReady, ProtocolVersion); err != nil {
		return err
	}
	// The predecessor quiesces before it begins, which waits for its sessions to
	// park, so this read gets the whole transfer budget too.
	count, err := ch.ExpectUint32(MsgBegin)
	if err != nil {
		return err
	}
	data := ch.DataReader()
	if err := imp.ImportStorage(data); err != nil {
		_ = ch.Send(MsgAbort, []byte(err.Error()))
		return fmt.Errorf("import storage: %w", err)
	}
	// Whatever the importer left unread — trailing buffering, a format it skips —
	// so the session frames that follow are read as frames.
	if _, err := io.Copy(io.Discard, data); err != nil {
		return err
	}
	states := make([][]byte, 0, count)
	for range count {
		st, err := ch.Expect(MsgSession)
		if err != nil {
			return err
		}
		states = append(states, st)
	}
	files, err := ch.RecvFiles(int(count))
	if err != nil {
		return err
	}
	if err := imp.Restore(states, files); err != nil {
		_ = ch.Send(MsgAbort, []byte(err.Error()))
		return fmt.Errorf("restore sessions: %w", err)
	}
	if err := ch.Send(MsgImported, nil); err != nil {
		imp.Abort()
		return err
	}
	if _, err := ch.Expect(MsgCommit); err != nil {
		// No commit, no serving — even when the predecessor simply vanished: it may
		// have aborted and gone back to the very sockets restored here.
		imp.Abort()
		if errors.Is(err, io.EOF) {
			return errors.New("predecessor went away before committing")
		}
		return err
	}
	imp.Start()
	return nil
}
