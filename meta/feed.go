package meta

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"enode/logging"
	"enode/storage"

	"connectrpc.com/connect/v2"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
)

// Feed holds one daemon's published set in memory, kept current by a Subscribe
// stream, so its releases match a search without a round trip.
//
// The stream starts from a snapshot (after_seq 0) on every process start and resumes
// from the last applied cursor on a reconnect within the process. Rows live only in
// memory, so there is no persisted cursor that could outlive the rows it describes.
// The contract's rules are applied as written in enodemeta/docs/ingest-contract.md:
// reset drops everything held for the daemon, an upsert replaces every row of its
// catalog_id, and snapshot_end drops whatever the snapshot did not re-send.
type Feed struct {
	network string
	client  metav1connect.MetaIngestClient
	maxRows int
	minWait time.Duration
	maxWait time.Duration

	mu       sync.RWMutex
	releases map[string][]feedRow // by catalog_id
	rows     int
	cursor   uint64
	// seen collects the catalog_ids a snapshot re-sent, between reset and snapshot_end.
	seen      map[string]struct{}
	capWarned bool
	caughtUp  bool
}

// feedRow is a converted row plus its lowercased name, so a search can reject most
// rows with one substring test before running the full expression.
type feedRow struct {
	file  storage.File
	lname string
}

// NewFeed returns a feed for one daemon. It does nothing until Run.
func NewFeed(network string, client metav1connect.MetaIngestClient, maxRows int, minWait, maxWait time.Duration) *Feed {
	return &Feed{
		network:  network,
		client:   client,
		maxRows:  maxRows,
		minWait:  minWait,
		maxWait:  maxWait,
		releases: map[string][]feedRow{},
	}
}

// Run keeps the subscription open until ctx ends, reconnecting with exponential
// backoff. A daemon that is down is "no new rows", never an error: the rows already
// held keep answering searches.
func (f *Feed) Run(ctx context.Context) {
	wait := f.minWait
	for {
		received, err := f.subscribe(ctx)
		if ctx.Err() != nil {
			return
		}
		if received {
			wait = f.minWait
		}
		logging.Warnf("meta feed %s: stream ended (%v), reconnecting in %s", f.network, err, wait)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, f.maxWait)
	}
}

// Match returns up to limit rows matching expr, best-seeded first. terms are the
// positive keywords of the query, used as a cheap prefilter: a row must contain every
// one of them for the full expression to match it anyway.
func (f *Feed) Match(expr *storage.SearchExpr, terms []string, limit int) []storage.File {
	if limit <= 0 {
		return nil
	}
	lower := make([]string, len(terms))
	for i, t := range terms {
		lower[i] = strings.ToLower(t)
	}

	f.mu.RLock()
	var out []storage.File
	for _, rows := range f.releases {
		for _, row := range rows {
			if !containsAll(row.lname, lower) || !storage.MatchSearchExpr(expr, row.file) {
				continue
			}
			out = append(out, row.file)
		}
	}
	f.mu.RUnlock()

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Meta.Seeders != out[j].Meta.Seeders {
			return out[i].Meta.Seeders > out[j].Meta.Seeders
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Rows reports how many rows the feed holds.
func (f *Feed) Rows() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.rows
}

// FeedStats is what a feed holds and where its stream stands.
type FeedStats struct {
	Releases int
	Rows     int
	Cursor   uint64
	CaughtUp bool
}

// Stats reports what the feed holds, for the admin dashboard.
func (f *Feed) Stats() FeedStats {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return FeedStats{Releases: len(f.releases), Rows: f.rows, Cursor: f.cursor, CaughtUp: f.caughtUp}
}

// subscribe runs one stream to its end. It reports whether any message arrived, so
// a stream that worked for a while resets the backoff.
func (f *Feed) subscribe(ctx context.Context) (bool, error) {
	f.mu.RLock()
	after := f.cursor
	if f.seen != nil {
		// The stream broke inside a snapshot. Its snapshot_end, which is what prunes
		// the releases it did not re-send, will never arrive on a resumed stream, so
		// ask for the whole snapshot again.
		after = 0
	}
	f.mu.RUnlock()

	stream, err := f.client.Subscribe(ctx, &metav1.SubscribeRequest{AfterSeq: after, Subscriber: "eNode-go"})
	if err != nil {
		return false, err
	}
	defer func() { _ = stream.Close() }()

	received := false
	for {
		msg, err := stream.Receive()
		if err != nil {
			if connect.CodeOf(err) == connect.CodeUnauthenticated {
				err = errors.New("the daemon refused the token (metaSearch." + f.network + ".token)")
			}
			return received, err
		}
		if !received {
			// Logged on the first message rather than at Subscribe: the stream is
			// opened lazily, so until then nothing has actually connected.
			logging.Infof("meta feed %s: subscribed after_seq=%d", f.network, after)
		}
		received = true
		f.apply(msg)
	}
}

// apply applies one stream message. The cursor advances only after its changes are
// in, which is the contract's "persist after applying" rule held in memory.
func (f *Feed) apply(msg *metav1.SubscribeResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if msg.GetReset_() {
		logging.Infof("meta feed %s: reset, dropping %d rows for a fresh snapshot", f.network, f.rows)
		f.releases = map[string][]feedRow{}
		f.rows = 0
		f.seen = map[string]struct{}{}
		f.capWarned = false
	}
	for _, change := range msg.GetChanges() {
		id := change.GetCatalogId()
		f.removeLocked(id)
		if change.GetOp() != metav1.ChangeOp_CHANGE_OP_UPSERT {
			continue
		}
		if f.seen != nil {
			f.seen[id] = struct{}{}
		}
		f.addLocked(id, change.GetEntries())
	}
	if msg.GetSnapshotEnd() && f.seen != nil {
		for id := range f.releases {
			if _, ok := f.seen[id]; !ok {
				f.removeLocked(id)
			}
		}
		f.seen = nil
	}
	if msg.GetCursor() > f.cursor {
		f.cursor = msg.GetCursor()
	}
	if msg.GetCaughtUp() && !f.caughtUp {
		f.caughtUp = true
		logging.Infof("meta feed %s: caught up, %d releases / %d rows, cursor %d",
			f.network, len(f.releases), f.rows, f.cursor)
	}
}

func (f *Feed) addLocked(id string, entries []*metav1.MetaEntry) {
	rows := make([]feedRow, 0, len(entries))
	for _, entry := range entries {
		file, err := EntryToFile(entry)
		if err != nil {
			logging.Debugf("meta feed %s: dropped row of %s: %v", f.network, id, err)
			continue
		}
		rows = append(rows, feedRow{file: file, lname: strings.ToLower(file.Name)})
	}
	if len(rows) == 0 {
		return
	}
	if f.rows+len(rows) > f.maxRows {
		if !f.capWarned {
			f.capWarned = true
			logging.Warnf("meta feed %s: maxRows %d reached, further releases are not held (raise metaSearch.%s.feed.maxRows)",
				f.network, f.maxRows, f.network)
		}
		return
	}
	f.releases[id] = rows
	f.rows += len(rows)
}

func (f *Feed) removeLocked(id string) {
	if rows, ok := f.releases[id]; ok {
		f.rows -= len(rows)
		delete(f.releases, id)
	}
}

func containsAll(s string, terms []string) bool {
	for _, t := range terms {
		if !strings.Contains(s, t) {
			return false
		}
	}
	return true
}
