package storage

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lukechampine.com/blake3"

	"enode/logging"
)

// The ed3k keyword mirror of a ManticoreEngine. The database engine stays the
// store of record and decides every store; Manticore holds a copy of the live
// KEYWORD records and answers the searches that name words (Query.all), which
// on the database are a scan of the target. Each word is written as a hash
// token, so Manticore matches whole words byte for byte whatever its charset
// (ed3k has no substring match, §10.3). Searches without words, and every
// search while the mirror is not ready, run on the database.
//
// After a STORED keyword record the kept records of that file are read back
// from the database and written over the file's documents, so records that
// gave their place go at once. Expired documents go with the database sweep,
// and the whole table is rebuilt at startup and when the paging secret changes.

// ed3kManticoreSyncLimit is the size up to which InitEd3k fills the table before
// it returns; a larger store is filled in the background.
const ed3kManticoreSyncLimit = 50000

// ed3kManticore is the mirror's state inside a ManticoreEngine.
type ed3kManticore struct {
	ready      atomic.Bool
	rebuilding atomic.Bool
	mu         sync.Mutex
	secret     []byte // the paging secret the documents were written with
	matched    atomic.Uint64
	fallback   atomic.Uint64
}

// Ed3kTable is the name of the ed3k keyword table beside the eD2K one.
func (m *ManticoreEngine) Ed3kTable() string { return m.cfg.Table + "_ed3k" }

// Ed3kMirrorReady reports whether keyword searches run on Manticore.
func (m *ManticoreEngine) Ed3kMirrorReady() bool { return m.ed3k.ready.Load() }

// Ed3kMirrorMatched counts the keyword searches Manticore answered.
func (m *ManticoreEngine) Ed3kMirrorMatched() uint64 { return m.ed3k.matched.Load() }

// InitEd3k prepares the database engine, creates the mirror table and fills it.
func (m *ManticoreEngine) InitEd3k(ctx context.Context) error {
	inner, src, err := m.ed3kInner()
	if err != nil {
		return err
	}
	if err := inner.InitEd3k(ctx); err != nil {
		return err
	}
	if err := m.ed3kCreateTable(ctx); err != nil {
		m.setError(err)
		logging.Warnf("manticore: %v; ed3k keyword searches run on the database", err)
		return nil
	}
	st, err := inner.Ed3kStats(ctx, time.Now())
	if err == nil && st.Keywords <= ed3kManticoreSyncLimit {
		if err := m.ed3kRebuild(ctx, src); err != nil {
			logging.Warnf("manticore: filling %s: %v", m.Ed3kTable(), err)
		}
		return nil
	}
	go m.ed3kRebuildBackground(src)
	return nil
}

// StoreEd3kSource is the database engine's.
func (m *ManticoreEngine) StoreEd3kSource(ctx context.Context, r Ed3kSource, lim Ed3kLimits, now time.Time) (Ed3kResult, error) {
	inner, _, err := m.ed3kInner()
	if err != nil {
		return 0, err
	}
	return inner.StoreEd3kSource(ctx, r, lim, now)
}

// StoreEd3kKeyword stores on the database engine and copies the file's kept
// records to Manticore.
func (m *ManticoreEngine) StoreEd3kKeyword(ctx context.Context, r Ed3kKeyword, lim Ed3kLimits, now time.Time, verify func() error) (Ed3kResult, error) {
	inner, src, err := m.ed3kInner()
	if err != nil {
		return 0, err
	}
	res, err := inner.StoreEd3kKeyword(ctx, r, lim, now, verify)
	if err != nil || res != Ed3kStored {
		return res, err
	}
	if !m.up.Load() {
		return res, nil
	}
	if err := m.ed3kSyncFile(ctx, src, r.Target, r.Root); err != nil {
		// The mirror is behind: searches go to the database until it is rebuilt.
		m.ed3k.ready.Store(false)
		m.setError(fmt.Errorf("ed3k mirror write: %w", err))
		go m.ed3kRebuildBackground(src)
	}
	return res, nil
}

// StoreEd3kNote is the database engine's.
func (m *ManticoreEngine) StoreEd3kNote(ctx context.Context, r Ed3kNote, lim Ed3kLimits, now time.Time, verify func() error) (Ed3kResult, error) {
	inner, _, err := m.ed3kInner()
	if err != nil {
		return 0, err
	}
	return inner.StoreEd3kNote(ctx, r, lim, now, verify)
}

// SearchEd3kSources is the database engine's.
func (m *ManticoreEngine) SearchEd3kSources(ctx context.Context, target [16]byte, offset, limit int, now time.Time) ([]Ed3kSource, bool, error) {
	inner, _, err := m.ed3kInner()
	if err != nil {
		return nil, false, err
	}
	return inner.SearchEd3kSources(ctx, target, offset, limit, now)
}

// SearchEd3kKeywords runs a search that names words on Manticore, any other on
// the database engine.
func (m *ManticoreEngine) SearchEd3kKeywords(ctx context.Context, target [16]byte, q Ed3kQuery, offset, limit int, now time.Time) (Ed3kKeywordPage, error) {
	inner, src, err := m.ed3kInner()
	if err != nil {
		return Ed3kKeywordPage{}, err
	}
	if len(q.All) == 0 || !m.ed3k.ready.Load() {
		return inner.SearchEd3kKeywords(ctx, target, q, offset, limit, now)
	}
	p, err := m.ed3kSearch(ctx, src, target, q, offset, limit, now)
	if err == nil {
		m.ed3k.matched.Add(1)
		return p, nil
	}
	m.failures.Add(1)
	m.ed3k.fallback.Add(1)
	m.setError(fmt.Errorf("ed3k search: %w", err))
	m.warn("manticore: ed3k keyword search failed, running it on the database: %v", err)
	return inner.SearchEd3kKeywords(ctx, target, q, offset, limit, now)
}

// SearchEd3kNotes is the database engine's.
func (m *ManticoreEngine) SearchEd3kNotes(ctx context.Context, target [16]byte, offset, limit int, now time.Time) ([]Ed3kNote, bool, error) {
	inner, _, err := m.ed3kInner()
	if err != nil {
		return nil, false, err
	}
	return inner.SearchEd3kNotes(ctx, target, offset, limit, now)
}

// KeepEd3kSources is the database engine's.
func (m *ManticoreEngine) KeepEd3kSources(ctx context.Context, keptBy string, until time.Time) error {
	inner, _, err := m.ed3kInner()
	if err != nil {
		return err
	}
	return inner.KeepEd3kSources(ctx, keptBy, until)
}

// ReleaseEd3kSourcesByPrefix is the database engine's.
func (m *ManticoreEngine) ReleaseEd3kSourcesByPrefix(ctx context.Context, prefix string) error {
	inner, _, err := m.ed3kInner()
	if err != nil {
		return err
	}
	return inner.ReleaseEd3kSourcesByPrefix(ctx, prefix)
}

// Ed3kTarget is the database engine's.
func (m *ManticoreEngine) Ed3kTarget(ctx context.Context, kind uint8, target [16]byte, now time.Time) (int, bool, error) {
	inner, _, err := m.ed3kInner()
	if err != nil {
		return 0, false, err
	}
	return inner.Ed3kTarget(ctx, kind, target, now)
}

// ReleaseEd3kSources is the database engine's.
func (m *ManticoreEngine) ReleaseEd3kSources(ctx context.Context, keptBy string) error {
	inner, _, err := m.ed3kInner()
	if err != nil {
		return err
	}
	return inner.ReleaseEd3kSources(ctx, keptBy)
}

// ExpireEd3k sweeps the database engine, drops expired documents, and rebuilds
// the table when the paging secret changed.
func (m *ManticoreEngine) ExpireEd3k(ctx context.Context, now time.Time) (int, error) {
	inner, src, err := m.ed3kInner()
	if err != nil {
		return 0, err
	}
	n, err := inner.ExpireEd3k(ctx, now)
	if err != nil || !m.up.Load() {
		return n, err
	}
	if _, err := m.db.ExecContext(ctx, "DELETE FROM "+m.Ed3kTable()+" WHERE expires<=?", now.UnixMilli()); err != nil {
		m.setError(fmt.Errorf("ed3k mirror expiry: %w", err))
	}
	secret, err := src.ed3kPageSecret(ctx, now)
	if err != nil {
		return n, nil
	}
	m.ed3k.mu.Lock()
	changed := !bytes.Equal(secret, m.ed3k.secret)
	m.ed3k.mu.Unlock()
	if changed {
		go m.ed3kRebuildBackground(src)
	}
	return n, nil
}

// Ed3kBridge is the database engine's.
func (m *ManticoreEngine) Ed3kBridge(ctx context.Context, ed2k [16]byte, limit int, now time.Time) ([]Ed3kBridgeSource, error) {
	inner, _, err := m.ed3kInner()
	if err != nil {
		return nil, err
	}
	return inner.Ed3kBridge(ctx, ed2k, limit, now)
}

// Ed3kStats is the database engine's.
func (m *ManticoreEngine) Ed3kStats(ctx context.Context, now time.Time) (Ed3kStats, error) {
	inner, _, err := m.ed3kInner()
	if err != nil {
		return Ed3kStats{}, err
	}
	return inner.Ed3kStats(ctx, now)
}

func (m *ManticoreEngine) ed3kInner() (Ed3kStore, ed3kMirrorSource, error) {
	inner, ok := m.Engine.(Ed3kStore)
	src, ok2 := m.Engine.(ed3kMirrorSource)
	if !ok || !ok2 {
		return nil, nil, errors.New("manticore: the wrapped engine has no ed3k store")
	}
	return inner, src, nil
}

func (m *ManticoreEngine) ed3kCreateTable(ctx context.Context) error {
	if err := m.db.PingContext(ctx); err != nil {
		return fmt.Errorf("connecting to %s: %w", m.cfg.DSN, err)
	}
	if m.cfg.Recreate {
		if _, err := m.db.ExecContext(ctx, "DROP TABLE IF EXISTS "+m.Ed3kTable()); err != nil {
			return fmt.Errorf("manticore: dropping %s: %w", m.Ed3kTable(), err)
		}
	}
	_, err := m.db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+m.Ed3kTable()+` (
		terms text indexed, target string attribute, root string attribute, pubkey string attribute,
		publisher string attribute, signed string attribute, page_key string attribute, ext string attribute,
		ed2k string attribute, host string attribute, site string attribute,
		size bigint, sources bigint, expires bigint, stored_at bigint, via_signer bool
	) charset_table='0..9, a..z' min_word_len='1'`)
	if err != nil {
		return fmt.Errorf("manticore: creating %s: %w", m.Ed3kTable(), err)
	}
	return nil
}

// ed3kRebuild empties the table and writes every live record again.
func (m *ManticoreEngine) ed3kRebuild(ctx context.Context, src ed3kMirrorSource) error {
	if !m.ed3k.rebuilding.CompareAndSwap(false, true) {
		return nil
	}
	defer m.ed3k.rebuilding.Store(false)
	m.ed3k.ready.Store(false)
	now := time.Now()
	secret, err := src.ed3kPageSecret(ctx, now)
	if err != nil {
		return err
	}
	// Stores that land while the table fills write with the new secret too.
	m.ed3k.mu.Lock()
	m.ed3k.secret = secret
	m.ed3k.mu.Unlock()
	if _, err := m.db.ExecContext(ctx, "TRUNCATE TABLE "+m.Ed3kTable()); err != nil {
		return err
	}
	var batch []Ed3kKeyword
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := m.ed3kReplace(ctx, secret, batch)
		batch = batch[:0]
		return err
	}
	err = src.ed3kEachKeyword(ctx, now, func(r Ed3kKeyword) error {
		batch = append(batch, r)
		if len(batch) >= m.cfg.BatchSize {
			return flush()
		}
		return nil
	})
	if err == nil {
		err = flush()
	}
	if err != nil {
		return err
	}
	m.ed3k.ready.Store(true)
	return nil
}

func (m *ManticoreEngine) ed3kRebuildBackground(src ed3kMirrorSource) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	if err := m.ed3kRebuild(ctx, src); err != nil {
		m.setError(fmt.Errorf("ed3k mirror rebuild: %w", err))
		m.warn("manticore: rebuilding %s: %v", m.Ed3kTable(), err)
	}
}

// ed3kSyncFile writes the kept records of one file over its documents.
func (m *ManticoreEngine) ed3kSyncFile(ctx context.Context, src ed3kMirrorSource, target [16]byte, root [32]byte) error {
	recs, err := src.ed3kFileKeywords(ctx, target, root)
	if err != nil {
		return err
	}
	m.ed3k.mu.Lock()
	secret := m.ed3k.secret
	m.ed3k.mu.Unlock()
	if secret == nil {
		return nil // not filled yet; the rebuild writes it
	}
	if len(recs) > 0 {
		if err := m.ed3kReplace(ctx, secret, recs); err != nil {
			return err
		}
	}
	keep := make([]string, 0, len(recs))
	for _, r := range recs {
		keep = append(keep, fmt.Sprint(ed3kDocID(r)))
	}
	q := "DELETE FROM " + m.Ed3kTable() + " WHERE target=? AND root=?"
	if len(keep) > 0 {
		q += " AND id NOT IN (" + strings.Join(keep, ",") + ")"
	}
	_, err = m.db.ExecContext(ctx, q, hex.EncodeToString(target[:]), hex.EncodeToString(root[:]))
	return err
}

func (m *ManticoreEngine) ed3kReplace(ctx context.Context, secret []byte, recs []Ed3kKeyword) error {
	var b strings.Builder
	args := make([]any, 0, len(recs)*17)
	b.WriteString("REPLACE INTO " + m.Ed3kTable() + ` (id, terms, target, root, pubkey, publisher, signed, page_key, ext,
		ed2k, host, site, size, sources, expires, stored_at, via_signer) VALUES `)
	for i, r := range recs {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
		page := Ed3kPageKey(secret, r.Root[:], r.PubKey[:])
		args = append(args, ed3kDocID(r), ed3kTerms(r.Words), hex.EncodeToString(r.Target[:]), hex.EncodeToString(r.Root[:]),
			hex.EncodeToString(r.PubKey[:]), hex.EncodeToString(r.PublisherID[:]), hex.EncodeToString(r.Signed),
			hex.EncodeToString(page[:]), r.Ext, hex.EncodeToString(r.ED2K), r.Host, r.Site, int64(r.Size), int64(r.Sources),
			r.Expires.UnixMilli(), r.StoredAt.UnixMilli(), r.ViaSigner)
	}
	wctx, cancel := context.WithTimeout(ctx, manticoreWriteTimeout)
	defer cancel()
	_, err := m.db.ExecContext(wctx, b.String(), args...)
	return err
}

func (m *ManticoreEngine) ed3kSearch(ctx context.Context, src ed3kMirrorSource, target [16]byte, q Ed3kQuery, offset, limit int, now time.Time) (Ed3kKeywordPage, error) {
	var p Ed3kKeywordPage
	files, spill, err := src.Ed3kTarget(ctx, Ed3kKindKeyword, target, now)
	if err != nil {
		return p, err
	}
	p.Files, p.Spill = files, spill
	match := make([]string, 0, len(q.All)+len(q.None))
	for _, w := range q.All {
		match = append(match, ed3kTerm(w))
	}
	for _, w := range q.None {
		match = append(match, "-"+ed3kTerm(w))
	}
	where := []string{"MATCH(?)", "target=?", "expires>?"}
	args := []any{strings.Join(match, " "), hex.EncodeToString(target[:]), now.UnixMilli()}
	if q.MinSize > 0 {
		where, args = append(where, "size>=?"), append(args, int64(q.MinSize))
	}
	if q.MaxSize > 0 {
		where, args = append(where, "size<=?"), append(args, int64(q.MaxSize))
	}
	if q.MinSources > 0 {
		where, args = append(where, "sources>=?"), append(args, int64(q.MinSources))
	}
	if q.Ext != "" {
		where, args = append(where, "ext=?"), append(args, q.Ext)
	}
	args = append(args, offset, limit+1, offset+limit+1)
	sctx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
	defer cancel()
	rows, err := m.db.QueryContext(sctx, `SELECT target, root, pubkey, publisher, signed, ext, ed2k, host, site,
		size, sources, expires, stored_at, via_signer FROM `+m.Ed3kTable()+` WHERE `+strings.Join(where, " AND ")+
		` ORDER BY page_key ASC LIMIT ?,? OPTION max_matches=?`, args...)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var t, root, pub, pid, signed, ed2k string
		var size, sources, exp, stored int64
		var r Ed3kKeyword
		if err := rows.Scan(&t, &root, &pub, &pid, &signed, &r.Ext, &ed2k, &r.Host, &r.Site,
			&size, &sources, &exp, &stored, &r.ViaSigner); err != nil {
			return p, err
		}
		if err := ed3kUnhex(r.Target[:], t); err != nil {
			return p, err
		}
		ed3kUnhex(r.Root[:], root)
		ed3kUnhex(r.PubKey[:], pub)
		ed3kUnhex(r.PublisherID[:], pid)
		if r.Signed, err = hex.DecodeString(signed); err != nil {
			return p, err
		}
		if ed2k != "" {
			r.ED2K, _ = hex.DecodeString(ed2k)
		}
		r.Size, r.Sources = uint64(size), uint32(sources)
		r.Expires, r.StoredAt = time.UnixMilli(exp), time.UnixMilli(stored)
		p.Records = append(p.Records, r)
	}
	if err := rows.Err(); err != nil {
		return p, err
	}
	if len(p.Records) > limit {
		p.Records, p.More = p.Records[:limit], true
	}
	return p, nil
}

// ed3kDocID is a record's document id: one per (target, file, publisher).
func ed3kDocID(r Ed3kKeyword) uint64 { return manticoreKey(r.Target[:], r.Root[:], r.PubKey[:]) }

// ed3kTerms is the indexed field: one token per distinct word.
func ed3kTerms(words []string) string {
	seen := map[string]bool{}
	out := make([]string, 0, len(words))
	for _, w := range words {
		if t := ed3kTerm(w); !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return strings.Join(out, " ")
}

// ed3kTerm is the token of one word: "w" and 16 hex digits of its BLAKE3 hash,
// which Manticore's charset keeps as one word.
func ed3kTerm(w string) string {
	h := blake3.Sum256([]byte(w))
	return "w" + hex.EncodeToString(h[:8])
}

func ed3kUnhex(dst []byte, s string) error {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(dst) {
		return fmt.Errorf("manticore: bad hex attribute %q", s)
	}
	copy(dst, b)
	return nil
}
