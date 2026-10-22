package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"enode/ed3k/ident"
)

//go:embed ed3k_mysql.sql
var ed3kMySQLDDL string

// mysqlEd3k is the MySQLEngine's ed3k state: the paging secret as last read.
type mysqlEd3k struct {
	mu       sync.Mutex
	secret   []byte
	loadedAt time.Time
	total    int
	totalAt  time.Time
}

// ed3kSecretReload is how often an instance re-reads the paging secret that
// another instance on the same database may have replaced.
const ed3kSecretReload = time.Minute

// ed3kExpireBatch is how many rows one expiry statement deletes.
const ed3kExpireBatch = 5000

// InitEd3k creates the ed3k tables when missing and loads the paging secret.
func (m *MySQLEngine) InitEd3k(ctx context.Context) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	for _, stmt := range splitSQLStatements(ed3kMySQLDDL) {
		if _, err := m.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("mysql create ed3k tables: %w", err)
		}
	}
	_, err := m.ed3kSecret(ctx, time.Now(), true)
	return err
}

// StoreEd3kSource stores or renews a SOURCE record.
func (m *MySQLEngine) StoreEd3kSource(ctx context.Context, r Ed3kSource, lim Ed3kLimits, now time.Time) (Ed3kResult, error) {
	if err := m.ensureDB(); err != nil {
		return 0, err
	}
	lim = lim.WithDefaults()
	secret, err := m.ed3kSecret(ctx, now, false)
	if err != nil {
		return 0, err
	}
	nowMs := now.UnixMilli()
	total := m.ed3kTotal(ctx, now)
	if err := m.ed3kEnsureTarget(ctx, Ed3kKindSource, r.Target, now); err != nil {
		return 0, err
	}
	var result Ed3kResult
	err = m.ed3kTx(ctx, "ed3k store source", func(tx *sql.Tx) error {
		tid, _, err := ed3kLockTarget(ctx, tx, Ed3kKindSource, r.Target, now)
		if err != nil {
			return err
		}
		v := ed3kSourceView{Total: total}
		var held Ed3kSource
		switch err := tx.QueryRowContext(ctx, `SELECT host, site FROM ed3k_sources WHERE target=? AND node_id=?`,
			r.Target[:], r.NodeID[:]).Scan(&held.Host, &held.Site); {
		case err == nil:
			v.Held = &held
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		var evictable int
		if err := tx.QueryRowContext(ctx, `SELECT
			(SELECT COUNT(*) FROM ed3k_sources WHERE target=?),
			(SELECT COUNT(*) FROM ed3k_sources WHERE target=? AND host=? AND node_id<>?),
			(SELECT COUNT(*) FROM ed3k_sources WHERE target=? AND site=? AND node_id<>?),
			(SELECT COUNT(*) FROM ed3k_sources WHERE target=? AND lifetime_end<? AND node_id<>?)`,
			r.Target[:], r.Target[:], r.Host, r.NodeID[:], r.Target[:], r.Site, r.NodeID[:],
			r.Target[:], nowMs, r.NodeID[:]).Scan(&v.Count, &v.HostCount, &v.SiteCount, &evictable); err != nil {
			return err
		}
		v.Evictable = evictable > 0
		if v.HostTotal, v.SiteTotal, err = ed3kAddressTotals(ctx, tx, r.Host, r.Site); err != nil {
			return err
		}
		d := decideSource(v, r, lim)
		result = d.Result
		if d.Full {
			if _, err := tx.ExecContext(ctx, `UPDATE ed3k_targets SET full_at=?, updated_at=? WHERE id=?`, nowMs, now.UTC(), tid); err != nil {
				return err
			}
		}
		if d.Result != Ed3kStored {
			return nil
		}
		if d.Evict {
			if _, err := tx.ExecContext(ctx, `DELETE FROM ed3k_sources WHERE target=? AND lifetime_end<? AND node_id<>? ORDER BY lifetime_end LIMIT 1`,
				r.Target[:], nowMs, r.NodeID[:]); err != nil {
				return err
			}
		}
		page := Ed3kPageKey(secret, r.NodeID[:])
		_, err = tx.ExecContext(ctx, `INSERT INTO ed3k_sources
			(target,node_id,peer,host,site,ep4,ed2k_cap,lifetime_end,expires,kept_by,page_key,created_at,updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
			ON DUPLICATE KEY UPDATE peer=VALUES(peer), host=VALUES(host), site=VALUES(site), ep4=VALUES(ep4),
			ed2k_cap=VALUES(ed2k_cap), lifetime_end=VALUES(lifetime_end), expires=VALUES(expires),
			kept_by=VALUES(kept_by), page_key=VALUES(page_key), updated_at=VALUES(updated_at)`,
			r.Target[:], r.NodeID[:], r.Peer, r.Host, r.Site, ed3kEP4(r), r.ED2K, r.LifetimeEnd.UnixMilli(),
			r.LifetimeEnd.UnixMilli(), nullString(r.KeptBy), page[:], now.UTC(), now.UTC())
		return err
	})
	return result, err
}

// StoreEd3kKeyword stores a KEYWORD record.
func (m *MySQLEngine) StoreEd3kKeyword(ctx context.Context, r Ed3kKeyword, lim Ed3kLimits, now time.Time, verify func() error) (Ed3kResult, error) {
	if err := m.ensureDB(); err != nil {
		return 0, err
	}
	lim = lim.WithDefaults()
	secret, err := m.ed3kSecret(ctx, now, false)
	if err != nil {
		return 0, err
	}
	hash := Ed3kSignedHash(r.Signed)
	nowMs := now.UnixMilli()
	total := m.ed3kTotal(ctx, now)
	if err := m.ed3kEnsureTarget(ctx, Ed3kKindKeyword, r.Target, now); err != nil {
		return 0, err
	}
	var result Ed3kResult
	err = m.ed3kTx(ctx, "ed3k store keyword", func(tx *sql.Tx) error {
		tid, files, err := ed3kLockTarget(ctx, tx, Ed3kKindKeyword, r.Target, now)
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT pubkey, site, host, stored_at, expires, signed_hash
			FROM ed3k_keywords WHERE target=? AND root=?`, r.Target[:], r.Root[:])
		if err != nil {
			return err
		}
		v := ed3kKeywordView{Files: files, Total: total}
		for rows.Next() {
			var h ed3kHeldKeyword
			var pub, sh []byte
			var stored, exp int64
			if err := rows.Scan(&pub, &h.Site, &h.Host, &stored, &exp, &sh); err != nil {
				rows.Close()
				return err
			}
			copy(h.PubKey[:], pub)
			copy(h.SignedHash[:], sh)
			h.StoredAt, h.Expires = time.UnixMilli(stored), time.UnixMilli(exp)
			v.Held = append(v.Held, h)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, h := range v.Held {
			if h.PubKey == r.PubKey && h.SignedHash == hash {
				result = Ed3kOlder
				return nil
			}
		}
		if verify != nil {
			if err := verify(); err != nil {
				result = Ed3kRejected
				return nil
			}
		}
		if err := tx.QueryRowContext(ctx, `SELECT
			(SELECT COUNT(*) FROM ed3k_keywords WHERE target=? AND pubkey=?),
			(SELECT COUNT(DISTINCT root) FROM ed3k_keywords WHERE target=? AND site=?)`,
			r.Target[:], r.PubKey[:], r.Target[:], r.Site).Scan(&v.KeyFiles, &v.SiteFiles); err != nil {
			return err
		}
		if v.HostTotal, v.SiteTotal, err = ed3kAddressTotals(ctx, tx, r.Host, r.Site); err != nil {
			return err
		}
		d := decideKeyword(v, r, lim)
		result = d.Result
		if d.Full {
			if _, err := tx.ExecContext(ctx, `UPDATE ed3k_targets SET full_at=?, updated_at=? WHERE id=?`, nowMs, now.UTC(), tid); err != nil {
				return err
			}
		}
		if d.Result != Ed3kStored {
			return nil
		}
		if d.Replace != nil {
			if _, err := tx.ExecContext(ctx, `DELETE FROM ed3k_keywords WHERE target=? AND root=? AND pubkey=?`,
				r.Target[:], r.Root[:], d.Replace[:]); err != nil {
				return err
			}
		}
		page := Ed3kPageKey(secret, r.Root[:], r.PubKey[:])
		if _, err := tx.ExecContext(ctx, `INSERT INTO ed3k_keywords
			(target,root,root_target,pubkey,publisher_id,signed,signed_hash,words,ext,size,sources,ed2k,host,site,
			 via_signer,stored_at,expires,page_key,created_at,updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			r.Target[:], r.Root[:], r.Root[:16], r.PubKey[:], r.PublisherID[:], r.Signed, hash[:], ed3kWordList(r.Words),
			r.Ext, r.Size, r.Sources, nullBytes(r.ED2K), r.Host, r.Site, r.ViaSigner, nowMs, r.Expires.UnixMilli(),
			page[:], now.UTC(), now.UTC()); err != nil {
			return err
		}
		if len(v.Held) == 0 {
			_, err = tx.ExecContext(ctx, `UPDATE ed3k_targets SET files=files+1, updated_at=? WHERE id=?`, now.UTC(), tid)
		}
		return err
	})
	return result, err
}

// StoreEd3kNote stores a NOTE record.
func (m *MySQLEngine) StoreEd3kNote(ctx context.Context, r Ed3kNote, lim Ed3kLimits, now time.Time, verify func() error) (Ed3kResult, error) {
	if err := m.ensureDB(); err != nil {
		return 0, err
	}
	lim = lim.WithDefaults()
	secret, err := m.ed3kSecret(ctx, now, false)
	if err != nil {
		return 0, err
	}
	hash := Ed3kSignedHash(r.Signed)
	nowMs := now.UnixMilli()
	total := m.ed3kTotal(ctx, now)
	if err := m.ed3kEnsureTarget(ctx, Ed3kKindNote, r.Target, now); err != nil {
		return 0, err
	}
	var result Ed3kResult
	err = m.ed3kTx(ctx, "ed3k store note", func(tx *sql.Tx) error {
		tid, _, err := ed3kLockTarget(ctx, tx, Ed3kKindNote, r.Target, now)
		if err != nil {
			return err
		}
		v := ed3kNoteView{Total: total}
		var held Ed3kNote
		var sh []byte
		var exp int64
		switch err := tx.QueryRowContext(ctx, `SELECT host, site, expires, signed_hash FROM ed3k_notes WHERE target=? AND pubkey=?`,
			r.Target[:], r.PubKey[:]).Scan(&held.Host, &held.Site, &exp, &sh); {
		case err == nil:
			held.Expires = time.UnixMilli(exp)
			v.Held = &held
			if string(sh) == string(hash[:]) {
				result = Ed3kOlder
				return nil
			}
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		if verify != nil {
			if err := verify(); err != nil {
				result = Ed3kRejected
				return nil
			}
		}
		if err := tx.QueryRowContext(ctx, `SELECT
			(SELECT COUNT(*) FROM ed3k_notes WHERE target=?),
			(SELECT COUNT(*) FROM ed3k_notes WHERE target=? AND host=? AND pubkey<>?),
			(SELECT COUNT(*) FROM ed3k_notes WHERE target=? AND site=? AND pubkey<>?)`,
			r.Target[:], r.Target[:], r.Host, r.PubKey[:], r.Target[:], r.Site, r.PubKey[:]).Scan(&v.Count, &v.HostCount, &v.SiteCount); err != nil {
			return err
		}
		if v.HostTotal, v.SiteTotal, err = ed3kAddressTotals(ctx, tx, r.Host, r.Site); err != nil {
			return err
		}
		d := decideNote(v, r, lim)
		result = d.Result
		if d.Full {
			if _, err := tx.ExecContext(ctx, `UPDATE ed3k_targets SET full_at=?, updated_at=? WHERE id=?`, nowMs, now.UTC(), tid); err != nil {
				return err
			}
		}
		if d.Result != Ed3kStored {
			return nil
		}
		page := Ed3kPageKey(secret, r.PubKey[:])
		_, err = tx.ExecContext(ctx, `INSERT INTO ed3k_notes
			(target,pubkey,signed,signed_hash,host,site,expires,page_key,created_at,updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?)
			ON DUPLICATE KEY UPDATE signed=VALUES(signed), signed_hash=VALUES(signed_hash), host=VALUES(host),
			site=VALUES(site), expires=VALUES(expires), page_key=VALUES(page_key), updated_at=VALUES(updated_at)`,
			r.Target[:], r.PubKey[:], r.Signed, hash[:], r.Host, r.Site, r.Expires.UnixMilli(), page[:], now.UTC(), now.UTC())
		return err
	})
	return result, err
}

// SearchEd3kSources pages the live sources of a target.
func (m *MySQLEngine) SearchEd3kSources(ctx context.Context, target [16]byte, offset, limit int, now time.Time) ([]Ed3kSource, bool, error) {
	if err := m.ensureDB(); err != nil {
		return nil, false, err
	}
	rows, err := m.db.QueryContext(ctx, `SELECT node_id, peer, host, site, ep4, ed2k_cap, lifetime_end, kept_by
		FROM ed3k_sources WHERE target=? AND expires>? ORDER BY page_key LIMIT ? OFFSET ?`,
		target[:], now.UnixMilli(), limit+1, offset)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []Ed3kSource
	for rows.Next() {
		var s Ed3kSource
		var id, ep4 []byte
		var life int64
		var kept sql.NullString
		if err := rows.Scan(&id, &s.Peer, &s.Host, &s.Site, &ep4, &s.ED2K, &life, &kept); err != nil {
			return nil, false, err
		}
		s.Target = target
		copy(s.NodeID[:], id)
		s.EP4, _, _ = ident.DecodeEndpoint(ep4)
		s.LifetimeEnd = time.UnixMilli(life)
		s.KeptBy = kept.String
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

// SearchEd3kKeywords pages the records of a keyword target matching q.
func (m *MySQLEngine) SearchEd3kKeywords(ctx context.Context, target [16]byte, q Ed3kQuery, offset, limit int, now time.Time) (Ed3kKeywordPage, error) {
	var p Ed3kKeywordPage
	if err := m.ensureDB(); err != nil {
		return p, err
	}
	var fullAt int64
	switch err := m.db.QueryRowContext(ctx, `SELECT files, full_at FROM ed3k_targets WHERE kind=? AND target=?`,
		Ed3kKindKeyword, target[:]).Scan(&p.Files, &fullAt); {
	case errors.Is(err, sql.ErrNoRows):
		return p, nil
	case err != nil:
		return p, err
	}
	p.Spill = fullAt > 0 && now.Sub(time.UnixMilli(fullAt)) < ed3kFullMemory(Ed3kKindKeyword)
	where, args := ed3kKeywordWhere(target, q, now)
	args = append(args, limit+1, offset)
	rows, err := m.db.QueryContext(ctx, `SELECT root, pubkey, publisher_id, signed, words, ext, size, sources, ed2k,
		host, site, stored_at, expires FROM ed3k_keywords WHERE `+where+` ORDER BY page_key LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		r := Ed3kKeyword{Target: target}
		var root, pub, pid, ed2k []byte
		var words string
		var stored, exp int64
		if err := rows.Scan(&root, &pub, &pid, &r.Signed, &words, &r.Ext, &r.Size, &r.Sources, &ed2k,
			&r.Host, &r.Site, &stored, &exp); err != nil {
			return p, err
		}
		copy(r.Root[:], root)
		copy(r.PubKey[:], pub)
		copy(r.PublisherID[:], pid)
		r.ED2K = ed2k
		r.Words = ed3kParseWordList(words)
		r.StoredAt, r.Expires = time.UnixMilli(stored), time.UnixMilli(exp)
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

// SearchEd3kNotes pages the notes of a file target.
func (m *MySQLEngine) SearchEd3kNotes(ctx context.Context, target [16]byte, offset, limit int, now time.Time) ([]Ed3kNote, bool, error) {
	if err := m.ensureDB(); err != nil {
		return nil, false, err
	}
	rows, err := m.db.QueryContext(ctx, `SELECT pubkey, signed, host, site, expires FROM ed3k_notes
		WHERE target=? AND expires>? ORDER BY page_key LIMIT ? OFFSET ?`, target[:], now.UnixMilli(), limit+1, offset)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []Ed3kNote
	for rows.Next() {
		n := Ed3kNote{Target: target}
		var pub []byte
		var exp int64
		if err := rows.Scan(&pub, &n.Signed, &n.Host, &n.Site, &exp); err != nil {
			return nil, false, err
		}
		copy(n.PubKey[:], pub)
		n.Expires = time.UnixMilli(exp)
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

// KeepEd3kSources extends the records kept by a live connection.
func (m *MySQLEngine) KeepEd3kSources(ctx context.Context, keptBy string, until time.Time) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	return m.execRetry("ed3k keep sources", func() error {
		_, err := m.db.ExecContext(ctx, `UPDATE ed3k_sources SET expires=GREATEST(expires, ?) WHERE kept_by=?`, until.UnixMilli(), keptBy)
		return err
	})
}

// ReleaseEd3kSources ends the keeping of a closed connection.
func (m *MySQLEngine) ReleaseEd3kSources(ctx context.Context, keptBy string) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	return m.execRetry("ed3k release sources", func() error {
		_, err := m.db.ExecContext(ctx, `UPDATE ed3k_sources SET expires=lifetime_end, kept_by=NULL WHERE kept_by=?`, keptBy)
		return err
	})
}

// ReleaseEd3kSourcesByPrefix ends the keeping of the connections whose names start with prefix.
func (m *MySQLEngine) ReleaseEd3kSourcesByPrefix(ctx context.Context, prefix string) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	return m.execRetry("ed3k release sources", func() error {
		_, err := m.db.ExecContext(ctx, `UPDATE ed3k_sources SET expires=lifetime_end, kept_by=NULL WHERE kept_by LIKE ?`,
			likePrefix(prefix))
		return err
	})
}

// likePrefix is a LIKE pattern that matches the strings starting with p.
func likePrefix(p string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(p) + "%"
}

// ExpireEd3k deletes what has expired and rotates the paging secret.
func (m *MySQLEngine) ExpireEd3k(ctx context.Context, now time.Time) (int, error) {
	if err := m.ensureDB(); err != nil {
		return 0, err
	}
	nowMs := now.UnixMilli()
	total := 0
	for _, table := range []string{"ed3k_sources", "ed3k_notes"} {
		for {
			res, err := m.db.ExecContext(ctx, `DELETE FROM `+table+` WHERE expires<=? LIMIT ?`, nowMs, ed3kExpireBatch)
			if err != nil {
				return total, err
			}
			n, _ := res.RowsAffected()
			total += int(n)
			if n < ed3kExpireBatch {
				break
			}
		}
	}
	for {
		n, err := m.ed3kExpireKeywords(ctx, nowMs)
		total += n
		if err != nil {
			return total, err
		}
		if n < ed3kExpireBatch {
			break
		}
	}
	if _, err := m.db.ExecContext(ctx, `DELETE t FROM ed3k_targets t WHERE t.full_at<? AND (
		(t.kind=2 AND t.files=0) OR
		(t.kind=1 AND NOT EXISTS (SELECT 1 FROM ed3k_sources s WHERE s.target=t.target)) OR
		(t.kind=3 AND NOT EXISTS (SELECT 1 FROM ed3k_notes n WHERE n.target=t.target)))`,
		now.Add(-ed3kFullMemory(Ed3kKindKeyword)).UnixMilli()); err != nil {
		return total, err
	}
	if err := m.ed3kRotate(ctx, now); err != nil {
		return total, err
	}
	m.ed3kState.mu.Lock()
	m.ed3kState.totalAt = time.Time{}
	m.ed3kState.mu.Unlock()
	return total, nil
}

// Ed3kBridge returns live sources of the ed2k hash whose publisher signed a
// KEYWORD record giving that hash for the file.
func (m *MySQLEngine) Ed3kBridge(ctx context.Context, ed2k [16]byte, limit int, now time.Time) ([]Ed3kBridgeSource, error) {
	if err := m.ensureDB(); err != nil {
		return nil, err
	}
	nowMs := now.UnixMilli()
	rows, err := m.db.QueryContext(ctx, `SELECT DISTINCT s.node_id, s.ep4 FROM ed3k_keywords k
		JOIN ed3k_sources s ON s.target=k.root_target AND s.node_id=k.publisher_id
		WHERE k.ed2k=? AND k.expires>? AND s.expires>? AND s.ed2k_cap=1 AND s.ep4 IS NOT NULL LIMIT ?`,
		ed2k[:], nowMs, nowMs, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ed3kBridgeSource
	for rows.Next() {
		var id, ep4 []byte
		if err := rows.Scan(&id, &ep4); err != nil {
			return nil, err
		}
		var b Ed3kBridgeSource
		copy(b.NodeID[:], id)
		if b.EP4, _, err = ident.DecodeEndpoint(ep4); err != nil || !b.EP4.IsValid() {
			continue
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// Ed3kStats counts the records.
func (m *MySQLEngine) Ed3kStats(ctx context.Context, now time.Time) (Ed3kStats, error) {
	var st Ed3kStats
	if err := m.ensureDB(); err != nil {
		return st, err
	}
	err := m.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM ed3k_sources),
		(SELECT COUNT(*) FROM ed3k_keywords),
		(SELECT COUNT(*) FROM ed3k_notes),
		(SELECT COUNT(*) FROM ed3k_sources WHERE kept_by IS NOT NULL AND lifetime_end<?)`, now.UnixMilli()).
		Scan(&st.Sources, &st.Keywords, &st.Notes, &st.Kept)
	return st, err
}

// ed3kEnsureTarget creates the target row in its own statement, before the
// transaction that locks it: concurrent INSERT IGNOREs of one key inside
// transactions deadlock on their gap locks.
func (m *MySQLEngine) ed3kEnsureTarget(ctx context.Context, kind uint8, target [16]byte, now time.Time) error {
	return m.execRetry("ed3k target row", func() error {
		_, err := m.db.ExecContext(ctx, `INSERT IGNORE INTO ed3k_targets (kind,target,files,full_at,created_at,updated_at) VALUES (?,?,0,0,?,?)`,
			kind, target[:], now.UTC(), now.UTC())
		return err
	})
}

// ed3kTx runs fn in a transaction and runs it again from the start when InnoDB
// rolled it back for a deadlock or a lock wait.
func (m *MySQLEngine) ed3kTx(ctx context.Context, what string, fn func(*sql.Tx) error) error {
	return m.execRetry(what, func() error {
		tx, err := m.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			tx.Rollback()
			return err
		}
		return tx.Commit()
	})
}

// ed3kSecret returns the paging secret, creating it on first use and re-reading
// it every minute.
func (m *MySQLEngine) ed3kSecret(ctx context.Context, now time.Time, force bool) ([]byte, error) {
	st := &m.ed3kState
	st.mu.Lock()
	defer st.mu.Unlock()
	if !force && st.secret != nil && now.Sub(st.loadedAt) < ed3kSecretReload {
		return st.secret, nil
	}
	if _, err := m.db.ExecContext(ctx, `INSERT IGNORE INTO ed3k_state (id,secret,rotated_at,created_at,updated_at) VALUES (1,?,?,?,?)`,
		ed3kNewSecret(), now.UnixMilli(), now.UTC(), now.UTC()); err != nil {
		return nil, err
	}
	var secret []byte
	if err := m.db.QueryRowContext(ctx, `SELECT secret FROM ed3k_state WHERE id=1`).Scan(&secret); err != nil {
		return nil, err
	}
	st.secret, st.loadedAt = secret, now
	return secret, nil
}

// ed3kTotal is the number of records held, re-counted at most once a minute:
// MaxRecords is a coarse bound.
func (m *MySQLEngine) ed3kTotal(ctx context.Context, now time.Time) int {
	st := &m.ed3kState
	st.mu.Lock()
	defer st.mu.Unlock()
	if now.Sub(st.totalAt) < time.Minute {
		return st.total
	}
	var n int
	if err := m.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(TABLE_ROWS),0) FROM information_schema.TABLES
		WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('ed3k_sources','ed3k_keywords','ed3k_notes')`).Scan(&n); err == nil {
		st.total, st.totalAt = n, now
	}
	return st.total
}

// ed3kRotate replaces the paging secret once it is 24 h old and recomputes the
// page keys. Only the instance whose UPDATE wins does the rekeying.
func (m *MySQLEngine) ed3kRotate(ctx context.Context, now time.Time) error {
	var rotated int64
	if err := m.db.QueryRowContext(ctx, `SELECT rotated_at FROM ed3k_state WHERE id=1`).Scan(&rotated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if now.Sub(time.UnixMilli(rotated)) < Ed3kSecretPeriod {
		return nil
	}
	secret := ed3kNewSecret()
	res, err := m.db.ExecContext(ctx, `UPDATE ed3k_state SET secret=?, rotated_at=?, updated_at=? WHERE id=1 AND rotated_at=?`,
		secret, now.UnixMilli(), now.UTC(), rotated)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil
	}
	m.ed3kState.mu.Lock()
	m.ed3kState.secret, m.ed3kState.loadedAt = secret, now
	m.ed3kState.mu.Unlock()
	rekeys := []struct {
		table, cols string
		key         func(cols [][]byte) [32]byte
	}{
		{"ed3k_sources", "node_id", func(c [][]byte) [32]byte { return Ed3kPageKey(secret, c[0]) }},
		{"ed3k_keywords", "root, pubkey", func(c [][]byte) [32]byte { return Ed3kPageKey(secret, c[0], c[1]) }},
		{"ed3k_notes", "pubkey", func(c [][]byte) [32]byte { return Ed3kPageKey(secret, c[0]) }},
	}
	for _, rk := range rekeys {
		if err := m.ed3kRekey(ctx, rk.table, rk.cols, rk.key); err != nil {
			return err
		}
	}
	return nil
}

func (m *MySQLEngine) ed3kRekey(ctx context.Context, table, cols string, key func([][]byte) [32]byte) error {
	n := len(strings.Split(cols, ","))
	var last uint64
	for {
		rows, err := m.db.QueryContext(ctx, `SELECT id, `+cols+` FROM `+table+` WHERE id>? ORDER BY id LIMIT 1000`, last)
		if err != nil {
			return err
		}
		type upd struct {
			id  uint64
			key [32]byte
		}
		var batch []upd
		for rows.Next() {
			vals := make([][]byte, n)
			dest := []any{&last}
			for i := range vals {
				dest = append(dest, &vals[i])
			}
			if err := rows.Scan(dest...); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, upd{last, key(vals)})
		}
		rows.Close()
		if len(batch) == 0 {
			return nil
		}
		for _, u := range batch {
			if _, err := m.db.ExecContext(ctx, `UPDATE `+table+` SET page_key=? WHERE id=?`, u.key[:], u.id); err != nil {
				return err
			}
		}
		if len(batch) < 1000 {
			return nil
		}
	}
}

// ed3kExpireKeywords deletes one batch of expired keyword records and lowers the
// file count of each target whose file lost its last record.
func (m *MySQLEngine) ed3kExpireKeywords(ctx context.Context, nowMs int64) (int, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT id, target, root FROM ed3k_keywords WHERE expires<=? LIMIT ?`, nowMs, ed3kExpireBatch)
	if err != nil {
		return 0, err
	}
	type file struct{ target, root string }
	var ids []any
	files := map[file]bool{}
	for rows.Next() {
		var id uint64
		var target, root []byte
		if err := rows.Scan(&id, &target, &root); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
		files[file{string(target), string(root)}] = true
	}
	rows.Close()
	if len(ids) == 0 {
		return 0, rows.Err()
	}
	if _, err := m.db.ExecContext(ctx, `DELETE FROM ed3k_keywords WHERE id IN (?`+strings.Repeat(",?", len(ids)-1)+`)`, ids...); err != nil {
		return 0, err
	}
	for f := range files {
		err := m.ed3kTx(ctx, "ed3k expire keyword file", func(tx *sql.Tx) error {
			var tid uint64
			if err := tx.QueryRowContext(ctx, `SELECT id FROM ed3k_targets WHERE kind=? AND target=? FOR UPDATE`,
				Ed3kKindKeyword, []byte(f.target)).Scan(&tid); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return nil
				}
				return err
			}
			var left int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ed3k_keywords WHERE target=? AND root=?`,
				[]byte(f.target), []byte(f.root)).Scan(&left); err != nil {
				return err
			}
			if left > 0 {
				return nil
			}
			_, err := tx.ExecContext(ctx, `UPDATE ed3k_targets SET files=GREATEST(files,1)-1 WHERE id=?`, tid)
			return err
		})
		if err != nil {
			return len(ids), err
		}
	}
	return len(ids), nil
}

// ed3kLockTarget locks the target row for the transaction, creating it when the
// sweeper removed it since ed3kEnsureTarget. It returns the row's id and the
// target's file count.
func ed3kLockTarget(ctx context.Context, tx *sql.Tx, kind uint8, target [16]byte, now time.Time) (uint64, int, error) {
	var id uint64
	var files int
	err := tx.QueryRowContext(ctx, `SELECT id, files FROM ed3k_targets WHERE kind=? AND target=? FOR UPDATE`, kind, target[:]).Scan(&id, &files)
	if !errors.Is(err, sql.ErrNoRows) {
		return id, files, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT IGNORE INTO ed3k_targets (kind,target,files,full_at,created_at,updated_at) VALUES (?,?,0,0,?,?)`,
		kind, target[:], now.UTC(), now.UTC()); err != nil {
		return 0, 0, err
	}
	err = tx.QueryRowContext(ctx, `SELECT id, files FROM ed3k_targets WHERE kind=? AND target=? FOR UPDATE`, kind, target[:]).Scan(&id, &files)
	return id, files, err
}

// ed3kAddressTotals counts the records of a host and of a site over all targets
// and kinds (§11).
func ed3kAddressTotals(ctx context.Context, tx *sql.Tx, host, site string) (int, int, error) {
	var h, s int
	err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM ed3k_sources WHERE host=?) + (SELECT COUNT(*) FROM ed3k_keywords WHERE host=?) + (SELECT COUNT(*) FROM ed3k_notes WHERE host=?),
		(SELECT COUNT(*) FROM ed3k_sources WHERE site=?) + (SELECT COUNT(*) FROM ed3k_keywords WHERE site=?) + (SELECT COUNT(*) FROM ed3k_notes WHERE site=?)`,
		host, host, host, site, site, site).Scan(&h, &s)
	return h, s, err
}

// ed3kKeywordWhere builds the WHERE clause of a keyword search.
func ed3kKeywordWhere(target [16]byte, q Ed3kQuery, now time.Time) (string, []any) {
	where := []string{"target=?", "expires>?"}
	args := []any{target[:], now.UnixMilli()}
	if q.MinSize > 0 {
		where, args = append(where, "size>=?"), append(args, q.MinSize)
	}
	if q.MaxSize > 0 {
		where, args = append(where, "size<=?"), append(args, q.MaxSize)
	}
	if q.MinSources > 0 {
		where, args = append(where, "sources>=?"), append(args, q.MinSources)
	}
	if q.Ext != "" {
		where, args = append(where, "ext=?"), append(args, q.Ext)
	}
	for _, w := range q.All {
		where, args = append(where, "words LIKE ?"), append(args, ed3kWordPattern(w))
	}
	for _, w := range q.None {
		where, args = append(where, "words NOT LIKE ?"), append(args, ed3kWordPattern(w))
	}
	return strings.Join(where, " AND "), args
}

// ed3kWordList stores words as 0x1F w1 0x1F w2 … 0x1F, so that a word matches
// only whole: LIKE '%\x1Fword\x1F%'. A word holds no 0x1F, which is a control
// character and never part of a word (§10.1).
func ed3kWordList(words []string) string {
	if len(words) == 0 {
		return "\x1f"
	}
	return "\x1f" + strings.Join(words, "\x1f") + "\x1f"
}

func ed3kParseWordList(s string) []string {
	s = strings.Trim(s, "\x1f")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x1f")
}

func ed3kWordPattern(w string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%\x1f" + r.Replace(w) + "\x1f%"
}

func ed3kEP4(r Ed3kSource) any {
	if !r.EP4.IsValid() {
		return nil
	}
	return ident.EncodeEndpoint(r.EP4)
}

func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func (m *MySQLEngine) ed3kPageSecret(ctx context.Context, now time.Time) ([]byte, error) {
	return m.ed3kSecret(ctx, now, false)
}

const ed3kMySQLKeywordCols = `target, root, pubkey, publisher_id, signed, words, ext, size, sources, ed2k, host, site, via_signer, stored_at, expires`

func (m *MySQLEngine) ed3kFileKeywords(ctx context.Context, target [16]byte, root [32]byte) ([]Ed3kKeyword, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT `+ed3kMySQLKeywordCols+` FROM ed3k_keywords WHERE target=? AND root=?`, target[:], root[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ed3kKeyword
	for rows.Next() {
		r, err := scanEd3kKeyword(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (m *MySQLEngine) ed3kEachKeyword(ctx context.Context, now time.Time, fn func(Ed3kKeyword) error) error {
	var last uint64
	for {
		rows, err := m.db.QueryContext(ctx, `SELECT id, `+ed3kMySQLKeywordCols+` FROM ed3k_keywords
			WHERE id>? AND expires>? ORDER BY id LIMIT 1000`, last, now.UnixMilli())
		if err != nil {
			return err
		}
		var batch []Ed3kKeyword
		for rows.Next() {
			r, err := scanEd3kKeywordWithID(rows, &last)
			if err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, r)
		}
		rows.Close()
		for _, r := range batch {
			if err := fn(r); err != nil {
				return err
			}
		}
		if len(batch) < 1000 {
			return rows.Err()
		}
	}
}

// Ed3kTarget reports a target's file count (KEYWORD) and spill.
func (m *MySQLEngine) Ed3kTarget(ctx context.Context, kind uint8, target [16]byte, now time.Time) (int, bool, error) {
	if err := m.ensureDB(); err != nil {
		return 0, false, err
	}
	var files int
	var fullAt int64
	err := m.db.QueryRowContext(ctx, `SELECT files, full_at FROM ed3k_targets WHERE kind=? AND target=?`,
		kind, target[:]).Scan(&files, &fullAt)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if kind != Ed3kKindKeyword {
		files = 0
	}
	return files, fullAt > 0 && now.Sub(time.UnixMilli(fullAt)) < ed3kFullMemory(kind), err
}

type rowScanner2 interface{ Scan(dest ...any) error }

func scanEd3kKeyword(rows rowScanner2) (Ed3kKeyword, error) {
	return scanEd3kKeywordWithID(rows, nil)
}

func scanEd3kKeywordWithID(rows rowScanner2, id *uint64) (Ed3kKeyword, error) {
	var r Ed3kKeyword
	var target, root, pub, pid, ed2k []byte
	var words string
	var stored, exp int64
	dest := []any{&target, &root, &pub, &pid, &r.Signed, &words, &r.Ext, &r.Size, &r.Sources, &ed2k,
		&r.Host, &r.Site, &r.ViaSigner, &stored, &exp}
	if id != nil {
		dest = append([]any{id}, dest...)
	}
	if err := rows.Scan(dest...); err != nil {
		return r, err
	}
	copy(r.Target[:], target)
	copy(r.Root[:], root)
	copy(r.PubKey[:], pub)
	copy(r.PublisherID[:], pid)
	r.ED2K = ed2k
	r.Words = ed3kParseWordList(words)
	r.StoredAt, r.Expires = time.UnixMilli(stored), time.UnixMilli(exp)
	return r, nil
}
