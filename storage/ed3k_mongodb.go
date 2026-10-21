package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"enode/ed3k/ident"
)

// ed3k collections. Documents carry the default ObjectId _id, as the eD2K
// collections do; nothing outside the store refers to them. Times are Unix
// milliseconds.
const (
	collEd3kTargets  = "ed3k_targets"
	collEd3kSources  = "ed3k_sources"
	collEd3kKeywords = "ed3k_keywords"
	collEd3kNotes    = "ed3k_notes"
	collEd3kState    = "ed3k_state"
)

// ed3kTargetLease bounds how long one store holds the lock of a target; a lock
// left by a crashed instance frees itself after it.
const ed3kTargetLease = 10 * time.Second

// ed3kMongoIndexes are created by InitEd3k, never by Init, so a server without
// ed3k never grows these collections.
var ed3kMongoIndexes = []mongoIndex{
	{collection: collEd3kTargets, name: "kind_1_target_1", keys: bson.D{{Key: "kind", Value: 1}, {Key: "target", Value: 1}}, unique: true},
	{collection: collEd3kTargets, name: "full_at_1", keys: bson.D{{Key: "full_at", Value: 1}}},
	{collection: collEd3kSources, name: "target_1_node_id_1", keys: bson.D{{Key: "target", Value: 1}, {Key: "node_id", Value: 1}}, unique: true},
	{collection: collEd3kSources, name: "target_1_page_key_1", keys: bson.D{{Key: "target", Value: 1}, {Key: "page_key", Value: 1}}},
	{collection: collEd3kSources, name: "target_1_host_1", keys: bson.D{{Key: "target", Value: 1}, {Key: "host", Value: 1}}},
	{collection: collEd3kSources, name: "target_1_site_1", keys: bson.D{{Key: "target", Value: 1}, {Key: "site", Value: 1}}},
	{collection: collEd3kSources, name: "expires_1", keys: bson.D{{Key: "expires", Value: 1}}},
	{collection: collEd3kSources, name: "host_1", keys: bson.D{{Key: "host", Value: 1}}},
	{collection: collEd3kSources, name: "site_1", keys: bson.D{{Key: "site", Value: 1}}},
	{collection: collEd3kSources, name: "kept_by_1", keys: bson.D{{Key: "kept_by", Value: 1}}},
	{collection: collEd3kKeywords, name: "target_1_root_1_pubkey_1", keys: bson.D{{Key: "target", Value: 1}, {Key: "root", Value: 1}, {Key: "pubkey", Value: 1}}, unique: true},
	{collection: collEd3kKeywords, name: "target_1_page_key_1", keys: bson.D{{Key: "target", Value: 1}, {Key: "page_key", Value: 1}}},
	{collection: collEd3kKeywords, name: "target_1_pubkey_1", keys: bson.D{{Key: "target", Value: 1}, {Key: "pubkey", Value: 1}}},
	{collection: collEd3kKeywords, name: "target_1_site_1_root_1", keys: bson.D{{Key: "target", Value: 1}, {Key: "site", Value: 1}, {Key: "root", Value: 1}}},
	{collection: collEd3kKeywords, name: "expires_1", keys: bson.D{{Key: "expires", Value: 1}}},
	{collection: collEd3kKeywords, name: "host_1", keys: bson.D{{Key: "host", Value: 1}}},
	{collection: collEd3kKeywords, name: "site_1", keys: bson.D{{Key: "site", Value: 1}}},
	{collection: collEd3kKeywords, name: "ed2k_1", keys: bson.D{{Key: "ed2k", Value: 1}}},
	{collection: collEd3kNotes, name: "target_1_pubkey_1", keys: bson.D{{Key: "target", Value: 1}, {Key: "pubkey", Value: 1}}, unique: true},
	{collection: collEd3kNotes, name: "target_1_page_key_1", keys: bson.D{{Key: "target", Value: 1}, {Key: "page_key", Value: 1}}},
	{collection: collEd3kNotes, name: "target_1_host_1", keys: bson.D{{Key: "target", Value: 1}, {Key: "host", Value: 1}}},
	{collection: collEd3kNotes, name: "target_1_site_1", keys: bson.D{{Key: "target", Value: 1}, {Key: "site", Value: 1}}},
	{collection: collEd3kNotes, name: "expires_1", keys: bson.D{{Key: "expires", Value: 1}}},
	{collection: collEd3kNotes, name: "host_1", keys: bson.D{{Key: "host", Value: 1}}},
	{collection: collEd3kNotes, name: "site_1", keys: bson.D{{Key: "site", Value: 1}}},
}

// mongoEd3k is the MongoDBEngine's ed3k state: the paging secret as last read.
type mongoEd3k struct {
	mu       sync.Mutex
	secret   []byte
	loadedAt time.Time
	total    int
	totalAt  time.Time
}

type mongoEd3kSource struct {
	Target      []byte `bson:"target"`
	NodeID      []byte `bson:"node_id"`
	Peer        []byte `bson:"peer"`
	Host        string `bson:"host"`
	Site        string `bson:"site"`
	EP4         []byte `bson:"ep4,omitempty"`
	ED2K        bool   `bson:"ed2k_cap"`
	LifetimeEnd int64  `bson:"lifetime_end"`
	Expires     int64  `bson:"expires"`
	KeptBy      string `bson:"kept_by,omitempty"`
	PageKey     []byte `bson:"page_key"`
}

type mongoEd3kKeyword struct {
	Target      []byte   `bson:"target"`
	Root        []byte   `bson:"root"`
	RootTarget  []byte   `bson:"root_target"`
	PubKey      []byte   `bson:"pubkey"`
	PublisherID []byte   `bson:"publisher_id"`
	Signed      []byte   `bson:"signed"`
	SignedHash  []byte   `bson:"signed_hash"`
	Words       []string `bson:"words"`
	Ext         string   `bson:"ext"`
	Size        int64    `bson:"size"`
	Sources     int64    `bson:"sources"`
	ED2K        []byte   `bson:"ed2k,omitempty"`
	Host        string   `bson:"host"`
	Site        string   `bson:"site"`
	ViaSigner   bool     `bson:"via_signer"`
	StoredAt    int64    `bson:"stored_at"`
	Expires     int64    `bson:"expires"`
	PageKey     []byte   `bson:"page_key"`
}

type mongoEd3kNote struct {
	Target     []byte `bson:"target"`
	PubKey     []byte `bson:"pubkey"`
	Signed     []byte `bson:"signed"`
	SignedHash []byte `bson:"signed_hash"`
	Host       string `bson:"host"`
	Site       string `bson:"site"`
	Expires    int64  `bson:"expires"`
	PageKey    []byte `bson:"page_key"`
}

// InitEd3k creates the ed3k indexes and the paging secret.
func (m *MongoDBEngine) InitEd3k(ctx context.Context) error {
	if m.db == nil {
		return errors.New("mongodb not initialized")
	}
	if _, _, err := m.ensureIndexList(ctx, ed3kMongoIndexes, nil); err != nil {
		return fmt.Errorf("mongodb ed3k indexes: %w", err)
	}
	_, err := m.ed3kSecret(ctx, time.Now(), true)
	return err
}

// StoreEd3kSource stores or renews a SOURCE record.
func (m *MongoDBEngine) StoreEd3kSource(ctx context.Context, r Ed3kSource, lim Ed3kLimits, now time.Time) (Ed3kResult, error) {
	lim = lim.WithDefaults()
	secret, err := m.ed3kSecret(ctx, now, false)
	if err != nil {
		return 0, err
	}
	unlock, _, err := m.ed3kLock(ctx, Ed3kKindSource, r.Target)
	if err != nil {
		return 0, err
	}
	defer unlock()
	c := m.db.Collection(collEd3kSources)
	nowMs := now.UnixMilli()
	v := ed3kSourceView{Total: m.ed3kTotal(ctx, now)}
	var held mongoEd3kSource
	switch err := c.FindOne(ctx, bson.M{"target": r.Target[:], "node_id": r.NodeID[:]}).Decode(&held); {
	case err == nil:
		v.Held = &Ed3kSource{Host: held.Host, Site: held.Site}
	case !errors.Is(err, mongo.ErrNoDocuments):
		return 0, err
	}
	others := bson.M{"target": r.Target[:], "node_id": bson.M{"$ne": r.NodeID[:]}}
	counts := []struct {
		dst    *int
		filter bson.M
	}{
		{&v.Count, bson.M{"target": r.Target[:]}},
		{&v.HostCount, with(others, "host", r.Host)},
		{&v.SiteCount, with(others, "site", r.Site)},
	}
	for _, q := range counts {
		n, err := c.CountDocuments(ctx, q.filter)
		if err != nil {
			return 0, err
		}
		*q.dst = int(n)
	}
	ev, err := c.CountDocuments(ctx, with(others, "lifetime_end", bson.M{"$lt": nowMs}), options.Count().SetLimit(1))
	if err != nil {
		return 0, err
	}
	v.Evictable = ev > 0
	if v.HostTotal, v.SiteTotal, err = m.ed3kAddressTotals(ctx, r.Host, r.Site); err != nil {
		return 0, err
	}
	d := decideSource(v, r, lim)
	if d.Full {
		if err := m.ed3kMarkFull(ctx, Ed3kKindSource, r.Target, nowMs); err != nil {
			return 0, err
		}
	}
	if d.Result != Ed3kStored {
		return d.Result, nil
	}
	if d.Evict {
		var victim struct {
			ID bson.ObjectID `bson:"_id"`
		}
		err := c.FindOne(ctx, with(others, "lifetime_end", bson.M{"$lt": nowMs}),
			options.FindOne().SetSort(bson.D{{Key: "lifetime_end", Value: 1}}).SetProjection(bson.M{"_id": 1})).Decode(&victim)
		if err == nil {
			if _, err := c.DeleteOne(ctx, bson.M{"_id": victim.ID}); err != nil {
				return 0, err
			}
		}
	}
	page := Ed3kPageKey(secret, r.NodeID[:])
	doc := mongoEd3kSource{Target: r.Target[:], NodeID: r.NodeID[:], Peer: r.Peer, Host: r.Host, Site: r.Site,
		ED2K: r.ED2K, LifetimeEnd: r.LifetimeEnd.UnixMilli(), Expires: r.LifetimeEnd.UnixMilli(), KeptBy: r.KeptBy, PageKey: page[:]}
	if r.EP4.IsValid() {
		doc.EP4 = ident.EncodeEndpoint(r.EP4)
	}
	_, err = c.ReplaceOne(ctx, bson.M{"target": r.Target[:], "node_id": r.NodeID[:]}, doc, options.Replace().SetUpsert(true))
	if err != nil {
		return 0, err
	}
	return Ed3kStored, nil
}

// StoreEd3kKeyword stores a KEYWORD record.
func (m *MongoDBEngine) StoreEd3kKeyword(ctx context.Context, r Ed3kKeyword, lim Ed3kLimits, now time.Time, verify func() error) (Ed3kResult, error) {
	lim = lim.WithDefaults()
	secret, err := m.ed3kSecret(ctx, now, false)
	if err != nil {
		return 0, err
	}
	unlock, files, err := m.ed3kLock(ctx, Ed3kKindKeyword, r.Target)
	if err != nil {
		return 0, err
	}
	defer unlock()
	c := m.db.Collection(collEd3kKeywords)
	hash := Ed3kSignedHash(r.Signed)
	nowMs := now.UnixMilli()
	cur, err := c.Find(ctx, bson.M{"target": r.Target[:], "root": r.Root[:]})
	if err != nil {
		return 0, err
	}
	var heldDocs []mongoEd3kKeyword
	if err := cur.All(ctx, &heldDocs); err != nil {
		return 0, err
	}
	v := ed3kKeywordView{Files: files, Total: m.ed3kTotal(ctx, now)}
	for _, h := range heldDocs {
		var x ed3kHeldKeyword
		copy(x.PubKey[:], h.PubKey)
		copy(x.SignedHash[:], h.SignedHash)
		x.Site, x.Host = h.Site, h.Host
		x.StoredAt, x.Expires = time.UnixMilli(h.StoredAt), time.UnixMilli(h.Expires)
		if x.PubKey == r.PubKey && x.SignedHash == hash {
			return Ed3kOlder, nil
		}
		v.Held = append(v.Held, x)
	}
	if verify != nil {
		if err := verify(); err != nil {
			return Ed3kRejected, nil
		}
	}
	n, err := c.CountDocuments(ctx, bson.M{"target": r.Target[:], "pubkey": r.PubKey[:]})
	if err != nil {
		return 0, err
	}
	v.KeyFiles = int(n)
	roots, err := c.Distinct(ctx, "root", bson.M{"target": r.Target[:], "site": r.Site}).Raw()
	if err != nil {
		return 0, err
	}
	vals, _ := roots.Values()
	v.SiteFiles = len(vals)
	if v.HostTotal, v.SiteTotal, err = m.ed3kAddressTotals(ctx, r.Host, r.Site); err != nil {
		return 0, err
	}
	d := decideKeyword(v, r, lim)
	if d.Full {
		if err := m.ed3kMarkFull(ctx, Ed3kKindKeyword, r.Target, nowMs); err != nil {
			return 0, err
		}
	}
	if d.Result != Ed3kStored {
		return d.Result, nil
	}
	if d.Replace != nil {
		if _, err := c.DeleteOne(ctx, bson.M{"target": r.Target[:], "root": r.Root[:], "pubkey": d.Replace[:]}); err != nil {
			return 0, err
		}
	}
	page := Ed3kPageKey(secret, r.Root[:], r.PubKey[:])
	words := r.Words
	if words == nil {
		words = []string{}
	}
	doc := mongoEd3kKeyword{Target: r.Target[:], Root: r.Root[:], RootTarget: r.Root[:16], PubKey: r.PubKey[:],
		PublisherID: r.PublisherID[:], Signed: r.Signed, SignedHash: hash[:], Words: words, Ext: r.Ext,
		Size: int64(r.Size), Sources: int64(r.Sources), ED2K: r.ED2K, Host: r.Host, Site: r.Site, ViaSigner: r.ViaSigner,
		StoredAt: nowMs, Expires: r.Expires.UnixMilli(), PageKey: page[:]}
	if _, err := c.InsertOne(ctx, doc); err != nil {
		return 0, err
	}
	if len(v.Held) == 0 {
		if _, err := m.db.Collection(collEd3kTargets).UpdateOne(ctx, bson.M{"kind": Ed3kKindKeyword, "target": r.Target[:]},
			bson.M{"$inc": bson.M{"files": 1}}); err != nil {
			return 0, err
		}
	}
	return Ed3kStored, nil
}

// StoreEd3kNote stores a NOTE record.
func (m *MongoDBEngine) StoreEd3kNote(ctx context.Context, r Ed3kNote, lim Ed3kLimits, now time.Time, verify func() error) (Ed3kResult, error) {
	lim = lim.WithDefaults()
	secret, err := m.ed3kSecret(ctx, now, false)
	if err != nil {
		return 0, err
	}
	unlock, _, err := m.ed3kLock(ctx, Ed3kKindNote, r.Target)
	if err != nil {
		return 0, err
	}
	defer unlock()
	c := m.db.Collection(collEd3kNotes)
	hash := Ed3kSignedHash(r.Signed)
	v := ed3kNoteView{Total: m.ed3kTotal(ctx, now)}
	var held mongoEd3kNote
	switch err := c.FindOne(ctx, bson.M{"target": r.Target[:], "pubkey": r.PubKey[:]}).Decode(&held); {
	case err == nil:
		if string(held.SignedHash) == string(hash[:]) {
			return Ed3kOlder, nil
		}
		v.Held = &Ed3kNote{Host: held.Host, Site: held.Site, Expires: time.UnixMilli(held.Expires)}
	case !errors.Is(err, mongo.ErrNoDocuments):
		return 0, err
	}
	if verify != nil {
		if err := verify(); err != nil {
			return Ed3kRejected, nil
		}
	}
	others := bson.M{"target": r.Target[:], "pubkey": bson.M{"$ne": r.PubKey[:]}}
	for _, q := range []struct {
		dst    *int
		filter bson.M
	}{
		{&v.Count, bson.M{"target": r.Target[:]}},
		{&v.HostCount, with(others, "host", r.Host)},
		{&v.SiteCount, with(others, "site", r.Site)},
	} {
		n, err := c.CountDocuments(ctx, q.filter)
		if err != nil {
			return 0, err
		}
		*q.dst = int(n)
	}
	if v.HostTotal, v.SiteTotal, err = m.ed3kAddressTotals(ctx, r.Host, r.Site); err != nil {
		return 0, err
	}
	d := decideNote(v, r, lim)
	if d.Full {
		if err := m.ed3kMarkFull(ctx, Ed3kKindNote, r.Target, now.UnixMilli()); err != nil {
			return 0, err
		}
	}
	if d.Result != Ed3kStored {
		return d.Result, nil
	}
	page := Ed3kPageKey(secret, r.PubKey[:])
	doc := mongoEd3kNote{Target: r.Target[:], PubKey: r.PubKey[:], Signed: r.Signed, SignedHash: hash[:],
		Host: r.Host, Site: r.Site, Expires: r.Expires.UnixMilli(), PageKey: page[:]}
	_, err = c.ReplaceOne(ctx, bson.M{"target": r.Target[:], "pubkey": r.PubKey[:]}, doc, options.Replace().SetUpsert(true))
	if err != nil {
		return 0, err
	}
	return Ed3kStored, nil
}

// SearchEd3kSources pages the live sources of a target.
func (m *MongoDBEngine) SearchEd3kSources(ctx context.Context, target [16]byte, offset, limit int, now time.Time) ([]Ed3kSource, bool, error) {
	cur, err := m.db.Collection(collEd3kSources).Find(ctx,
		bson.M{"target": target[:], "expires": bson.M{"$gt": now.UnixMilli()}},
		options.Find().SetSort(bson.D{{Key: "page_key", Value: 1}}).SetSkip(int64(offset)).SetLimit(int64(limit+1)))
	if err != nil {
		return nil, false, err
	}
	var docs []mongoEd3kSource
	if err := cur.All(ctx, &docs); err != nil {
		return nil, false, err
	}
	out := make([]Ed3kSource, 0, len(docs))
	for _, d := range docs {
		s := Ed3kSource{Target: target, Peer: d.Peer, Host: d.Host, Site: d.Site, ED2K: d.ED2K,
			LifetimeEnd: time.UnixMilli(d.LifetimeEnd), KeptBy: d.KeptBy}
		copy(s.NodeID[:], d.NodeID)
		s.EP4, _, _ = ident.DecodeEndpoint(d.EP4)
		out = append(out, s)
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

// SearchEd3kKeywords pages the records of a keyword target matching q.
func (m *MongoDBEngine) SearchEd3kKeywords(ctx context.Context, target [16]byte, q Ed3kQuery, offset, limit int, now time.Time) (Ed3kKeywordPage, error) {
	var p Ed3kKeywordPage
	var t struct {
		Files  int   `bson:"files"`
		FullAt int64 `bson:"full_at"`
	}
	switch err := m.db.Collection(collEd3kTargets).FindOne(ctx, bson.M{"kind": Ed3kKindKeyword, "target": target[:]}).Decode(&t); {
	case errors.Is(err, mongo.ErrNoDocuments):
		return p, nil
	case err != nil:
		return p, err
	}
	p.Files = t.Files
	p.Spill = t.FullAt > 0 && now.Sub(time.UnixMilli(t.FullAt)) < ed3kFullMemory(Ed3kKindKeyword)
	cur, err := m.db.Collection(collEd3kKeywords).Find(ctx, ed3kMongoKeywordFilter(target, q, now),
		options.Find().SetSort(bson.D{{Key: "page_key", Value: 1}}).SetSkip(int64(offset)).SetLimit(int64(limit+1)))
	if err != nil {
		return p, err
	}
	var docs []mongoEd3kKeyword
	if err := cur.All(ctx, &docs); err != nil {
		return p, err
	}
	for _, d := range docs {
		r := Ed3kKeyword{Target: target, Signed: d.Signed, Words: d.Words, Ext: d.Ext, Size: uint64(d.Size),
			Sources: uint32(d.Sources), ED2K: d.ED2K, Host: d.Host, Site: d.Site, ViaSigner: d.ViaSigner,
			StoredAt: time.UnixMilli(d.StoredAt), Expires: time.UnixMilli(d.Expires)}
		copy(r.Root[:], d.Root)
		copy(r.PubKey[:], d.PubKey)
		copy(r.PublisherID[:], d.PublisherID)
		p.Records = append(p.Records, r)
	}
	if len(p.Records) > limit {
		p.Records, p.More = p.Records[:limit], true
	}
	return p, nil
}

// SearchEd3kNotes pages the notes of a file target.
func (m *MongoDBEngine) SearchEd3kNotes(ctx context.Context, target [16]byte, offset, limit int, now time.Time) ([]Ed3kNote, bool, error) {
	cur, err := m.db.Collection(collEd3kNotes).Find(ctx,
		bson.M{"target": target[:], "expires": bson.M{"$gt": now.UnixMilli()}},
		options.Find().SetSort(bson.D{{Key: "page_key", Value: 1}}).SetSkip(int64(offset)).SetLimit(int64(limit+1)))
	if err != nil {
		return nil, false, err
	}
	var docs []mongoEd3kNote
	if err := cur.All(ctx, &docs); err != nil {
		return nil, false, err
	}
	out := make([]Ed3kNote, 0, len(docs))
	for _, d := range docs {
		n := Ed3kNote{Target: target, Signed: d.Signed, Host: d.Host, Site: d.Site, Expires: time.UnixMilli(d.Expires)}
		copy(n.PubKey[:], d.PubKey)
		out = append(out, n)
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

// KeepEd3kSources extends the records kept by a live connection.
func (m *MongoDBEngine) KeepEd3kSources(ctx context.Context, keptBy string, until time.Time) error {
	_, err := m.db.Collection(collEd3kSources).UpdateMany(ctx,
		bson.M{"kept_by": keptBy, "expires": bson.M{"$lt": until.UnixMilli()}},
		bson.M{"$set": bson.M{"expires": until.UnixMilli()}})
	return err
}

// ReleaseEd3kSources ends the keeping of a closed connection.
func (m *MongoDBEngine) ReleaseEd3kSources(ctx context.Context, keptBy string) error {
	_, err := m.db.Collection(collEd3kSources).UpdateMany(ctx, bson.M{"kept_by": keptBy},
		bson.A{bson.M{"$set": bson.M{"expires": "$lifetime_end"}}, bson.M{"$unset": "kept_by"}})
	return err
}

// ExpireEd3k deletes what has expired and rotates the paging secret.
func (m *MongoDBEngine) ExpireEd3k(ctx context.Context, now time.Time) (int, error) {
	nowMs := now.UnixMilli()
	total := 0
	for _, coll := range []string{collEd3kSources, collEd3kNotes} {
		res, err := m.db.Collection(coll).DeleteMany(ctx, bson.M{"expires": bson.M{"$lte": nowMs}})
		if err != nil {
			return total, err
		}
		total += int(res.DeletedCount)
	}
	n, err := m.ed3kExpireKeywords(ctx, nowMs)
	total += n
	if err != nil {
		return total, err
	}
	cutoff := now.Add(-ed3kFullMemory(Ed3kKindKeyword)).UnixMilli()
	targets := m.db.Collection(collEd3kTargets)
	if _, err := targets.DeleteMany(ctx, bson.M{"kind": Ed3kKindKeyword, "files": bson.M{"$lte": 0}, "full_at": bson.M{"$lt": cutoff},
		"lock_until": bson.M{"$lt": time.Now().UnixMilli()}}); err != nil {
		return total, err
	}
	for kind, coll := range map[uint8]string{Ed3kKindSource: collEd3kSources, Ed3kKindNote: collEd3kNotes} {
		cur, err := targets.Find(ctx, bson.M{"kind": kind, "full_at": bson.M{"$lt": cutoff}}, options.Find().SetLimit(1000))
		if err != nil {
			return total, err
		}
		var docs []struct {
			ID     bson.ObjectID `bson:"_id"`
			Target []byte        `bson:"target"`
		}
		if err := cur.All(ctx, &docs); err != nil {
			return total, err
		}
		for _, d := range docs {
			n, err := m.db.Collection(coll).CountDocuments(ctx, bson.M{"target": d.Target}, options.Count().SetLimit(1))
			if err != nil {
				return total, err
			}
			if n == 0 {
				targets.DeleteOne(ctx, bson.M{"_id": d.ID, "lock_until": bson.M{"$lt": time.Now().UnixMilli()}})
			}
		}
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
func (m *MongoDBEngine) Ed3kBridge(ctx context.Context, ed2k [16]byte, limit int, now time.Time) ([]Ed3kBridgeSource, error) {
	nowMs := now.UnixMilli()
	cur, err := m.db.Collection(collEd3kKeywords).Find(ctx, bson.M{"ed2k": ed2k[:], "expires": bson.M{"$gt": nowMs}},
		options.Find().SetProjection(bson.M{"root_target": 1, "publisher_id": 1}).SetLimit(int64(limit*4)))
	if err != nil {
		return nil, err
	}
	var kws []mongoEd3kKeyword
	if err := cur.All(ctx, &kws); err != nil {
		return nil, err
	}
	var out []Ed3kBridgeSource
	seen := map[string]bool{}
	for _, k := range kws {
		if len(out) >= limit || seen[string(k.PublisherID)] {
			continue
		}
		var s mongoEd3kSource
		err := m.db.Collection(collEd3kSources).FindOne(ctx, bson.M{"target": k.RootTarget, "node_id": k.PublisherID,
			"ed2k_cap": true, "ep4": bson.M{"$exists": true}, "expires": bson.M{"$gt": nowMs}}).Decode(&s)
		if errors.Is(err, mongo.ErrNoDocuments) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var b Ed3kBridgeSource
		copy(b.NodeID[:], s.NodeID)
		if b.EP4, _, err = ident.DecodeEndpoint(s.EP4); err != nil || !b.EP4.IsValid() {
			continue
		}
		seen[string(k.PublisherID)] = true
		out = append(out, b)
	}
	return out, nil
}

// Ed3kStats counts the records.
func (m *MongoDBEngine) Ed3kStats(ctx context.Context, now time.Time) (Ed3kStats, error) {
	var st Ed3kStats
	for _, q := range []struct {
		dst    *int
		coll   string
		filter bson.M
	}{
		{&st.Sources, collEd3kSources, bson.M{}},
		{&st.Keywords, collEd3kKeywords, bson.M{}},
		{&st.Notes, collEd3kNotes, bson.M{}},
		{&st.Kept, collEd3kSources, bson.M{"kept_by": bson.M{"$exists": true}, "lifetime_end": bson.M{"$lt": now.UnixMilli()}}},
	} {
		n, err := m.db.Collection(q.coll).CountDocuments(ctx, q.filter)
		if err != nil {
			return st, err
		}
		*q.dst = int(n)
	}
	return st, nil
}

// ed3kLock takes the lease of a target, creating its document when missing, and
// returns the release and the target's file count. Stores of one target from
// every instance on the database go through it one at a time.
func (m *MongoDBEngine) ed3kLock(ctx context.Context, kind uint8, target [16]byte) (func(), int, error) {
	owner := make([]byte, 8)
	rand.Read(owner)
	token := hex.EncodeToString(owner)
	targets := m.db.Collection(collEd3kTargets)
	delay := 2 * time.Millisecond
	for {
		wall := time.Now().UnixMilli()
		var doc struct {
			Files int `bson:"files"`
		}
		err := targets.FindOneAndUpdate(ctx,
			bson.M{"kind": kind, "target": target[:], "$or": bson.A{
				bson.M{"lock_until": bson.M{"$lt": wall}}, bson.M{"lock_until": bson.M{"$exists": false}}}},
			bson.M{"$set": bson.M{"lock_until": wall + ed3kTargetLease.Milliseconds(), "lock_owner": token},
				"$setOnInsert": bson.M{"files": 0, "full_at": int64(0)}},
			options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)).Decode(&doc)
		if err == nil {
			release := func() {
				targets.UpdateOne(context.Background(), bson.M{"kind": kind, "target": target[:], "lock_owner": token},
					bson.M{"$set": bson.M{"lock_until": int64(0)}})
			}
			return release, doc.Files, nil
		}
		if !mongo.IsDuplicateKeyError(err) {
			return nil, 0, err
		}
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, 100*time.Millisecond)
	}
}

func (m *MongoDBEngine) ed3kMarkFull(ctx context.Context, kind uint8, target [16]byte, nowMs int64) error {
	_, err := m.db.Collection(collEd3kTargets).UpdateOne(ctx, bson.M{"kind": kind, "target": target[:]},
		bson.M{"$set": bson.M{"full_at": nowMs}})
	return err
}

func (m *MongoDBEngine) ed3kAddressTotals(ctx context.Context, host, site string) (int, int, error) {
	var h, s int
	for _, coll := range []string{collEd3kSources, collEd3kKeywords, collEd3kNotes} {
		n, err := m.db.Collection(coll).CountDocuments(ctx, bson.M{"host": host})
		if err != nil {
			return 0, 0, err
		}
		h += int(n)
		if n, err = m.db.Collection(coll).CountDocuments(ctx, bson.M{"site": site}); err != nil {
			return 0, 0, err
		}
		s += int(n)
	}
	return h, s, nil
}

// ed3kTotal is the number of records held, from the collections' estimated
// counts, refreshed at most once a minute.
func (m *MongoDBEngine) ed3kTotal(ctx context.Context, now time.Time) int {
	st := &m.ed3kState
	st.mu.Lock()
	defer st.mu.Unlock()
	if now.Sub(st.totalAt) < time.Minute {
		return st.total
	}
	n := 0
	for _, coll := range []string{collEd3kSources, collEd3kKeywords, collEd3kNotes} {
		c, err := m.db.Collection(coll).EstimatedDocumentCount(ctx)
		if err != nil {
			return st.total
		}
		n += int(c)
	}
	st.total, st.totalAt = n, now
	return n
}

func (m *MongoDBEngine) ed3kSecret(ctx context.Context, now time.Time, force bool) ([]byte, error) {
	st := &m.ed3kState
	st.mu.Lock()
	defer st.mu.Unlock()
	if !force && st.secret != nil && now.Sub(st.loadedAt) < ed3kSecretReload {
		return st.secret, nil
	}
	var doc struct {
		Secret []byte `bson:"secret"`
	}
	err := m.db.Collection(collEd3kState).FindOneAndUpdate(ctx, bson.M{"_id": 1},
		bson.M{"$setOnInsert": bson.M{"secret": ed3kNewSecret(), "rotated_at": now.UnixMilli()}},
		options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)).Decode(&doc)
	if err != nil {
		return nil, err
	}
	st.secret, st.loadedAt = doc.Secret, now
	return doc.Secret, nil
}

func (m *MongoDBEngine) ed3kRotate(ctx context.Context, now time.Time) error {
	var doc struct {
		RotatedAt int64 `bson:"rotated_at"`
	}
	if err := m.db.Collection(collEd3kState).FindOne(ctx, bson.M{"_id": 1}).Decode(&doc); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil
		}
		return err
	}
	if now.Sub(time.UnixMilli(doc.RotatedAt)) < Ed3kSecretPeriod {
		return nil
	}
	secret := ed3kNewSecret()
	res, err := m.db.Collection(collEd3kState).UpdateOne(ctx, bson.M{"_id": 1, "rotated_at": doc.RotatedAt},
		bson.M{"$set": bson.M{"secret": secret, "rotated_at": now.UnixMilli()}})
	if err != nil || res.ModifiedCount != 1 {
		return err
	}
	m.ed3kState.mu.Lock()
	m.ed3kState.secret, m.ed3kState.loadedAt = secret, now
	m.ed3kState.mu.Unlock()
	rekey := []struct {
		coll   string
		fields []string
	}{
		{collEd3kSources, []string{"node_id"}},
		{collEd3kKeywords, []string{"root", "pubkey"}},
		{collEd3kNotes, []string{"pubkey"}},
	}
	for _, rk := range rekey {
		proj := bson.M{"_id": 1}
		for _, f := range rk.fields {
			proj[f] = 1
		}
		cur, err := m.db.Collection(rk.coll).Find(ctx, bson.M{}, options.Find().SetProjection(proj))
		if err != nil {
			return err
		}
		var models []mongo.WriteModel
		for cur.Next(ctx) {
			var raw bson.Raw = cur.Current
			var parts [][]byte
			for _, f := range rk.fields {
				_, b, _ := raw.Lookup(f).BinaryOK()
				parts = append(parts, b)
			}
			key := Ed3kPageKey(secret, parts...)
			models = append(models, mongo.NewUpdateOneModel().SetFilter(bson.M{"_id": raw.Lookup("_id")}).
				SetUpdate(bson.M{"$set": bson.M{"page_key": key[:]}}))
			if len(models) == 1000 {
				if _, err := m.db.Collection(rk.coll).BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false)); err != nil {
					cur.Close(ctx)
					return err
				}
				models = models[:0]
			}
		}
		cur.Close(ctx)
		if len(models) > 0 {
			if _, err := m.db.Collection(rk.coll).BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false)); err != nil {
				return err
			}
		}
	}
	return nil
}

// ed3kExpireKeywords deletes expired keyword records and lowers the file count of
// each target whose file lost its last record.
func (m *MongoDBEngine) ed3kExpireKeywords(ctx context.Context, nowMs int64) (int, error) {
	c := m.db.Collection(collEd3kKeywords)
	cur, err := c.Find(ctx, bson.M{"expires": bson.M{"$lte": nowMs}}, options.Find().SetProjection(bson.M{"target": 1, "root": 1}))
	if err != nil {
		return 0, err
	}
	type file struct{ target, root string }
	files := map[file]bool{}
	for cur.Next(ctx) {
		var d mongoEd3kKeyword
		if err := cur.Decode(&d); err != nil {
			cur.Close(ctx)
			return 0, err
		}
		files[file{string(d.Target), string(d.Root)}] = true
	}
	cur.Close(ctx)
	res, err := c.DeleteMany(ctx, bson.M{"expires": bson.M{"$lte": nowMs}})
	if err != nil {
		return 0, err
	}
	for f := range files {
		var target [16]byte
		copy(target[:], f.target)
		unlock, _, err := m.ed3kLock(ctx, Ed3kKindKeyword, target)
		if err != nil {
			return int(res.DeletedCount), err
		}
		left, err := c.CountDocuments(ctx, bson.M{"target": []byte(f.target), "root": []byte(f.root)}, options.Count().SetLimit(1))
		if err == nil && left == 0 {
			_, err = m.db.Collection(collEd3kTargets).UpdateOne(ctx,
				bson.M{"kind": Ed3kKindKeyword, "target": []byte(f.target), "files": bson.M{"$gt": 0}},
				bson.M{"$inc": bson.M{"files": -1}})
		}
		unlock()
		if err != nil {
			return int(res.DeletedCount), err
		}
	}
	return int(res.DeletedCount), nil
}

// ed3kMongoKeywordFilter is the filter of a keyword search.
func ed3kMongoKeywordFilter(target [16]byte, q Ed3kQuery, now time.Time) bson.M {
	f := bson.M{"target": target[:], "expires": bson.M{"$gt": now.UnixMilli()}}
	size := bson.M{}
	if q.MinSize > 0 {
		size["$gte"] = int64(q.MinSize)
	}
	if q.MaxSize > 0 {
		size["$lte"] = int64(q.MaxSize)
	}
	if len(size) > 0 {
		f["size"] = size
	}
	if q.MinSources > 0 {
		f["sources"] = bson.M{"$gte": int64(q.MinSources)}
	}
	if q.Ext != "" {
		f["ext"] = q.Ext
	}
	words := bson.M{}
	if len(q.All) > 0 {
		words["$all"] = q.All
	}
	if len(q.None) > 0 {
		words["$nin"] = q.None
	}
	if len(words) > 0 {
		f["words"] = words
	}
	return f
}

// with returns a copy of f with one more condition.
func with(f bson.M, key string, value any) bson.M {
	out := make(bson.M, len(f)+1)
	for k, v := range f {
		out[k] = v
	}
	out[key] = value
	return out
}

func (m *MongoDBEngine) ed3kPageSecret(ctx context.Context, now time.Time) ([]byte, error) {
	return m.ed3kSecret(ctx, now, false)
}

func (m *MongoDBEngine) ed3kFileKeywords(ctx context.Context, target [16]byte, root [32]byte) ([]Ed3kKeyword, error) {
	cur, err := m.db.Collection(collEd3kKeywords).Find(ctx, bson.M{"target": target[:], "root": root[:]})
	if err != nil {
		return nil, err
	}
	var docs []mongoEd3kKeyword
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	out := make([]Ed3kKeyword, len(docs))
	for i, d := range docs {
		out[i] = d.keyword()
	}
	return out, nil
}

func (m *MongoDBEngine) ed3kEachKeyword(ctx context.Context, now time.Time, fn func(Ed3kKeyword) error) error {
	cur, err := m.db.Collection(collEd3kKeywords).Find(ctx, bson.M{"expires": bson.M{"$gt": now.UnixMilli()}})
	if err != nil {
		return err
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		var d mongoEd3kKeyword
		if err := cur.Decode(&d); err != nil {
			return err
		}
		if err := fn(d.keyword()); err != nil {
			return err
		}
	}
	return cur.Err()
}

func (m *MongoDBEngine) ed3kKeywordTarget(ctx context.Context, target [16]byte, now time.Time) (int, bool, error) {
	var t struct {
		Files  int   `bson:"files"`
		FullAt int64 `bson:"full_at"`
	}
	err := m.db.Collection(collEd3kTargets).FindOne(ctx, bson.M{"kind": Ed3kKindKeyword, "target": target[:]}).Decode(&t)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return 0, false, nil
	}
	return t.Files, t.FullAt > 0 && now.Sub(time.UnixMilli(t.FullAt)) < ed3kFullMemory(Ed3kKindKeyword), err
}

func (d mongoEd3kKeyword) keyword() Ed3kKeyword {
	r := Ed3kKeyword{Signed: d.Signed, Words: d.Words, Ext: d.Ext, Size: uint64(d.Size), Sources: uint32(d.Sources),
		ED2K: d.ED2K, Host: d.Host, Site: d.Site, ViaSigner: d.ViaSigner,
		StoredAt: time.UnixMilli(d.StoredAt), Expires: time.UnixMilli(d.Expires)}
	copy(r.Target[:], d.Target)
	copy(r.Root[:], d.Root)
	copy(r.PubKey[:], d.PubKey)
	copy(r.PublisherID[:], d.PublisherID)
	return r
}
