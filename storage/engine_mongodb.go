package storage

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"enode/logging"
)

var (
	ErrMongoConfigInvalid  = errors.New("mongodb config is invalid")
	ErrMongoNotInitialized = errors.New("mongodb engine is not initialized")
)

type MongoConfig struct {
	URI      string
	Database string
	Timeout  time.Duration
}

type MongoDBEngine struct {
	cfg     MongoConfig
	client  *mongo.Client
	db      *mongo.Database
	servers []Server
}

func NewMongoDBEngine(cfg MongoConfig) (*MongoDBEngine, error) {
	if cfg.URI == "" || cfg.Database == "" {
		return nil, ErrMongoConfigInvalid
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &MongoDBEngine{cfg: cfg}, nil
}

func (m *MongoDBEngine) ensureDB() error {
	if m.db == nil {
		return ErrMongoNotInitialized
	}
	return nil
}

func (m *MongoDBEngine) Init() error {
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(m.cfg.URI))
	if err != nil {
		return err
	}
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return err
	}
	db := client.Database(m.cfg.Database)
	m.client = client
	m.db = db

	if _, err := db.Collection("clients").UpdateMany(ctx, bson.M{}, bson.M{"$set": bson.M{"online": false}}); err != nil {
		logging.Errorf("mongodb reset clients online flag failed: %v", err)
	}
	if _, err := db.Collection("sources").UpdateMany(ctx, bson.M{}, bson.M{"$set": bson.M{"online": false}}); err != nil {
		logging.Errorf("mongodb reset sources online flag failed: %v", err)
	}

	_, _ = db.Collection("clients").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "hash", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	// Backs both the online count and the stale-row sweep. Composite for the same
	// reason as the MySQL side: `online` leads so the count uses it, and
	// time_login covers the sweep's second predicate.
	_, _ = db.Collection("clients").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "online", Value: 1}, {Key: "time_login", Value: 1}},
	})
	_, _ = db.Collection("sources").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "online", Value: 1}, {Key: "time_offer", Value: 1}},
	})
	_, _ = db.Collection("files").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "hash", Value: 1}, {Key: "size", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	// Source identity is (file, client hash). Assumes an empty database: there is
	// no drop of the previous client_ed2k index and no backfill of client_hash,
	// so an existing deployment would need its sources collection cleared.
	_, _ = db.Collection("sources").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "file_hash", Value: 1}, {Key: "file_size", Value: 1}, {Key: "client_hash", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	_, _ = db.Collection("sources").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "file_hash", Value: 1}, {Key: "file_size", Value: 1}}},
		{Keys: bson.D{{Key: "name", Value: "text"}}},
		// Backs the regex fallback in mongoNameRegexFilter, which runs whenever a
		// text term cannot be hoisted into the $text stage.
		{Keys: bson.D{{Key: "name", Value: 1}}},
		{Keys: bson.D{{Key: "type", Value: 1}}},
		{Keys: bson.D{{Key: "ext", Value: 1}}},
		{Keys: bson.D{{Key: "codec", Value: 1}}},
		{Keys: bson.D{{Key: "bitrate", Value: 1}}},
		{Keys: bson.D{{Key: "length", Value: 1}}},
		{Keys: bson.D{{Key: "file_size", Value: 1}}},
	})
	_, _ = db.Collection("files").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "sources", Value: 1}}},
		{Keys: bson.D{{Key: "completed", Value: 1}}},
	})
	return nil
}

func (m *MongoDBEngine) Close() error {
	if m.client == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	return m.client.Disconnect(ctx)
}

func (m *MongoDBEngine) ClientsCount() int {
	if err := m.ensureDB(); err != nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	n, err := m.db.Collection("clients").CountDocuments(ctx, bson.M{"online": true})
	if err != nil {
		return 0
	}
	return int(n)
}

func (m *MongoDBEngine) IsConnected(info ClientInfo) bool {
	if err := m.ensureDB(); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	n, err := m.db.Collection("clients").CountDocuments(ctx, bson.M{"hash": info.Hash, "online": true})
	return err == nil && n > 0
}

func (m *MongoDBEngine) Connect(info ClientInfo) (uint64, error) {
	if err := m.ensureDB(); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	doc := bson.M{
		"hash":           info.Hash,
		"id_ed2k":        info.ID,
		"ipv4":           info.IPv4,
		"port":           info.Port,
		"crypt_options":  int32(info.CryptOptions),
		"ipv6":           nullableIPv6(info.IPv6),
		"ipv6_reachable": info.IPv6Reachable,
		"online":         true,
		"time_login":     time.Now(),
	}
	_, err := m.db.Collection("clients").UpdateOne(
		ctx,
		bson.M{"hash": info.Hash},
		bson.M{"$set": doc},
		options.UpdateOne().SetUpsert(true),
	)
	if err != nil {
		return 0, err
	}
	var got struct {
		IDEd2K uint32 `bson:"id_ed2k"`
	}
	if err := m.db.Collection("clients").FindOne(ctx, bson.M{"hash": info.Hash}).Decode(&got); err != nil {
		return 0, err
	}
	return uint64(got.IDEd2K), nil
}

func (m *MongoDBEngine) Disconnect(info ClientInfo) {
	if err := m.ensureDB(); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	// Match on the user hash, not the ed2k ID. An ID is reassigned to a different
	// user once the address is recycled, so an ID-keyed update could flip the
	// wrong client offline and would miss the rows of a client that reconnected
	// on a new address. MySQL uses the stable clients.id for the same reason.
	if len(info.Hash) == 0 {
		logging.Errorf("mongodb disconnect called without a client hash (ed2k=%d)", info.ID)
		return
	}
	// time_login is refreshed here so it means "last state change", matching
	// MySQL, where the column is declared ON UPDATE CURRENT_TIMESTAMP and so is
	// bumped by this same update. Without it the two engines would expire rows at
	// different ages from the same configured TTL: Mongo would measure from last
	// *login* while MySQL measures from last *disconnect*.
	now := time.Now()
	if _, err := m.db.Collection("clients").UpdateOne(ctx, bson.M{"hash": info.Hash},
		bson.M{"$set": bson.M{"online": false, "time_login": now}}); err != nil {
		logging.Errorf("mongodb disconnect client hash=%x failed: %v", info.Hash, err)
	}
	if _, err := m.db.Collection("sources").UpdateMany(ctx, bson.M{"client_hash": info.Hash},
		bson.M{"$set": bson.M{"online": false, "time_offer": now}}); err != nil {
		logging.Errorf("mongodb disconnect sources hash=%x failed: %v", info.Hash, err)
	}
}

func (m *MongoDBEngine) FilesCount() int {
	if err := m.ensureDB(); err != nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	n, err := m.db.Collection("files").CountDocuments(ctx, bson.M{})
	if err != nil {
		return 0
	}
	return int(n)
}

func (m *MongoDBEngine) AddFile(file File, clientInfo ClientInfo) {
	if err := m.ensureDB(); err != nil {
		return
	}
	// Normalized even though MongoDB is schemaless: otherwise the two engines
	// store different type/ext values for the same offer, and a search that hits
	// on MySQL misses on MongoDB.
	file = NormalizeFile(file)
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()

	if _, err := m.db.Collection("files").UpdateOne(
		ctx,
		bson.M{"hash": file.Hash, "size": file.Size},
		bson.M{"$set": bson.M{"hash": file.Hash, "size": file.Size, "time_offer": time.Now()}},
		options.UpdateOne().SetUpsert(true),
	); err != nil {
		logging.Errorf("mongodb upsert file hash=%x size=%d failed: %v", file.Hash, file.Size, err)
		return
	}

	typ := file.Type
	if typ == "" {
		typ = GetFileType(file.Name)
	}
	// A source is identified by (file, client hash). client_ed2k is kept as the
	// client's *current* address — GetSources needs it — but it must not be part
	// of the identity: LowIDs are per-session and HighIDs follow the IP, so
	// keying on it created a fresh source document on every reconnect. The old
	// ones then matched nothing in Disconnect and stayed online forever, while
	// the $group below counted every stale duplicate. MySQL keys on
	// (id_file, id_client), where id_client resolves through UNIQUE(hash).
	src := bson.M{
		"file_hash":   file.Hash,
		"file_size":   file.Size,
		"client_hash": clientInfo.Hash,
		"client_ed2k": clientInfo.ID,
		"name":        file.Name,
		"ext":         NormalizeExt(file.Name),
		"type":        typ,
		"title":       file.Title,
		"artist":      file.Artist,
		"album":       file.Album,
		"length":      file.Runtime,
		"bitrate":     file.Bitrate,
		"codec":       file.Codec,
		"online":      true,
		"complete":    file.Completed > 0,
		"time_offer":  time.Now(),
	}
	if _, err := m.db.Collection("sources").UpdateOne(
		ctx,
		bson.M{"file_hash": file.Hash, "file_size": file.Size, "client_hash": clientInfo.Hash},
		bson.M{"$set": src},
		options.UpdateOne().SetUpsert(true),
	); err != nil {
		logging.Errorf("mongodb upsert source hash=%x client=%x failed: %v", file.Hash, clientInfo.Hash, err)
		return
	}

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"file_hash": file.Hash, "file_size": file.Size}}},
		{{Key: "$group", Value: bson.M{
			"_id":       bson.M{"file_hash": "$file_hash", "file_size": "$file_size"},
			"sources":   bson.M{"$sum": 1},
			"completed": bson.M{"$sum": bson.M{"$cond": []any{"$complete", 1, 0}}},
		}}},
	}
	cur, err := m.db.Collection("sources").Aggregate(ctx, pipeline)
	if err != nil {
		return
	}
	defer cur.Close(ctx)
	var agg []struct {
		Sources   int32 `bson:"sources"`
		Completed int32 `bson:"completed"`
	}
	if err := cur.All(ctx, &agg); err != nil || len(agg) == 0 {
		return
	}
	_, _ = m.db.Collection("files").UpdateOne(
		ctx,
		bson.M{"hash": file.Hash, "size": file.Size},
		bson.M{"$set": bson.M{
			"sources":     agg[0].Sources,
			"completed":   agg[0].Completed,
			"source_id":   clientInfo.ID,
			"source_port": clientInfo.Port,
		}},
	)
}

func (m *MongoDBEngine) GetSources(fileHash []byte, fileSize uint64) []Source {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	return m.getSourcesByFile(ctx, fileHash, fileSize)
}

func (m *MongoDBEngine) GetSourcesByHash(fileHash []byte) []Source {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	return m.lookupSources(ctx, bson.M{"file_hash": fileHash, "online": true})
}

func (m *MongoDBEngine) getSourcesByFile(ctx context.Context, fileHash []byte, fileSize uint64) []Source {
	return m.lookupSources(ctx, bson.M{"file_hash": fileHash, "file_size": fileSize, "online": true})
}

func (m *MongoDBEngine) FindByNameContains(term string) []File {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	cur, err := m.db.Collection("sources").Find(
		ctx,
		bson.M{"$text": bson.M{"$search": term}},
		options.Find().
			SetLimit(255).
			SetProjection(bson.M{"score": bson.M{"$meta": "textScore"}}).
			SetSort(bson.D{{Key: "score", Value: bson.M{"$meta": "textScore"}}}),
	)
	if err != nil {
		logging.Errorf("mongodb find by name %q failed: %v", term, err)
		return nil
	}
	defer cur.Close(ctx)
	var src []struct {
		FileHash []byte `bson:"file_hash"`
		FileSize uint64 `bson:"file_size"`
		Name     string `bson:"name"`
		Type     string `bson:"type"`
		Title    string `bson:"title"`
		Artist   string `bson:"artist"`
		Album    string `bson:"album"`
		Runtime  uint32 `bson:"length"`
		Bitrate  uint32 `bson:"bitrate"`
		Codec    string `bson:"codec"`
	}
	if err := cur.All(ctx, &src); err != nil {
		logging.Errorf("mongodb decode sources failed: %v", err)
		return nil
	}
	seen := map[string]bool{}
	var out []File
	for _, s := range src {
		key := string(s.FileHash) + ":" + strconv.FormatUint(s.FileSize, 10)
		if seen[key] {
			continue
		}
		seen[key] = true
		var fdoc struct {
			Hash       []byte `bson:"hash"`
			Size       uint64 `bson:"size"`
			Sources    uint32 `bson:"sources"`
			Completed  uint32 `bson:"completed"`
			SourceID   uint32 `bson:"source_id"`
			SourcePort uint16 `bson:"source_port"`
		}
		if err := m.db.Collection("files").FindOne(ctx, bson.M{"hash": s.FileHash, "size": s.FileSize}).Decode(&fdoc); err != nil {
			continue
		}
		out = append(out, File{
			Hash: fdoc.Hash, Name: s.Name, Size: fdoc.Size, Type: s.Type,
			Sources: fdoc.Sources, Completed: fdoc.Completed, Title: s.Title, Artist: s.Artist,
			Album: s.Album, Runtime: s.Runtime, Bitrate: s.Bitrate, Codec: s.Codec,
			SourceID: fdoc.SourceID, SourcePort: fdoc.SourcePort,
		})
	}
	return out
}

func (m *MongoDBEngine) FindBySearch(expr *SearchExpr) []File {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	if expr == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()

	// A $text match must be the very first pipeline stage, and $text is illegal
	// inside $or/$nor. So we hoist a single text leaf to stage 0 only when it sits
	// on the AND spine; anything else falls back to regex matching, which composes
	// anywhere. See hoistTextLeaf.
	textSearch, rest, hoisted := hoistTextLeaf(expr)

	filterExpr := expr
	if hoisted {
		filterExpr = rest // may be nil when the whole query was just that text leaf
	}

	var fullMatch bson.M
	if filterExpr != nil {
		// needsFile is intentionally discarded: the join below is unconditional, so
		// whether this particular filter references file.* no longer decides it.
		fullMatch, _ = mongoFilter(filterExpr)
		if fullMatch == nil {
			logging.Errorf("mongodb search: unsupported search expression, dropping query")
			return nil
		}
	}
	if !hoisted && fullMatch == nil {
		logging.Errorf("mongodb search: search expression produced no filter, dropping query")
		return nil
	}

	pipeline := mongo.Pipeline{}
	if hoisted {
		// $meta:"textScore" is captured immediately after the $text stage, before
		// any $lookup, so the score survives into $group.
		pipeline = append(pipeline,
			bson.D{{Key: "$match", Value: bson.M{"$text": bson.M{"$search": textSearch}}}},
			bson.D{{Key: "$addFields", Value: bson.M{"_textScore": bson.M{"$meta": "textScore"}}}},
		)
	}
	if sourceMatch := mongoSourceConjunctFilter(filterExpr); sourceMatch != nil {
		pipeline = append(pipeline, bson.D{{Key: "$match", Value: sourceMatch}})
	}
	// Always join the files document. The denormalized counters live there
	// (files.sources/completed/source_id/source_port), and every result row carries
	// them, so the group below reads $file.* unconditionally. Gating this on
	// "does the filter need file.*" left a plain text search with no $file at all,
	// which is why every such result reported Sources:0 / Completed:0. $unwind
	// without preserveNullAndEmptyArrays drops a source with no matching file —
	// which cannot happen (AddFile upserts the file before the source) and matches
	// the MySQL engine's INNER JOIN files.
	pipeline = append(pipeline,
		bson.D{{
			Key: "$lookup", Value: bson.M{
				"from": "files",
				"let":  bson.M{"h": "$file_hash", "s": "$file_size"},
				"pipeline": mongo.Pipeline{
					bson.D{{Key: "$match", Value: bson.M{
						"$expr": bson.M{
							"$and": []bson.M{
								{"$eq": []any{"$hash", "$$h"}},
								{"$eq": []any{"$size", "$$s"}},
							},
						},
					}}},
				},
				"as": "file",
			},
		}},
		bson.D{{Key: "$unwind", Value: "$file"}},
	)
	if fullMatch != nil {
		pipeline = append(pipeline, bson.D{{Key: "$match", Value: fullMatch}})
	}

	group := bson.M{
		"_id":         bson.M{"hash": "$file_hash", "size": "$file_size"},
		"hash":        bson.M{"$first": "$file_hash"},
		"size":        bson.M{"$first": "$file_size"},
		"name":        bson.M{"$first": "$name"},
		"type":        bson.M{"$first": "$type"},
		"title":       bson.M{"$first": "$title"},
		"artist":      bson.M{"$first": "$artist"},
		"album":       bson.M{"$first": "$album"},
		"runtime":     bson.M{"$first": "$length"},
		"bitrate":     bson.M{"$first": "$bitrate"},
		"codec":       bson.M{"$first": "$codec"},
		"sources":     bson.M{"$first": "$file.sources"},
		"completed":   bson.M{"$first": "$file.completed"},
		"source_id":   bson.M{"$first": "$file.source_id"},
		"source_port": bson.M{"$first": "$file.source_port"},
	}
	// Only carry a relevance score when a $text stage actually produced one;
	// referencing $meta without it fails the whole aggregation.
	if hoisted {
		group["score"] = bson.M{"$first": "$_textScore"}
	}
	pipeline = append(pipeline, bson.D{{Key: "$group", Value: group}})

	if hoisted {
		pipeline = append(pipeline, bson.D{{Key: "$sort", Value: bson.M{"score": -1}}})
	} else {
		pipeline = append(pipeline, bson.D{{Key: "$sort", Value: bson.M{"sources": -1}}})
	}
	pipeline = append(pipeline,
		bson.D{{Key: "$limit", Value: MaxSearchResults}},
	)

	cur, err := m.db.Collection("sources").Aggregate(ctx, pipeline, options.Aggregate().SetAllowDiskUse(true))
	if err != nil {
		logging.Errorf("mongodb search aggregate failed: %v", err)
		return nil
	}
	defer cur.Close(ctx)

	var out []File
	for cur.Next(ctx) {
		var doc struct {
			Hash       []byte  `bson:"hash"`
			Size       uint64  `bson:"size"`
			Name       string  `bson:"name"`
			Type       string  `bson:"type"`
			Title      string  `bson:"title"`
			Artist     string  `bson:"artist"`
			Album      string  `bson:"album"`
			Runtime    uint32  `bson:"runtime"`
			Bitrate    uint32  `bson:"bitrate"`
			Codec      string  `bson:"codec"`
			Sources    uint32  `bson:"sources"`
			Completed  uint32  `bson:"completed"`
			SourceID   uint32  `bson:"source_id"`
			SourcePort uint16  `bson:"source_port"`
			Score      float64 `bson:"score"`
		}
		if err := cur.Decode(&doc); err != nil {
			continue
		}
		out = append(out, File{
			Hash: doc.Hash, Name: doc.Name, Size: doc.Size, Type: doc.Type,
			Sources: doc.Sources, Completed: doc.Completed, Title: doc.Title, Artist: doc.Artist,
			Album: doc.Album, Runtime: doc.Runtime, Bitrate: doc.Bitrate, Codec: doc.Codec,
			SourceID: doc.SourceID, SourcePort: doc.SourcePort,
		})
	}
	return out
}

// mongoSourceConjunctFilter builds an optional pre-$lookup filter on the sources
// collection. It is purely an optimization: the caller always applies the complete
// filter later, so "nothing could be pushed down" must return nil, never an error.
func mongoSourceConjunctFilter(expr *SearchExpr) bson.M {
	if expr == nil {
		return nil
	}
	switch expr.Kind {
	case SearchAnd:
		l := mongoSourceConjunctFilter(expr.Left)
		r := mongoSourceConjunctFilter(expr.Right)
		if l == nil {
			return r
		}
		if r == nil {
			return l
		}
		return bson.M{"$and": []bson.M{l, r}}
	case SearchOr, SearchAndNot:
		// Neither branch is individually required, so nothing is safe to push down.
		return nil
	default:
		f, needsFile := mongoFilter(expr)
		if f == nil || needsFile {
			return nil
		}
		return f
	}
}

// mongoFilter translates a search expression into a match filter. It reports
// whether the filter needs the joined files document.
//
// Text leaves become case-insensitive regexes rather than $text: a regex composes
// inside $or/$nor, works in any pipeline stage, needs no $meta, and matches the
// substring semantics of the MySQL (LIKE '%t%') and memory (strings.Contains)
// engines. FindBySearch separately hoists a single AND-spine text leaf to a $text
// stage so the text index still gets used for the common case.
func mongoFilter(expr *SearchExpr) (bson.M, bool) {
	f, needsFile, prune := mongoFilterNode(expr)
	if prune {
		return nil, false
	}
	return f, needsFile
}

// mongoMatchNothing is a filter no document satisfies. An empty $in is the
// cheapest way to say so and stays index-friendly. It represents a real but
// unsatisfiable constraint — an all-whitespace text term — which is distinct
// from a pruned node and must not be dropped from an AND.
func mongoMatchNothing() bson.M {
	return bson.M{"_id": bson.M{"$in": bson.A{}}}
}

func isMongoMatchNothing(f bson.M) bool {
	in, ok := f["_id"].(bson.M)
	if !ok {
		return false
	}
	arr, ok := in["$in"].(bson.A)
	return ok && len(arr) == 0
}

// mongoFilterNode mirrors storage.buildSearchNode: prune reports that the node
// carries no constraint, so it is removed from the tree and its siblings
// survive. Returning nil for both "unsupported" and "matches nothing" is what
// previously let one unrecognised tag discard the whole query.
func mongoFilterNode(expr *SearchExpr) (filter bson.M, needsFile, prune bool) {
	if expr == nil {
		return nil, false, true
	}
	switch expr.Kind {
	case SearchText:
		terms := splitTerms(expr.Text)
		if len(terms) == 0 {
			return mongoMatchNothing(), false, false
		}
		return mongoNameRegexFilter(terms), false, false
	case SearchString:
		if expr.TagType == searchTypeText {
			return mongoFilterNode(&SearchExpr{Kind: SearchText, Text: expr.ValueString})
		}
		switch expr.TagType {
		case searchTypeFileType:
			return bson.M{"type": expr.ValueString}, false, false
		case searchTypeExt:
			return bson.M{"ext": expr.ValueString}, false, false
		case searchTypeCodec:
			return bson.M{"codec": expr.ValueString}, false, false
		default:
			return nil, false, true
		}
	case SearchUInt32, SearchUInt64:
		val := expr.ValueUint
		switch expr.TagType {
		case searchTypeSizeGt:
			return bson.M{"file_size": bson.M{"$gt": val}}, false, false
		case searchTypeSizeLt:
			return bson.M{"file_size": bson.M{"$lt": val}}, false, false
		case searchTypeSources:
			return bson.M{"file.sources": bson.M{"$gt": val}}, true, false
		case searchTypeBitrate:
			return bson.M{"bitrate": bson.M{"$gt": val}}, false, false
		case searchTypeDuration:
			return bson.M{"length": bson.M{"$gt": val}}, false, false
		case searchTypeComplete:
			return bson.M{"file.completed": bson.M{"$gt": val}}, true, false
		default:
			return nil, false, true
		}
	case SearchAnd, SearchOr, SearchAndNot:
		l, lNeedsFile, lPrune := mongoFilterNode(expr.Left)
		r, rNeedsFile, rPrune := mongoFilterNode(expr.Right)
		needsFile := lNeedsFile || rNeedsFile

		if expr.Kind == SearchAndNot {
			// Nothing to negate, or NOT(matches-nothing) which is unconstrained:
			// either way keep only the positive side.
			if rPrune || isMongoMatchNothing(r) {
				return l, lNeedsFile, lPrune
			}
			// A bare $nor would match nearly the whole collection.
			if lPrune {
				return nil, false, true
			}
			if isMongoMatchNothing(l) {
				return l, lNeedsFile, false
			}
			return bson.M{"$and": []bson.M{l, {"$nor": []bson.M{r}}}}, needsFile, false
		}

		if lPrune {
			return r, rNeedsFile, rPrune
		}
		if rPrune {
			return l, lNeedsFile, false
		}

		if expr.Kind == SearchOr {
			if isMongoMatchNothing(l) {
				return r, rNeedsFile, false
			}
			if isMongoMatchNothing(r) {
				return l, lNeedsFile, false
			}
			return bson.M{"$or": []bson.M{l, r}}, needsFile, false
		}

		if isMongoMatchNothing(l) || isMongoMatchNothing(r) {
			return mongoMatchNothing(), needsFile, false
		}
		return bson.M{"$and": []bson.M{l, r}}, needsFile, false
	default:
		return nil, false, true
	}
}

// CleanupStale removes offline clients and sources older than maxAge.
//
// Mirrors the MySQL sweep, including the counter recompute: files.sources is
// denormalized here too (built by a $group in AddFile), so deleting source
// documents without refreshing it leaves every affected file overstating its
// source count permanently.
func (m *MongoDBEngine) CleanupStale(maxAge time.Duration, opts CleanupOptions) (CleanupResult, error) {
	var result CleanupResult
	if err := m.ensureDB(); err != nil {
		return result, err
	}
	if maxAge <= 0 {
		return result, fmt.Errorf("cleanup: maxAge must be positive, got %s", maxAge)
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()

	cutoff := time.Now().Add(-maxAge)
	// online = false only: a long-lived session is not stale no matter how long
	// ago it logged in.
	staleClients := bson.M{"online": false, "time_login": bson.M{"$lt": cutoff}}
	staleSources := bson.M{"online": false, "time_offer": bson.M{"$lt": cutoff}}

	// The hashes of clients about to go, so their sources can be removed too.
	// Mongo has no foreign keys, so there is no cascade to rely on.
	hashes, err := m.staleClientHashes(ctx, staleClients)
	if err != nil {
		return result, err
	}

	affected, err := m.affectedFileKeys(ctx, staleSources, hashes)
	if err != nil {
		return result, err
	}

	if len(hashes) > 0 {
		res, err := m.db.Collection("sources").DeleteMany(ctx, bson.M{"client_hash": bson.M{"$in": hashes}})
		if err != nil {
			return result, err
		}
		result.Sources += int(res.DeletedCount)
	}
	res, err := m.db.Collection("sources").DeleteMany(ctx, staleSources)
	if err != nil {
		return result, err
	}
	result.Sources += int(res.DeletedCount)

	res, err = m.db.Collection("clients").DeleteMany(ctx, staleClients)
	if err != nil {
		return result, err
	}
	result.Clients = int(res.DeletedCount)

	for _, key := range affected {
		if err := m.recountFileSources(ctx, key.hash, key.size); err != nil {
			logging.Errorf("mongodb cleanup recount hash=%x size=%d failed: %v", key.hash, key.size, err)
		}
	}

	if !opts.KeepZeroSourceFiles {
		res, err = m.db.Collection("files").DeleteMany(ctx, bson.M{"sources": 0})
		if err != nil {
			return result, err
		}
		result.Files = int(res.DeletedCount)
	}
	return result, nil
}

func (m *MongoDBEngine) ServersCount() int {
	return len(m.servers)
}

func (m *MongoDBEngine) AddServer(server Server) {
	m.servers, _ = appendUniqueServer(m.servers, server)
}

func (m *MongoDBEngine) ServersAll() []Server {
	return append([]Server(nil), m.servers...)
}

// mongoNameRegexFilter matches every term against the file name, case
// insensitively. Terms are AND-ed, matching BuildSearchWhere and MatchSearchExpr.
func mongoNameRegexFilter(terms []string) bson.M {
	parts := make([]bson.M, 0, len(terms))
	for _, t := range terms {
		parts = append(parts, bson.M{"name": bson.M{"$regex": regexp.QuoteMeta(t), "$options": "i"}})
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return bson.M{"$and": parts}
}

// hoistTextLeaf reports whether the expression contains exactly one text leaf
// reachable through conjunctions only, and if so returns the $text search string
// plus the expression with that leaf removed.
//
// The restriction exists because MongoDB requires a $match containing $text to be
// the first pipeline stage and forbids $text inside $or/$nor. Anything that does
// not qualify is matched by regex instead (see mongoFilter).
//
// Known divergence: $text tokenizes and stems, so it matches whole words only,
// whereas the MySQL and memory engines do substring matching. A search for "emul"
// finds "eMule.zip" on those engines but not through this path. Terms are emitted
// as quoted phrases so that multiple terms are AND-ed; an unquoted $text search
// would OR them, which would not match the other two engines.
func hoistTextLeaf(expr *SearchExpr) (string, *SearchExpr, bool) {
	if countTextLeaves(expr) != 1 {
		return "", nil, false
	}
	return removeTextLeaf(expr)
}

func countTextLeaves(expr *SearchExpr) int {
	if expr == nil {
		return 0
	}
	switch expr.Kind {
	case SearchText:
		return 1
	case SearchString:
		if expr.TagType == searchTypeText {
			return 1
		}
		return 0
	case SearchAnd, SearchOr, SearchAndNot:
		return countTextLeaves(expr.Left) + countTextLeaves(expr.Right)
	default:
		return 0
	}
}

// textLeafSearch returns the $text search string for a text leaf, with each term
// quoted so MongoDB requires all of them rather than any of them.
func textLeafSearch(expr *SearchExpr) (string, bool) {
	if expr == nil {
		return "", false
	}
	var raw string
	switch expr.Kind {
	case SearchText:
		raw = expr.Text
	case SearchString:
		if expr.TagType != searchTypeText {
			return "", false
		}
		raw = expr.ValueString
	default:
		return "", false
	}
	terms := splitTerms(raw)
	if len(terms) == 0 {
		return "", false
	}
	quoted := make([]string, 0, len(terms))
	for _, t := range terms {
		// A stray quote would otherwise unbalance the phrase syntax.
		quoted = append(quoted, `"`+strings.ReplaceAll(t, `"`, "")+`"`)
	}
	return strings.Join(quoted, " "), true
}

// removeTextLeaf finds the first text leaf reachable through conjunctions and
// returns it together with the remaining expression. It descends the left side of
// AND NOT only: the right side is negated, so a $text there cannot be hoisted.
func removeTextLeaf(expr *SearchExpr) (string, *SearchExpr, bool) {
	if expr == nil {
		return "", nil, false
	}
	if search, ok := textLeafSearch(expr); ok {
		return search, nil, true
	}
	switch expr.Kind {
	case SearchAnd:
		if search, rest, ok := removeTextLeaf(expr.Left); ok {
			if rest == nil {
				return search, expr.Right, true
			}
			return search, &SearchExpr{Kind: SearchAnd, Left: rest, Right: expr.Right}, true
		}
		if search, rest, ok := removeTextLeaf(expr.Right); ok {
			if rest == nil {
				return search, expr.Left, true
			}
			return search, &SearchExpr{Kind: SearchAnd, Left: expr.Left, Right: rest}, true
		}
	case SearchAndNot:
		if search, rest, ok := removeTextLeaf(expr.Left); ok && rest != nil {
			return search, &SearchExpr{Kind: SearchAndNot, Left: rest, Right: expr.Right}, true
		}
		// A bare negation has no positive side left to anchor the query, so fall
		// back to regex rather than emitting a $nor-only filter.
	}
	return "", nil, false
}

// lookupSources resolves source documents to their clients in a single
// aggregation.
//
// This replaces up to 255 individual clients.FindOne round trips per call. Those
// also resolved by ed2k ID, which is reassigned when an address is recycled — so
// a stale source row could bind to whichever client currently holds that address
// and return that client's hash and port. Joining on the user hash cannot
// mis-bind, and mirrors the MySQL engine's INNER JOIN on clients.id.
func (m *MongoDBEngine) lookupSources(ctx context.Context, match bson.M) []Source {
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: match}},
		{{Key: "$sort", Value: bson.D{{Key: "online", Value: -1}, {Key: "time_offer", Value: -1}}}},
		{{Key: "$limit", Value: int64(MaxWireSources)}},
		{{Key: "$lookup", Value: bson.M{
			"from":         "clients",
			"localField":   "client_hash",
			"foreignField": "hash",
			"as":           "client",
		}}},
		{{Key: "$unwind", Value: "$client"}},
		{{Key: "$match", Value: bson.M{"client.online": true}}},
	}
	cur, err := m.db.Collection("sources").Aggregate(ctx, pipeline)
	if err != nil {
		logging.Errorf("mongodb source lookup failed (match=%v): %v", match, err)
		return nil
	}
	defer cur.Close(ctx)

	var docs []struct {
		Client struct {
			IDEd2K        uint32 `bson:"id_ed2k"`
			Port          uint16 `bson:"port"`
			Hash          []byte `bson:"hash"`
			CryptOptions  uint8  `bson:"crypt_options"`
			IPv6          []byte `bson:"ipv6"`
			IPv6Reachable bool   `bson:"ipv6_reachable"`
		} `bson:"client"`
	}
	if err := cur.All(ctx, &docs); err != nil {
		logging.Errorf("mongodb decode sources failed: %v", err)
		return nil
	}
	out := make([]Source, 0, len(docs))
	for _, d := range docs {
		out = append(out, Source{
			ID:            d.Client.IDEd2K,
			Port:          d.Client.Port,
			UserHash:      append([]byte(nil), d.Client.Hash...),
			CryptOptions:  d.Client.CryptOptions,
			IPv6:          append([]byte(nil), d.Client.IPv6...),
			IPv6Reachable: d.Client.IPv6Reachable,
		})
	}
	return out
}

// fileKey identifies a file document by its (hash, size) pair, matching the
// unique index.
type fileKey struct {
	hash []byte
	size uint64
}

// staleClientHashes lists the user hashes of the clients a sweep will delete.
// MongoDB has no foreign keys, so their source documents have to be removed
// explicitly — there is no cascade as there is on MySQL.
func (m *MongoDBEngine) staleClientHashes(ctx context.Context, filter bson.M) ([]any, error) {
	cur, err := m.db.Collection("clients").Find(ctx, filter,
		options.Find().SetProjection(bson.M{"hash": 1}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var docs []struct {
		Hash []byte `bson:"hash"`
	}
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	hashes := make([]any, 0, len(docs))
	for _, d := range docs {
		hashes = append(hashes, d.Hash)
	}
	return hashes, nil
}

// affectedFileKeys lists the files that will lose at least one source, whether
// because the source itself aged out or because its client did.
func (m *MongoDBEngine) affectedFileKeys(ctx context.Context, staleSources bson.M, staleHashes []any) ([]fileKey, error) {
	clauses := []bson.M{staleSources}
	if len(staleHashes) > 0 {
		clauses = append(clauses, bson.M{"client_hash": bson.M{"$in": staleHashes}})
	}
	cur, err := m.db.Collection("sources").Aggregate(ctx, mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"$or": clauses}}},
		{{Key: "$group", Value: bson.M{
			"_id": bson.M{"file_hash": "$file_hash", "file_size": "$file_size"},
		}}},
	})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var docs []struct {
		ID struct {
			FileHash []byte `bson:"file_hash"`
			FileSize uint64 `bson:"file_size"`
		} `bson:"_id"`
	}
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	keys := make([]fileKey, 0, len(docs))
	for _, d := range docs {
		keys = append(keys, fileKey{hash: d.ID.FileHash, size: d.ID.FileSize})
	}
	return keys, nil
}

// recountFileSources refreshes the denormalized counters for one file after a
// sweep, leaving source_id and source_port alone: a cleanup has no offering
// client, and writing zeros there would wipe the last known source address.
func (m *MongoDBEngine) recountFileSources(ctx context.Context, fileHash []byte, fileSize uint64) error {
	cur, err := m.db.Collection("sources").Aggregate(ctx, mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"file_hash": fileHash, "file_size": fileSize}}},
		{{Key: "$group", Value: bson.M{
			"_id":       nil,
			"sources":   bson.M{"$sum": 1},
			"completed": bson.M{"$sum": bson.M{"$cond": []any{"$complete", 1, 0}}},
		}}},
	})
	if err != nil {
		return err
	}
	defer cur.Close(ctx)

	var agg []struct {
		Sources   int32 `bson:"sources"`
		Completed int32 `bson:"completed"`
	}
	if err := cur.All(ctx, &agg); err != nil {
		return err
	}
	// No rows left means zero sources, not "leave it alone" — that is exactly the
	// case where a stale count would otherwise persist forever.
	var sources, completed int32
	if len(agg) > 0 {
		sources, completed = agg[0].Sources, agg[0].Completed
	}
	_, err = m.db.Collection("files").UpdateOne(ctx,
		bson.M{"hash": fileHash, "size": fileSize},
		bson.M{"$set": bson.M{"sources": sources, "completed": completed}},
	)
	return err
}
