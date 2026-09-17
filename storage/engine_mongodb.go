package storage

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
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

	// Its own deadline: up to six round-trips, which must not eat into what the
	// online-flag resets above have left of ctx.
	indexCtx, indexCancel := m.opContext()
	created, err := m.ensureIndexes(indexCtx)
	indexCancel()
	if len(created) > 0 {
		logging.Infof("mongodb: created indexes %s", strings.Join(created, ", "))
	}
	if err != nil {
		logging.Errorf("mongodb ensure indexes failed: %v", err)
	}
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
	m.AddFiles([]File{file}, clientInfo)
}

// AddFiles writes one client's offer as four round-trips per offerBatchSize chunk —
// a files bulk upsert, a sources bulk upsert, one aggregate and one counter bulk
// update — however many files the chunk holds. It used to be those four per file,
// once per record of every OP_OFFERFILES.
//
// Failure isolation is the same as when each file was its own set of calls. The
// bulks are unordered, so a document the server rejects fails alone and the rest
// are written; as before, a file whose upsert failed gets no source, and a source
// that failed does not move the counters. A failure that takes out a whole
// operation instead — a timeout, or a value the driver cannot encode, such as a
// size past int64 — retries that chunk file by file, as the MySQL engine does.
func (m *MongoDBEngine) AddFiles(files []File, clientInfo ClientInfo) {
	if err := m.ensureDB(); err != nil {
		return
	}
	// Normalized even though MongoDB is schemaless: otherwise the two engines
	// store different type/ext values for the same offer, and a search that hits
	// on MySQL misses on MongoDB.
	batch := prepareOfferBatch(files)
	for start := 0; start < len(batch); start += offerBatchSize {
		chunk := batch[start:min(start+offerBatchSize, len(batch))]
		err := m.addFilesChunk(chunk, clientInfo)
		if err == nil {
			continue
		}
		if len(chunk) > 1 {
			logging.Warnf("mongodb add files batch of %d client=%x failed, retrying one by one: %v",
				len(chunk), clientInfo.Hash, err)
			for _, file := range chunk {
				if err := m.addFilesChunk([]File{file}, clientInfo); err != nil {
					logMongoAddFileError(file, clientInfo, err)
				}
			}
			continue
		}
		logMongoAddFileError(chunk[0], clientInfo, err)
	}
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
	// One aggregate. This was a find of up to 255 sources followed by a files
	// FindOne per distinct file — up to 256 round-trips for one call.
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"$text": bson.M{"$search": term}}}},
		{{Key: "$addFields", Value: bson.M{"_textScore": bson.M{"$meta": "textScore"}}}},
		{{Key: "$sort", Value: bson.D{{Key: "_textScore", Value: -1}}}},
		{{Key: "$limit", Value: int64(255)}},
		{{Key: "$group", Value: mongoSearchGroup(true, false)}},
		{{Key: "$sort", Value: bson.D{{Key: "score", Value: -1}}}},
	}
	pipeline = append(pipeline, mongoFileCounterStages()...)
	cur, err := m.db.Collection("sources").Aggregate(ctx, pipeline,
		options.Aggregate().SetBatchSize(255+1))
	if err != nil {
		logging.Errorf("mongodb find by name %q failed: %v", term, err)
		return nil
	}
	defer cur.Close(ctx)
	return decodeMongoSearchFiles(ctx, cur)
}

func (m *MongoDBEngine) FindBySearch(expr *SearchExpr) []File {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	if expr == nil {
		return nil
	}
	pipeline, ok := mongoSearchPipeline(expr)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()

	// The batch holds every result the pipeline can return, so the reply ends the
	// cursor. The server's default first batch is 101 documents, which cost every
	// search with more hits than that a getMore; one more than the limit because a
	// batch the results fill exactly leaves the cursor open (see refreshFileCounters).
	cur, err := m.db.Collection("sources").Aggregate(ctx, pipeline,
		options.Aggregate().SetAllowDiskUse(true).SetBatchSize(MaxSearchResults+1))
	if err != nil {
		logging.Errorf("mongodb search aggregate failed: %v", err)
		return nil
	}
	defer cur.Close(ctx)
	return decodeMongoSearchFiles(ctx, cur)
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
	batch := opts.BatchSize
	if batch <= 0 {
		batch = DefaultCleanupBatchSize
	}

	cutoff := time.Now().Add(-maxAge)
	// online = false only: a long-lived session is not stale no matter how long
	// ago it logged in.
	staleClients := bson.M{"online": false, "time_login": bson.M{"$lt": cutoff}}
	staleSources := bson.M{"online": false, "time_offer": bson.M{"$lt": cutoff}}

	// Every operation below takes its own deadline from opContext. The sweep used to
	// share one m.cfg.Timeout across all of them, per-file recount loop included,
	// which made the real limit total round-trips × RTT: about 330 against a
	// database 30 ms away. A busy server's hourly sweep needs more than that, so it
	// aborted after the deletes and before the recount — every hour — leaving
	// files.sources overstating reality, the exact drift the recount exists to stop.

	// The hashes of clients about to go, so their sources can be removed too.
	// Mongo has no foreign keys, so there is no cascade to rely on.
	ctx, cancel := m.opContext()
	hashes, err := m.staleClientHashes(ctx, staleClients)
	cancel()
	if err != nil {
		return result, err
	}

	// Everything keyed by those hashes goes in chunks of batch. A $in of every stale
	// hash in one command stops working on the first sweep of a large database:
	// MongoDB rejects a command document past 16 MB, about half a million hashes,
	// and a sweep that fails the same way every hour never gets anywhere.
	chunks := chunkAny(hashes, batch)
	var affected []fileKey
	seen := map[offerKey]struct{}{}
	// At least one lookup even with no stale client: stale sources of live clients
	// affect files too, and are matched by the first one.
	for i := 0; i == 0 || i < len(chunks); i++ {
		var chunk []any
		var sources bson.M
		if i < len(chunks) {
			chunk = chunks[i]
		}
		if i == 0 {
			sources = staleSources
		}
		ctx, cancel = m.opContext()
		keys, err := m.affectedFileKeys(ctx, sources, chunk)
		cancel()
		if err != nil {
			return result, err
		}
		for _, key := range keys {
			k := offerKey{hash: string(key.hash), size: key.size}
			if _, dup := seen[k]; !dup {
				seen[k] = struct{}{}
				affected = append(affected, key)
			}
		}
	}

	for _, chunk := range chunks {
		// online: false, like staleClients below: a client that reconnected since its
		// hash was read has marked its sources online again, and they stay.
		ctx, cancel = m.opContext()
		res, err := m.db.Collection("sources").DeleteMany(ctx, bson.M{"client_hash": bson.M{"$in": chunk}, "online": false})
		cancel()
		if err != nil {
			return result, err
		}
		result.Sources += int(res.DeletedCount)

		// By hash as well as by staleClients: a client that went stale after its hash
		// was read would otherwise be deleted with its sources left behind.
		clients := bson.M{"hash": bson.M{"$in": chunk}}
		for k, v := range staleClients {
			clients[k] = v
		}
		ctx, cancel = m.opContext()
		res, err = m.db.Collection("clients").DeleteMany(ctx, clients)
		cancel()
		if err != nil {
			return result, err
		}
		result.Clients += int(res.DeletedCount)
	}
	ctx, cancel = m.opContext()
	res, err := m.db.Collection("sources").DeleteMany(ctx, staleSources)
	cancel()
	if err != nil {
		return result, err
	}
	result.Sources += int(res.DeletedCount)

	// Two round-trips per batch rather than per file, bounded by the same batch
	// size the MySQL engine uses for its DELETEs.
	for start := 0; start < len(affected); start += batch {
		chunk := affected[start:min(start+batch, len(affected))]
		if err := m.refreshFileCounters(chunk, nil); err != nil {
			logging.Errorf("mongodb cleanup recount files=%d failed: %v", len(chunk), err)
		}
	}

	if !opts.KeepZeroSourceFiles {
		// time_offer < cutoff, not just sources = 0: a file an offer is writing right
		// now also has sources = 0, between the offer's files upsert and its counter
		// refresh, and deleting it then left the offer's source without a file —
		// invisible to every search, which joins sources to files. The offer stamps
		// time_offer before it writes any source, so a file past the cutoff has no
		// offer in flight.
		ctx, cancel = m.opContext()
		res, err = m.db.Collection("files").DeleteMany(ctx, bson.M{"sources": 0, "time_offer": bson.M{"$lt": cutoff}})
		cancel()
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
	// The batch holds every document the pipeline can return, so the reply ends the
	// cursor: with the server's default first batch of 101, every file with more
	// online sources than that cost a getMore.
	cur, err := m.db.Collection("sources").Aggregate(ctx, sourceLookupPipeline(match),
		options.Aggregate().SetBatchSize(MaxWireSources+1))
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

// mongoWholeResultBatch asks for a read's whole result in the first reply, for reads
// whose size is not known in advance. The server still ends a batch at 16 MiB (some
// 270,000 file keys), and only then does the driver need a getMore; with the default
// first batch of 101 documents, any sweep touching more files than that needed one.
const mongoWholeResultBatch = math.MaxInt32

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
		options.Find().SetProjection(bson.M{"hash": 1}).SetBatchSize(mongoWholeResultBatch))
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
// because the source itself aged out (staleSources, when not nil) or because its
// client did (staleHashes).
func (m *MongoDBEngine) affectedFileKeys(ctx context.Context, staleSources bson.M, staleHashes []any) ([]fileKey, error) {
	var clauses []bson.M
	if staleSources != nil {
		clauses = append(clauses, staleSources)
	}
	if len(staleHashes) > 0 {
		clauses = append(clauses, bson.M{"client_hash": bson.M{"$in": staleHashes}})
	}
	if len(clauses) == 0 {
		return nil, nil
	}
	cur, err := m.db.Collection("sources").Aggregate(ctx, mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"$or": clauses}}},
		{{Key: "$group", Value: bson.M{
			"_id": bson.M{"file_hash": "$file_hash", "file_size": "$file_size"},
		}}},
	}, options.Aggregate().SetBatchSize(mongoWholeResultBatch))
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

// addFilesChunk writes at most offerBatchSize files prepared by prepareOfferBatch.
// Documents the server rejected individually are logged here; an error is returned
// only when an operation failed as a whole, which is what AddFiles retries.
func (m *MongoDBEngine) addFilesChunk(files []File, clientInfo ClientInfo) error {
	now := time.Now()

	fileModels := make([]mongo.WriteModel, len(files))
	for i, file := range files {
		fileModels[i] = mongo.NewUpdateOneModel().
			SetFilter(bson.M{"hash": file.Hash, "size": file.Size}).
			SetUpdate(bson.M{"$set": bson.M{"hash": file.Hash, "size": file.Size, "time_offer": now}}).
			SetUpsert(true)
	}
	ctx, cancel := m.opContext()
	failedFiles, err := bulkFailures(m.db.Collection("files").BulkWrite(ctx, fileModels, options.BulkWrite().SetOrdered(false)))
	cancel()
	if err != nil {
		return fmt.Errorf("upsert files: %w", err)
	}

	// A source is identified by (file, client hash). client_ed2k is kept as the
	// client's *current* address — GetSources needs it — but it must not be part
	// of the identity: LowIDs are per-session and HighIDs follow the IP, so
	// keying on it created a fresh source document on every reconnect. The old
	// ones then matched nothing in Disconnect and stayed online forever, while
	// the counter refresh counted every stale duplicate. MySQL keys on
	// (id_file, id_client), where id_client resolves through UNIQUE(hash).
	stored := make([]File, 0, len(files))
	sourceModels := make([]mongo.WriteModel, 0, len(files))
	for i, file := range files {
		if _, failed := failedFiles[i]; failed {
			continue
		}
		src := bson.M{
			"file_hash":   file.Hash,
			"file_size":   file.Size,
			"client_hash": clientInfo.Hash,
			"client_ed2k": clientInfo.ID,
			"name":        file.Name,
			"ext":         NormalizeExt(file.Name),
			"type":        file.Type,
			"title":       file.Title,
			"artist":      file.Artist,
			"album":       file.Album,
			"length":      file.Runtime,
			"bitrate":     file.Bitrate,
			"codec":       file.Codec,
			"online":      true,
			"complete":    file.Completed > 0,
			"time_offer":  now,
		}
		sourceModels = append(sourceModels, mongo.NewUpdateOneModel().
			SetFilter(bson.M{"file_hash": file.Hash, "file_size": file.Size, "client_hash": clientInfo.Hash}).
			SetUpdate(bson.M{"$set": src}).
			SetUpsert(true))
		stored = append(stored, file)
	}
	if len(sourceModels) == 0 {
		return nil
	}
	ctx, cancel = m.opContext()
	failedSources, err := bulkFailures(m.db.Collection("sources").BulkWrite(ctx, sourceModels, options.BulkWrite().SetOrdered(false)))
	cancel()
	if err != nil {
		return fmt.Errorf("upsert sources: %w", err)
	}

	keys := make([]fileKey, 0, len(stored))
	for i, file := range stored {
		if _, failed := failedSources[i]; !failed {
			keys = append(keys, fileKey{hash: file.Hash, size: file.Size})
		}
	}
	if err := m.refreshFileCounters(keys, &counterSource{ID: clientInfo.ID, Port: clientInfo.Port}); err != nil {
		return fmt.Errorf("refresh counters: %w", err)
	}
	return nil
}

// refreshFileCounters recomputes files.sources / files.completed for a set of files in
// two round-trips: one aggregate over their sources, one unordered bulk update.
//
// src stamps the offering client's address onto every file, which is what an offer
// wants. A cleanup sweep passes nil and source_id/source_port are left alone: the
// sweep has no offering client, and writing zeros would wipe the last known source
// address. A file with no source left is written as zero, not skipped — that is
// exactly the case where a stale count would otherwise persist forever.
func (m *MongoDBEngine) refreshFileCounters(keys []fileKey, src *counterSource) error {
	if len(keys) == 0 {
		return nil
	}
	hashes := make([]any, len(keys))
	for i, key := range keys {
		hashes[i] = key.hash
	}

	// Matched on file_hash alone, which leads the {file_hash, file_size} index; the
	// same hash at a size outside keys is grouped too and ignored below.
	ctx, cancel := m.opContext()
	defer cancel()
	// The batch size is set so every group arrives with the aggregate's reply. The
	// server's default first batch is 101 documents, which would cost a 200-file offer
	// a getMore. One more than len(keys), not len(keys): a batch the results fill
	// exactly leaves the cursor open, and the driver then spends a getMore learning
	// it is empty — measured on every offer, one file included. Callers bound
	// len(keys), and a group is well under 100 bytes, so this stays far inside the
	// 16 MB reply limit.
	cur, err := m.db.Collection("sources").Aggregate(ctx, mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"file_hash": bson.M{"$in": hashes}}}},
		{{Key: "$group", Value: bson.M{
			"_id":       bson.M{"file_hash": "$file_hash", "file_size": "$file_size"},
			"sources":   bson.M{"$sum": 1},
			"completed": bson.M{"$sum": bson.M{"$cond": []any{"$complete", 1, 0}}},
		}}},
	}, options.Aggregate().SetBatchSize(int32(len(keys)+1)))
	if err != nil {
		return fmt.Errorf("aggregate counters: %w", err)
	}
	var groups []struct {
		ID struct {
			FileHash []byte `bson:"file_hash"`
			FileSize uint64 `bson:"file_size"`
		} `bson:"_id"`
		Sources   int32 `bson:"sources"`
		Completed int32 `bson:"completed"`
	}
	err = cur.All(ctx, &groups)
	_ = cur.Close(ctx)
	if err != nil {
		return fmt.Errorf("decode counters: %w", err)
	}
	type counters struct{ sources, completed int32 }
	byKey := make(map[offerKey]counters, len(groups))
	for _, g := range groups {
		byKey[offerKey{hash: string(g.ID.FileHash), size: g.ID.FileSize}] = counters{g.Sources, g.Completed}
	}

	models := make([]mongo.WriteModel, len(keys))
	for i, key := range keys {
		c := byKey[offerKey{hash: string(key.hash), size: key.size}]
		set := bson.M{"sources": c.sources, "completed": c.completed}
		if src != nil {
			set["source_id"] = src.ID
			set["source_port"] = src.Port
		}
		models[i] = mongo.NewUpdateOneModel().
			SetFilter(bson.M{"hash": key.hash, "size": key.size}).
			SetUpdate(bson.M{"$set": set})
	}
	writeCtx, writeCancel := m.opContext()
	defer writeCancel()
	if _, err := m.db.Collection("files").BulkWrite(writeCtx, models, options.BulkWrite().SetOrdered(false)); err != nil {
		return fmt.Errorf("write counters: %w", err)
	}
	return nil
}

// mongoIndex is one index ensureIndexes maintains.
type mongoIndex struct {
	collection string
	// name is spelled out rather than left to the driver, and must equal what the
	// driver generates from keys (each field_value, joined by "_"). Deployments from
	// before names were explicit carry the generated name; the same keys under any
	// other name would be a conflict, not a match.
	name   string
	keys   bson.D
	unique bool
}

// mongoIndexes is every index the engine relies on.
var mongoIndexes = []mongoIndex{
	{collection: "clients", name: "hash_1", keys: bson.D{{Key: "hash", Value: 1}}, unique: true},
	// Backs both the online count and the stale-row sweep. Composite for the same
	// reason as the MySQL side: `online` leads so the count uses it, and
	// time_login covers the sweep's second predicate.
	{collection: "clients", name: "online_1_time_login_1", keys: bson.D{{Key: "online", Value: 1}, {Key: "time_login", Value: 1}}},
	{collection: "sources", name: "online_1_time_offer_1", keys: bson.D{{Key: "online", Value: 1}, {Key: "time_offer", Value: 1}}},
	{collection: "files", name: "hash_1_size_1", keys: bson.D{{Key: "hash", Value: 1}, {Key: "size", Value: 1}}, unique: true},
	// Source identity is (file, client hash). Assumes an empty database: there is
	// no drop of the previous client_ed2k index and no backfill of client_hash,
	// so an existing deployment would need its sources collection cleared.
	{collection: "sources", name: "file_hash_1_file_size_1_client_hash_1", keys: bson.D{{Key: "file_hash", Value: 1}, {Key: "file_size", Value: 1}, {Key: "client_hash", Value: 1}}, unique: true},
	// GetSources: {file_hash, file_size, online: true} newest offer first, answered
	// by an index scan that stops after MaxWireSources keys. Without it a popular
	// file's every source was read and sorted in memory on each request. It replaces
	// file_hash_1_file_size_1, which is its prefix; ensureIndexes never drops
	// anything, so a database created before keeps that one until an operator
	// removes it.
	{collection: "sources", name: "file_hash_1_file_size_1_online_1_time_offer_-1", keys: bson.D{{Key: "file_hash", Value: 1}, {Key: "file_size", Value: 1}, {Key: "online", Value: 1}, {Key: "time_offer", Value: -1}}},
	{collection: "sources", name: "name_text", keys: bson.D{{Key: "name", Value: "text"}}},
	// Backs the regex fallback in mongoNameRegexFilter, which runs whenever a
	// text term cannot be hoisted into the $text stage.
	{collection: "sources", name: "name_1", keys: bson.D{{Key: "name", Value: 1}}},
	{collection: "sources", name: "type_1", keys: bson.D{{Key: "type", Value: 1}}},
	{collection: "sources", name: "ext_1", keys: bson.D{{Key: "ext", Value: 1}}},
	{collection: "sources", name: "codec_1", keys: bson.D{{Key: "codec", Value: 1}}},
	{collection: "sources", name: "bitrate_1", keys: bson.D{{Key: "bitrate", Value: 1}}},
	{collection: "sources", name: "length_1", keys: bson.D{{Key: "length", Value: 1}}},
	{collection: "sources", name: "file_size_1", keys: bson.D{{Key: "file_size", Value: 1}}},
	// Disconnect and the stale-row sweep select sources by client hash alone. The
	// unique index above has client_hash last, so it cannot serve that, and without
	// this every disconnect and every sweep scanned the whole collection — which on a
	// large one can outlast a single operation's deadline by itself.
	{collection: "sources", name: "client_hash_1", keys: bson.D{{Key: "client_hash", Value: 1}}},
	{collection: "files", name: "sources_1", keys: bson.D{{Key: "sources", Value: 1}}},
	{collection: "files", name: "completed_1", keys: bson.D{{Key: "completed", Value: 1}}},
}

// ensureIndexes creates whichever of mongoIndexes are missing and returns their names.
//
// Init used to send every createIndexes on every start. MongoDB treats an identical
// existing index as a no-op, so nothing was rebuilt, but each call was a round-trip
// and `_, _ =` hid any conflict, which then repeated silently on every boot. Now each
// collection's index list is read once and only the absent ones are written: nothing
// in steady state, exactly the new ones after an upgrade adds one, and an index an
// operator dropped comes back on the next start.
//
// Matched by name, not by keys: listIndexes reports a text index's keys as
// {_fts: "text", _ftsx: 1}, never as the {name: "text"} it was created from.
func (m *MongoDBEngine) ensureIndexes(ctx context.Context) ([]string, error) {
	var order []string
	byCollection := map[string][]mongoIndex{}
	for _, idx := range mongoIndexes {
		if _, ok := byCollection[idx.collection]; !ok {
			order = append(order, idx.collection)
		}
		byCollection[idx.collection] = append(byCollection[idx.collection], idx)
	}

	var created []string
	var errs []error
	for _, collection := range order {
		view := m.db.Collection(collection).Indexes()
		// A collection that does not exist yet lists as empty, not as an error.
		specs, err := view.ListSpecifications(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("list %s indexes: %w", collection, err))
			continue
		}
		existing := make(map[string]struct{}, len(specs))
		for _, spec := range specs {
			existing[spec.Name] = struct{}{}
		}
		var missing []mongo.IndexModel
		var names []string
		for _, idx := range byCollection[collection] {
			if _, ok := existing[idx.name]; ok {
				continue
			}
			opts := options.Index().SetName(idx.name)
			if idx.unique {
				opts.SetUnique(true)
			}
			missing = append(missing, mongo.IndexModel{Keys: idx.keys, Options: opts})
			names = append(names, idx.name)
		}
		if len(missing) == 0 {
			continue
		}
		if _, err := view.CreateMany(ctx, missing); err != nil {
			errs = append(errs, fmt.Errorf("create %s indexes %s: %w", collection, strings.Join(names, ","), err))
			continue
		}
		for _, name := range names {
			created = append(created, collection+"."+name)
		}
	}
	return created, errors.Join(errs...)
}

// opContext bounds one database operation by the configured timeout. Per operation,
// never across a sequence: a deadline shared by several round-trips is really a
// budget on how far away the database is.
func (m *MongoDBEngine) opContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), m.cfg.Timeout)
}

// bulkFailures splits the result of an unordered BulkWrite.
//
// A BulkWriteException that names write errors means every other model was applied:
// the failed indices are logged and returned, and the error is not. Anything else —
// a timeout, a dropped connection, a document the driver could not encode, a write
// concern failure — gives no way to tell what was written, so it is returned whole
// for the caller to retry.
func bulkFailures(_ *mongo.BulkWriteResult, err error) (map[int]struct{}, error) {
	failed := map[int]struct{}{}
	if err == nil {
		return failed, nil
	}
	var bwe mongo.BulkWriteException
	if !errors.As(err, &bwe) || len(bwe.WriteErrors) == 0 || bwe.WriteConcernError != nil {
		return nil, err
	}
	for _, we := range bwe.WriteErrors {
		failed[we.Index] = struct{}{}
		logging.Errorf("mongodb bulk write rejected model %d: code=%d %s", we.Index, we.Code, we.Message)
	}
	return failed, nil
}

// logMongoAddFileError reports one file that could not be stored even on its own.
func logMongoAddFileError(file File, clientInfo ClientInfo, err error) {
	logging.Errorf("mongodb add file hash=%x size=%d client=%x name=%q type=%q failed: %v",
		file.Hash, file.Size, clientInfo.Hash, file.Name, file.Type, err)
}

// sourceLookupPipeline selects the newest MaxWireSources sources matching match and
// joins each to its client.
//
// Sorted by time_offer alone. Both callers match online: true, so the online sort
// key that used to lead ordered nothing, and without it
// file_hash_1_file_size_1_online_1_time_offer_-1 returns the documents already in
// order: MaxWireSources index keys read instead of every source of a popular file.
func sourceLookupPipeline(match bson.M) mongo.Pipeline {
	return mongo.Pipeline{
		{{Key: "$match", Value: match}},
		{{Key: "$sort", Value: bson.D{{Key: "time_offer", Value: -1}}}},
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
}

// mongoSearchPipeline builds FindBySearch's aggregation over sources: one document
// per matching file, with the counters of its files document, at most
// MaxSearchResults of them, best first. It returns false, after logging why, for an
// expression that yields no usable filter.
//
// A $text match must be the very first pipeline stage, and $text is illegal
// inside $or/$nor. So we hoist a single text leaf to stage 0 only when it sits
// on the AND spine; anything else falls back to regex matching, which composes
// anywhere. See hoistTextLeaf.
//
// Every result carries files.sources/completed/source_id/source_port, so files is
// always joined — leaving it out for a plain text search is what once made every
// such result report Sources:0. Where it is joined depends on the filter:
//   - A sources or completed term reads the files document, so every candidate
//     source is joined before the filter.
//   - Any other filter needs only sources, so it is applied and the sources grouped
//     per file first. A text search then sorts by score and joins only the page it
//     returns; any other search sorts by source count, so it joins each distinct
//     file once.
//
// Joining per source was measured at ~330 ms for a search matching 10,000 sources
// of 200 files. $unwind without preserveNullAndEmptyArrays drops a file with no
// files document, which cannot happen (AddFile upserts the file before the source)
// and matches the MySQL engine's INNER JOIN files.
func mongoSearchPipeline(expr *SearchExpr) (mongo.Pipeline, bool) {
	textSearch, rest, hoisted := hoistTextLeaf(expr)

	filterExpr := expr
	if hoisted {
		filterExpr = rest // may be nil when the whole query was just that text leaf
	}

	var fullMatch bson.M
	needsFile := false
	if filterExpr != nil {
		fullMatch, needsFile = mongoFilter(filterExpr)
		if fullMatch == nil {
			logging.Errorf("mongodb search: unsupported search expression, dropping query")
			return nil, false
		}
	}
	if !hoisted && fullMatch == nil {
		logging.Errorf("mongodb search: search expression produced no filter, dropping query")
		return nil, false
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

	byScore := bson.D{{Key: "$sort", Value: bson.D{{Key: "score", Value: -1}}}}
	bySources := bson.D{{Key: "$sort", Value: bson.D{{Key: "sources", Value: -1}}}}
	limit := bson.D{{Key: "$limit", Value: int64(MaxSearchResults)}}
	order := bySources
	if hoisted {
		order = byScore
	}

	if needsFile {
		pipeline = append(pipeline, mongoFileJoin("$file_hash", "$file_size")...)
		pipeline = append(pipeline,
			bson.D{{Key: "$match", Value: fullMatch}},
			bson.D{{Key: "$group", Value: mongoSearchGroup(hoisted, true)}},
			order, limit,
		)
		return pipeline, true
	}
	if fullMatch != nil {
		pipeline = append(pipeline, bson.D{{Key: "$match", Value: fullMatch}})
	}
	pipeline = append(pipeline, bson.D{{Key: "$group", Value: mongoSearchGroup(hoisted, false)}})
	if hoisted {
		pipeline = append(pipeline, byScore, limit)
		return append(pipeline, mongoFileCounterStages()...), true
	}
	pipeline = append(pipeline, mongoFileCounterStages()...)
	return append(pipeline, bySources, limit), true
}

// mongoSearchGroup folds the sources of one file into one search result: the first
// source's metadata, the best text score of them when score is set, and the files
// counters when counters is set, which needs the file joined in as "file" before.
func mongoSearchGroup(score, counters bool) bson.M {
	group := bson.M{
		"_id":     bson.M{"hash": "$file_hash", "size": "$file_size"},
		"hash":    bson.M{"$first": "$file_hash"},
		"size":    bson.M{"$first": "$file_size"},
		"name":    bson.M{"$first": "$name"},
		"type":    bson.M{"$first": "$type"},
		"title":   bson.M{"$first": "$title"},
		"artist":  bson.M{"$first": "$artist"},
		"album":   bson.M{"$first": "$album"},
		"runtime": bson.M{"$first": "$length"},
		"bitrate": bson.M{"$first": "$bitrate"},
		"codec":   bson.M{"$first": "$codec"},
	}
	// Only carry a relevance score when a $text stage actually produced one;
	// referencing $meta without it fails the whole aggregation.
	if score {
		group["score"] = bson.M{"$max": "$_textScore"}
	}
	if counters {
		group["sources"] = bson.M{"$first": "$file.sources"}
		group["completed"] = bson.M{"$first": "$file.completed"}
		group["source_id"] = bson.M{"$first": "$file.source_id"}
		group["source_port"] = bson.M{"$first": "$file.source_port"}
	}
	return group
}

// mongoFileCounterStages joins each grouped search result to its files document and
// copies the counters onto the result.
func mongoFileCounterStages() []bson.D {
	return append(mongoFileJoin("$hash", "$size"),
		bson.D{{Key: "$addFields", Value: bson.M{
			"sources":     "$file.sources",
			"completed":   "$file.completed",
			"source_id":   "$file.source_id",
			"source_port": "$file.source_port",
		}}},
		bson.D{{Key: "$project", Value: bson.M{"file": 0}}},
	)
}

// mongoFileJoin joins the files document whose hash and size equal the given
// field paths, as "file".
func mongoFileJoin(hashField, sizeField string) []bson.D {
	return []bson.D{
		{{Key: "$lookup", Value: bson.M{
			"from": "files",
			"let":  bson.M{"h": hashField, "s": sizeField},
			"pipeline": mongo.Pipeline{
				{{Key: "$match", Value: bson.M{
					"$expr": bson.M{
						"$and": []bson.M{
							{"$eq": []any{"$hash", "$$h"}},
							{"$eq": []any{"$size", "$$s"}},
						},
					},
				}}},
			},
			"as": "file",
		}}},
		{{Key: "$unwind", Value: "$file"}},
	}
}

// decodeMongoSearchFiles reads the results of a search pipeline.
func decodeMongoSearchFiles(ctx context.Context, cur *mongo.Cursor) []File {
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

// chunkAny splits items into consecutive slices of at most size elements.
func chunkAny(items []any, size int) [][]any {
	var chunks [][]any
	for start := 0; start < len(items); start += size {
		chunks = append(chunks, items[start:min(start+size, len(items))])
	}
	return chunks
}
