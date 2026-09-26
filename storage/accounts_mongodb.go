package storage

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"enode/logging"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Account collections. Primary keys are uint64 sequences from the account_counters
// collection rather than ObjectIDs, so an account id means the same thing on every
// engine.
const (
	collAccounts        = "accounts"
	collAccountSteps    = "account_steps"
	collPayments        = "payments"
	collAccountSessions = "account_sessions"
	collAccountCounters = "account_counters"
)

// sessionTTL0 expires a session document as soon as its expires_at passes.
var sessionTTL0 = int32(0)

// accountIndexes are created by InitAccounts, never by Init, so a server without
// accounts never grows these collections.
var accountIndexes = []mongoIndex{
	{collection: collAccounts, name: "username_1", keys: bson.D{{Key: "username", Value: 1}}, unique: true},
	{collection: collAccounts, name: "state_1", keys: bson.D{{Key: "state", Value: 1}}},
	{collection: collAccountSteps, name: "account_id_1_step_id_1", keys: bson.D{{Key: "account_id", Value: 1}, {Key: "step_id", Value: 1}}, unique: true},
	// Partial: a payment has no external_id until its checkout exists, and those rows
	// must not collide with each other.
	{collection: collPayments, name: "provider_1_external_id_1", keys: bson.D{{Key: "provider", Value: 1}, {Key: "external_id", Value: 1}}, unique: true,
		partial: bson.D{{Key: "external_id", Value: bson.D{{Key: "$type", Value: "string"}}}}},
	{collection: collPayments, name: "account_id_1", keys: bson.D{{Key: "account_id", Value: 1}}},
	{collection: collPayments, name: "status_1", keys: bson.D{{Key: "status", Value: 1}}},
	{collection: collPayments, name: "credited_at_1", keys: bson.D{{Key: "credited_at", Value: 1}}},
	{collection: collAccountSessions, name: "token_hash_1", keys: bson.D{{Key: "token_hash", Value: 1}}, unique: true},
	// TTL: MongoDB removes expired sessions itself; DeleteExpiredSessions is only the
	// engine-neutral backstop.
	{collection: collAccountSessions, name: "expires_at_1", keys: bson.D{{Key: "expires_at", Value: 1}}, expireAfter: &sessionTTL0},
}

type mongoAccount struct {
	ID           int64      `bson:"_id"`
	Username     string     `bson:"username"`
	Email        string     `bson:"email"`
	PasswordHash string     `bson:"password_hash"`
	State        int32      `bson:"state"`
	AccessUntil  *time.Time `bson:"access_until"`
	CreatedAt    time.Time  `bson:"created_at"`
	UpdatedAt    time.Time  `bson:"updated_at"`
}

type mongoAccountStep struct {
	ID          int64      `bson:"_id"`
	AccountID   int64      `bson:"account_id"`
	StepID      string     `bson:"step_id"`
	Status      int32      `bson:"status"`
	Data        []byte     `bson:"data"`
	CompletedAt *time.Time `bson:"completed_at"`
	CreatedAt   time.Time  `bson:"created_at"`
	UpdatedAt   time.Time  `bson:"updated_at"`
}

type mongoPayment struct {
	ID          int64      `bson:"_id"`
	AccountID   int64      `bson:"account_id"`
	StepID      string     `bson:"step_id"`
	PlanID      string     `bson:"plan_id"`
	Provider    string     `bson:"provider"`
	ExternalID  string     `bson:"external_id,omitempty"`
	ExternalKey string     `bson:"external_key"`
	Status      int32      `bson:"status"`
	Amount      string     `bson:"amount"`
	Currency    string     `bson:"currency"`
	PeriodDays  int64      `bson:"period_days"`
	CreditedAt  *time.Time `bson:"credited_at"`
	RevokedAt   *time.Time `bson:"revoked_at"`
	CreatedAt   time.Time  `bson:"created_at"`
	UpdatedAt   time.Time  `bson:"updated_at"`
}

type mongoSession struct {
	ID        int64     `bson:"_id"`
	AccountID int64     `bson:"account_id"`
	TokenHash []byte    `bson:"token_hash"`
	Client    string    `bson:"client"`
	ExpiresAt time.Time `bson:"expires_at"`
	CreatedAt time.Time `bson:"created_at"`
	UpdatedAt time.Time `bson:"updated_at"`
}

// DurableAccounts is true: accounts live in the database.
func (m *MongoDBEngine) DurableAccounts() bool { return true }

// InitAccounts creates the account indexes when missing.
func (m *MongoDBEngine) InitAccounts(ctx context.Context) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	created, err := m.ensureIndexList(ctx, accountIndexes)
	if len(created) > 0 {
		logging.Infof("mongodb: created account indexes %s", strings.Join(created, ", "))
	}
	return err
}

func (m *MongoDBEngine) CreateAccount(ctx context.Context, a *Account) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	id, err := m.nextAccountSeq(ctx, collAccounts)
	if err != nil {
		return err
	}
	now := mongoNow()
	doc := mongoAccount{ID: id, Username: a.Username, Email: a.Email, PasswordHash: a.PasswordHash,
		State: int32(a.State), AccessUntil: timePtr(a.AccessUntil), CreatedAt: now, UpdatedAt: now}
	if _, err := m.db.Collection(collAccounts).InsertOne(ctx, doc); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return ErrUsernameTaken
		}
		return err
	}
	a.ID, a.CreatedAt, a.UpdatedAt = uint64(id), now, now
	return nil
}

func (m *MongoDBEngine) AccountByID(ctx context.Context, id uint64) (Account, error) {
	return m.findAccount(ctx, bson.M{"_id": int64(id)})
}

func (m *MongoDBEngine) AccountByUsername(ctx context.Context, username string) (Account, error) {
	return m.findAccount(ctx, bson.M{"username": username})
}

func (m *MongoDBEngine) UpdateAccount(ctx context.Context, a *Account) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	now := mongoNow()
	res, err := m.db.Collection(collAccounts).UpdateOne(ctx, bson.M{"_id": int64(a.ID)}, bson.M{"$set": bson.M{
		"email": a.Email, "password_hash": a.PasswordHash, "state": int32(a.State),
		"access_until": timePtr(a.AccessUntil), "updated_at": now,
	}})
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return ErrAccountNotFound
	}
	a.UpdatedAt = now
	return nil
}

func (m *MongoDBEngine) CountAccounts(ctx context.Context) (map[AccountState]int, error) {
	if err := m.ensureDB(); err != nil {
		return nil, err
	}
	cur, err := m.db.Collection(collAccounts).Aggregate(ctx, mongo.Pipeline{
		{{Key: "$group", Value: bson.M{"_id": "$state", "n": bson.M{"$sum": 1}}}},
	})
	if err != nil {
		return nil, err
	}
	var rows []struct {
		State int32 `bson:"_id"`
		N     int   `bson:"n"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := map[AccountState]int{}
	for _, r := range rows {
		out[AccountState(r.State)] = r.N
	}
	return out, nil
}

func (m *MongoDBEngine) ListAccounts(ctx context.Context, filter AccountFilter, limit, offset int) ([]Account, error) {
	if err := m.ensureDB(); err != nil {
		return nil, err
	}
	query := bson.M{}
	if filter.State != 0 {
		query["state"] = int32(filter.State)
	}
	if filter.Search != "" {
		re := bson.Regex{Pattern: regexp.QuoteMeta(filter.Search), Options: "i"}
		query["$or"] = bson.A{bson.M{"username": re}, bson.M{"email": re}}
	}
	opts := options.Find().SetSort(bson.D{{Key: "_id", Value: -1}}).SetSkip(int64(max(offset, 0)))
	if limit > 0 {
		opts.SetLimit(int64(limit))
	}
	cur, err := m.db.Collection(collAccounts).Find(ctx, query, opts)
	if err != nil {
		return nil, err
	}
	var docs []mongoAccount
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.account())
	}
	return out, nil
}

func (m *MongoDBEngine) AccountSteps(ctx context.Context, accountID uint64) ([]AccountStep, error) {
	if err := m.ensureDB(); err != nil {
		return nil, err
	}
	cur, err := m.db.Collection(collAccountSteps).Find(ctx, bson.M{"account_id": int64(accountID)},
		options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		return nil, err
	}
	var docs []mongoAccountStep
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	out := make([]AccountStep, 0, len(docs))
	for _, d := range docs {
		out = append(out, AccountStep{ID: uint64(d.ID), AccountID: uint64(d.AccountID), StepID: d.StepID,
			Status: StepStatus(d.Status), Data: d.Data, CompletedAt: timeVal(d.CompletedAt),
			CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt})
	}
	return out, nil
}

func (m *MongoDBEngine) UpsertAccountStep(ctx context.Context, st *AccountStep) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	// The id is drawn up front and only used when the upsert inserts; a gap in the
	// sequence on the update path is harmless.
	id, err := m.nextAccountSeq(ctx, collAccountSteps)
	if err != nil {
		return err
	}
	now := mongoNow()
	var doc mongoAccountStep
	err = m.db.Collection(collAccountSteps).FindOneAndUpdate(ctx,
		bson.M{"account_id": int64(st.AccountID), "step_id": st.StepID},
		bson.M{
			"$set":         bson.M{"status": int32(st.Status), "data": st.Data, "completed_at": timePtr(st.CompletedAt), "updated_at": now},
			"$setOnInsert": bson.M{"_id": id, "created_at": now},
		},
		options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After),
	).Decode(&doc)
	if err != nil {
		return err
	}
	st.ID, st.CreatedAt, st.UpdatedAt = uint64(doc.ID), doc.CreatedAt, doc.UpdatedAt
	return nil
}

func (m *MongoDBEngine) CreatePayment(ctx context.Context, p *Payment) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	id, err := m.nextAccountSeq(ctx, collPayments)
	if err != nil {
		return err
	}
	now := mongoNow()
	doc := mongoPayment{ID: id, AccountID: int64(p.AccountID), StepID: p.StepID, PlanID: p.PlanID, Provider: p.Provider,
		ExternalID: p.ExternalID, ExternalKey: p.ExternalKey, Status: int32(p.Status), Amount: p.Amount,
		Currency: p.Currency, PeriodDays: int64(p.PeriodDays), CreditedAt: timePtr(p.CreditedAt), CreatedAt: now, UpdatedAt: now}
	if _, err := m.db.Collection(collPayments).InsertOne(ctx, doc); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return ErrPaymentDuplicate
		}
		return err
	}
	p.ID, p.CreatedAt, p.UpdatedAt = uint64(id), now, now
	return nil
}

func (m *MongoDBEngine) UpdatePayment(ctx context.Context, p *Payment) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	now := mongoNow()
	set := bson.M{"external_key": p.ExternalKey, "status": int32(p.Status), "amount": p.Amount,
		"currency": p.Currency, "updated_at": now}
	update := bson.M{"$set": set}
	if p.ExternalID != "" {
		set["external_id"] = p.ExternalID
	} else {
		update["$unset"] = bson.M{"external_id": ""}
	}
	res, err := m.db.Collection(collPayments).UpdateOne(ctx, bson.M{"_id": int64(p.ID)}, update)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return ErrPaymentDuplicate
		}
		return err
	}
	if res.MatchedCount == 0 {
		return ErrPaymentNotFound
	}
	p.UpdatedAt = now
	return nil
}

func (m *MongoDBEngine) PaymentByID(ctx context.Context, id uint64) (Payment, error) {
	return m.findPayment(ctx, bson.M{"_id": int64(id)})
}

func (m *MongoDBEngine) PaymentByExternal(ctx context.Context, provider, externalID string) (Payment, error) {
	if externalID == "" {
		return Payment{}, ErrPaymentNotFound
	}
	return m.findPayment(ctx, bson.M{"provider": provider, "external_id": externalID})
}

func (m *MongoDBEngine) OpenPayments(ctx context.Context, limit int) ([]Payment, error) {
	return m.findPayments(ctx,
		bson.M{"status": bson.M{"$in": bson.A{int32(PaymentCreated), int32(PaymentPending)}}},
		bson.D{{Key: "_id", Value: 1}}, limit)
}

func (m *MongoDBEngine) PaymentsByAccount(ctx context.Context, accountID uint64, limit int) ([]Payment, error) {
	return m.findPayments(ctx, bson.M{"account_id": int64(accountID)}, bson.D{{Key: "_id", Value: -1}}, limit)
}

func (m *MongoDBEngine) MarkPaymentCredited(ctx context.Context, id uint64, at time.Time) (bool, error) {
	if err := m.ensureDB(); err != nil {
		return false, err
	}
	// The credited_at: null predicate is the compare-and-set: a single-document
	// update is atomic, so exactly one concurrent caller matches.
	res, err := m.db.Collection(collPayments).UpdateOne(ctx,
		bson.M{"_id": int64(id), "credited_at": nil},
		bson.M{"$set": bson.M{"credited_at": at.UTC().Truncate(time.Millisecond), "updated_at": mongoNow()}})
	if err != nil {
		return false, err
	}
	if res.ModifiedCount == 0 {
		if _, err := m.PaymentByID(ctx, id); err != nil {
			return false, err
		}
		return false, nil
	}
	return true, nil
}

func (m *MongoDBEngine) MarkPaymentRevoked(ctx context.Context, id uint64, at time.Time) (bool, error) {
	if err := m.ensureDB(); err != nil {
		return false, err
	}
	res, err := m.db.Collection(collPayments).UpdateOne(ctx,
		bson.M{"_id": int64(id), "credited_at": bson.M{"$ne": nil}, "revoked_at": nil},
		bson.M{"$set": bson.M{"revoked_at": at.UTC().Truncate(time.Millisecond), "updated_at": mongoNow()}})
	if err != nil {
		return false, err
	}
	if res.ModifiedCount == 0 {
		if _, err := m.PaymentByID(ctx, id); err != nil {
			return false, err
		}
		return false, nil
	}
	return true, nil
}

func (m *MongoDBEngine) CreditedPayments(ctx context.Context, since time.Time, limit int) ([]Payment, error) {
	return m.findPayments(ctx,
		bson.M{"credited_at": bson.M{"$gte": since.UTC()}, "revoked_at": nil},
		bson.D{{Key: "credited_at", Value: -1}}, limit)
}

func (m *MongoDBEngine) CreateSession(ctx context.Context, s *AccountSession) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	id, err := m.nextAccountSeq(ctx, collAccountSessions)
	if err != nil {
		return err
	}
	now := mongoNow()
	doc := mongoSession{ID: id, AccountID: int64(s.AccountID), TokenHash: s.TokenHash, Client: s.Client,
		ExpiresAt: s.ExpiresAt.UTC(), CreatedAt: now, UpdatedAt: now}
	if _, err := m.db.Collection(collAccountSessions).InsertOne(ctx, doc); err != nil {
		return err
	}
	s.ID, s.CreatedAt, s.UpdatedAt = uint64(id), now, now
	return nil
}

func (m *MongoDBEngine) SessionByTokenHash(ctx context.Context, tokenHash []byte) (AccountSession, error) {
	if err := m.ensureDB(); err != nil {
		return AccountSession{}, err
	}
	var d mongoSession
	err := m.db.Collection(collAccountSessions).FindOne(ctx, bson.M{"token_hash": tokenHash}).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return AccountSession{}, ErrSessionNotFound
	}
	if err != nil {
		return AccountSession{}, err
	}
	return AccountSession{ID: uint64(d.ID), AccountID: uint64(d.AccountID), TokenHash: d.TokenHash, Client: d.Client,
		ExpiresAt: d.ExpiresAt, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt}, nil
}

func (m *MongoDBEngine) DeleteSession(ctx context.Context, id uint64) error {
	if err := m.ensureDB(); err != nil {
		return err
	}
	_, err := m.db.Collection(collAccountSessions).DeleteOne(ctx, bson.M{"_id": int64(id)})
	return err
}

func (m *MongoDBEngine) DeleteExpiredSessions(ctx context.Context, now time.Time) (int, error) {
	if err := m.ensureDB(); err != nil {
		return 0, err
	}
	res, err := m.db.Collection(collAccountSessions).DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lt": now.UTC()}})
	if err != nil {
		return 0, err
	}
	return int(res.DeletedCount), nil
}

func (m *MongoDBEngine) findAccount(ctx context.Context, filter bson.M) (Account, error) {
	if err := m.ensureDB(); err != nil {
		return Account{}, err
	}
	var d mongoAccount
	err := m.db.Collection(collAccounts).FindOne(ctx, filter).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return Account{}, ErrAccountNotFound
	}
	if err != nil {
		return Account{}, err
	}
	return d.account(), nil
}

func (m *MongoDBEngine) findPayment(ctx context.Context, filter bson.M) (Payment, error) {
	if err := m.ensureDB(); err != nil {
		return Payment{}, err
	}
	var d mongoPayment
	err := m.db.Collection(collPayments).FindOne(ctx, filter).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return Payment{}, ErrPaymentNotFound
	}
	if err != nil {
		return Payment{}, err
	}
	return d.payment(), nil
}

func (m *MongoDBEngine) findPayments(ctx context.Context, filter bson.M, sort bson.D, limit int) ([]Payment, error) {
	if err := m.ensureDB(); err != nil {
		return nil, err
	}
	opts := options.Find().SetSort(sort)
	if limit > 0 {
		opts.SetLimit(int64(limit))
	}
	cur, err := m.db.Collection(collPayments).Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	var docs []mongoPayment
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	out := make([]Payment, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.payment())
	}
	return out, nil
}

// nextAccountSeq draws the next id for one account collection.
func (m *MongoDBEngine) nextAccountSeq(ctx context.Context, collection string) (int64, error) {
	var doc struct {
		Seq int64 `bson:"seq"`
	}
	err := m.db.Collection(collAccountCounters).FindOneAndUpdate(ctx,
		bson.M{"_id": collection},
		bson.M{"$inc": bson.M{"seq": int64(1)}},
		options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After),
	).Decode(&doc)
	if err != nil {
		return 0, fmt.Errorf("mongodb next %s id: %w", collection, err)
	}
	return doc.Seq, nil
}

func (d mongoAccount) account() Account {
	return Account{ID: uint64(d.ID), Username: d.Username, Email: d.Email, PasswordHash: d.PasswordHash,
		State: AccountState(d.State), AccessUntil: timeVal(d.AccessUntil), CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt}
}

func (d mongoPayment) payment() Payment {
	return Payment{ID: uint64(d.ID), AccountID: uint64(d.AccountID), StepID: d.StepID, PlanID: d.PlanID,
		Provider: d.Provider, ExternalID: d.ExternalID, ExternalKey: d.ExternalKey, Status: PaymentStatus(d.Status),
		Amount: d.Amount, Currency: d.Currency, PeriodDays: uint32(d.PeriodDays), CreditedAt: timeVal(d.CreditedAt), RevokedAt: timeVal(d.RevokedAt),
		CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt}
}

// mongoNow is the current time at BSON date precision, so what a write returns
// equals what a later read decodes.
func mongoNow() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }

// timePtr stores the zero time as null.
func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC().Truncate(time.Millisecond)
	return &u
}

func timeVal(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
