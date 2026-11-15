package ed2k

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"enode/logging"
)

// OFFERFILES v1: server-paced fast publishing (emule-qt#185). The contract is
// ed2k-server's (README "OFFERFILES v1", src/server/offer_pacing.rs) and aMule's
// (docs/ED2K_EXTENSIONS.md); see docs/offerfiles-v1.md.
//
// A stock client publishes at most 200 files per OP_OFFERFILES and one packet a
// minute, because a Lugdunum server may black out an IP that publishes faster, and a
// client cannot tell this server from one of those. v1 tells it:
//
//  1. the client asks, with a string-named uint32 tag offerfiles_v >= 1 in its
//     OP_LOGINREQUEST;
//  2. only then, and only in the OP_SERVERIDENT that follows the login, the server
//     answers with ST_SOFTFILES, ST_HARDFILES, offerfiles_v = 1,
//     offerfiles_batch_max and offerfiles_min_interval_ms, all uint32, all or none;
//  3. that connection is held to what it was told: a packet declaring
//     ST_HARDFILES records or more closes it (as for everyone), one declaring more
//     than batch_max is not indexed but the session stays up, and one that arrives
//     early waits until it is due and is never dropped.
//
// The values are a snapshot taken at login (offerV1Policy), so what was advertised
// is what is enforced, and a reload reaches new logins only. A client that did not
// ask is a legacy one whatever the configuration says.
//
// ed2k-server also has a server-wide ceiling shared by every v1 connection
// (offerfiles_global_records_per_sec). It is not part of the client contract and is
// not implemented here.
// ToDo: a server-wide v1 records-per-second ceiling, should a reconnect wave of
// fast publishers ever saturate the content filter or storage.

// The tag names and the version of the contract this server implements.
const (
	OfferFilesV1Version        = 1
	TagNameOfferFilesVersion   = "offerfiles_v"
	TagNameOfferFilesBatchMax  = "offerfiles_batch_max"
	TagNameOfferFilesMinIntvMs = "offerfiles_min_interval_ms"
	// TagSoftFiles and TagHardFiles are ST_SOFTFILES / ST_HARDFILES, the server.met
	// tags a client keeps the two file limits under.
	TagSoftFiles uint8 = 0x88
	TagHardFiles uint8 = 0x89
)

// OfferFilesV1Config is the v1 part of TCPRuntimeConfig: config files.offerFilesV1.
type OfferFilesV1Config struct {
	Enabled     bool
	BatchMax    int
	MinInterval time.Duration
}

// OfferFilesV1Problem says why the configuration cannot be advertised to a client
// that asks for v1, or nil when it can (or v1 is off). The contract is all or
// nothing: soft > 0, batch_max > 0, interval > 0 and hard > batch_max. Since 0 is
// "unlimited" for both file limits here, an otherwise valid configuration fails it
// when either is.
func OfferFilesV1Problem(cfg TCPRuntimeConfig) error {
	_, err := newOfferV1Policy(cfg)
	return err
}

// LoginRequestsOfferFilesV1 reports whether an OP_LOGINREQUEST asked for v1: a
// string-named uint32 tag offerfiles_v carrying at least version 1. Any other
// shape — absent, another type, 0 — is a legacy client.
func LoginRequestsOfferFilesV1(tags []NamedTag) bool {
	for _, t := range tags {
		if t.Name != TagNameOfferFilesVersion || t.Type != TypeUint32 {
			continue
		}
		if v, ok := t.Value.(uint64); ok && v >= OfferFilesV1Version {
			return true
		}
	}
	return false
}

// offerV1Policy is what one v1 connection was told at login, and is held to.
type offerV1Policy struct {
	Soft     uint32
	Hard     uint32
	BatchMax uint32
	Interval time.Duration
}

var errOfferV1Off = errors.New("files.offerFilesV1 is off")

// newOfferV1Policy snapshots the policy a client logging in now is given.
func newOfferV1Policy(cfg TCPRuntimeConfig) (*offerV1Policy, error) {
	v1 := cfg.OfferFilesV1
	if !v1.Enabled {
		return nil, errOfferV1Off
	}
	switch {
	case cfg.SoftFileLimit <= 0:
		return nil, errors.New("files.softLimit must be above 0 (0, unlimited, cannot be advertised)")
	case cfg.HardFileLimit <= 0:
		return nil, errors.New("files.hardLimit must be above 0 (0, unlimited, cannot be advertised)")
	case v1.BatchMax <= 0:
		return nil, errors.New("files.offerFilesV1.batchMax must be above 0")
	case v1.MinInterval < time.Millisecond:
		return nil, errors.New("files.offerFilesV1.minIntervalMs must be above 0")
	case cfg.HardFileLimit <= v1.BatchMax:
		return nil, fmt.Errorf("files.offerFilesV1.batchMax (%d) must be below files.hardLimit (%d)",
			v1.BatchMax, cfg.HardFileLimit)
	}
	return &offerV1Policy{
		Soft:     uint32(cfg.SoftFileLimit),
		Hard:     uint32(cfg.HardFileLimit),
		BatchMax: uint32(v1.BatchMax),
		Interval: v1.MinInterval,
	}, nil
}

// tags is the advertisement, each tag exactly once.
func (p *offerV1Policy) tags() []Tag {
	return []Tag{
		{Type: TypeUint32, Code: TagSoftFiles, Data: p.Soft},
		{Type: TypeUint32, Code: TagHardFiles, Data: p.Hard},
		{Type: TypeUint32, Name: TagNameOfferFilesVersion, Data: uint32(OfferFilesV1Version)},
		{Type: TypeUint32, Name: TagNameOfferFilesBatchMax, Data: p.BatchMax},
		{Type: TypeUint32, Name: TagNameOfferFilesMinIntvMs, Data: uint32(p.Interval / time.Millisecond)},
	}
}

// offerV1Session is a v1 session's policy and the bucket pacing it, which is made on
// its first offer.
type offerV1Session struct {
	offerV1Policy
	pace *offerBucket
}

// offerBucket paces one v1 connection, in file records. It holds one batch, starts
// full so the first batch goes at once, and refills at BatchMax records per
// Interval, so a smaller batch costs proportionally less and two frames TCP happens
// to deliver together are not an offence. A batch the bucket cannot cover is not
// refused: the deficit is carried, and reserve says how long the batch waits.
type offerBucket struct {
	capacity float64
	perNanos float64
	tokens   float64
	last     time.Time
}

func newOfferBucket(p *offerV1Policy, now time.Time) *offerBucket {
	return &offerBucket{
		capacity: float64(p.BatchMax),
		perNanos: float64(p.BatchMax) / float64(p.Interval),
		tokens:   float64(p.BatchMax),
		last:     now,
	}
}

// reserve charges cost records at now and returns how long the batch has to wait
// before it is due. Zero when it is due already.
func (b *offerBucket) reserve(now time.Time, cost uint32) time.Duration {
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = min(b.capacity, b.tokens+float64(elapsed)*b.perNanos)
		b.last = now
	}
	b.tokens -= float64(cost)
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / b.perNanos)
}

// advertised is the policy to advertise in OP_SERVERIDENT, nil for a legacy session.
func (s *offerV1Session) advertised() *offerV1Policy {
	if s == nil {
		return nil
	}
	return &s.offerV1Policy
}

// offerV1Problems logs a v1 configuration that cannot be advertised once per
// distinct problem rather than once per login.
var offerV1Problems struct {
	sync.Mutex
	last string
}

// offerV1PolicyForLogin is the policy for a client that asked for v1, or nil when
// the server advertises nothing (v1 off or not advertisable).
func (c *tcpClient) offerV1PolicyForLogin() *offerV1Policy {
	p, err := newOfferV1Policy(*c.server.tcp())
	if err == nil {
		return p
	}
	if errors.Is(err, errOfferV1Off) {
		return nil
	}
	offerV1Problems.Lock()
	defer offerV1Problems.Unlock()
	if offerV1Problems.last != err.Error() {
		offerV1Problems.last = err.Error()
		logging.Errorf("offerfiles v1 is on but cannot be advertised: %v; clients asking for it publish at the legacy pace", err)
	}
	return nil
}

// waitOfferDue holds a v1 batch until the bucket says it is due. The connection's
// own goroutine waits, reading nothing more meanwhile, so the client is held back by
// TCP rather than by a queue here, and nothing is dropped.
//
// The wait is at most one interval, and is cut short when the session is closing or
// a handover starts parking sessions: the batch has been read off the stream already
// and must be processed before the session can park.
func (c *tcpClient) waitOfferDue(cost uint32) {
	v1 := c.offerV1
	if v1 == nil {
		return
	}
	now := time.Now()
	if v1.pace == nil {
		v1.pace = newOfferBucket(&v1.offerV1Policy, now)
	}
	wait := v1.pace.reserve(now, cost)
	if wait <= 0 {
		return
	}
	c.server.blocks.offerPaced.Add(1)
	logging.Debugf("offer files v1 early remote=%s records=%d: waiting %s", c.remoteHost, cost, wait)
	const step = 100 * time.Millisecond
	for deadline := now.Add(wait); ; {
		left := time.Until(deadline)
		if left <= 0 || c.server.parking.Load() != nil || c.closing() {
			return
		}
		time.Sleep(min(left, step))
	}
}
