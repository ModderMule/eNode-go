package spamfilter

import (
	"encoding/hex"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"enode/logging"
)

const (
	// detectionTTL is how long a detection stays listed after it was last seen.
	detectionTTL = 24 * time.Hour
	// maxFileDetections and maxPublisherDetections bound the lists: what a publisher
	// offers is its own choice, so without a bound it could grow them at will.
	maxFileDetections      = 10_000
	maxPublisherDetections = 1_000
	pruneEvery             = time.Minute
)

// FileDetection is one file that scored BandCaution or above.
type FileDetection struct {
	Hash    string // 32 hex digits
	Name    string
	Size    uint64
	Verdict Verdict
	// Offers is how many times the file was offered with a score in a band.
	Offers    uint64
	FirstSeen time.Time
	LastSeen  time.Time
}

// PublisherDetection is one session whose share was judged spam.
type PublisherDetection struct {
	UserHash string // 32 hex digits, or "" for a session without one
	Address  string
	// Files is how many files the session had offered when it was last seen.
	Files     int
	Reasons   []ReasonPoints
	FirstSeen time.Time
	LastSeen  time.Time
}

// Publisher is who offers the files of a session.
type Publisher struct {
	UserHash []byte
	Address  string
}

// Session is the detector's state for one client session. The zero value is ready.
type Session struct {
	profile Profile
	// flagged is set once the session's share was judged spam and logged.
	flagged bool
}

// Stats counts what the detector has scored since the start.
type Stats struct {
	Assessed uint64
	Caution  uint64
	Suspect  uint64
	Spam     uint64
}

// Detector scores offered files and keeps the detections. It observes only. Safe for
// concurrent use; a Session belongs to one connection and is not.
type Detector struct {
	mu         sync.Mutex
	files      map[string]*FileDetection
	publishers map[string]*PublisherDetection
	lastPrune  time.Time
	now        func() time.Time
	// exempt, when set, names the files that are never listed: the whitelist.
	exempt func(hash []byte) bool
	// log is the verdict log, or nil.
	log *verdictLog
	// logged is the score each file was last written to the log with. It outlives the
	// detection, so a file that expires and comes back is not logged again.
	logged map[string]int
	// scoring off makes Observe a no-op: nothing is scored, counted or listed.
	scoring bool

	assessed atomic.Uint64
	bands    [BandSpam + 1]atomic.Uint64
}

// New returns an empty detector.
func New() *Detector {
	return &Detector{
		files:      make(map[string]*FileDetection),
		publishers: make(map[string]*PublisherDetection),
		logged:     make(map[string]int),
		now:        time.Now,
		scoring:    true,
	}
}

// SetScoring turns the scoring of offers on or off; it is on in a new detector. Off,
// the list stays empty and the operator's buttons still work. Call it before the
// detector is used.
func (d *Detector) SetScoring(on bool) {
	d.scoring = on
}

// Scoring reports whether offers are scored.
func (d *Detector) Scoring() bool {
	return d != nil && d.scoring
}

// SetExempt names the files that are scored but never listed or logged, the operator
// having ruled them fine. Call it before the detector is used.
func (d *Detector) SetExempt(exempt func(hash []byte) bool) {
	d.exempt = exempt
}

// SetLog makes the detector append what it lists, and what the operator decides, to a
// file of JSON lines (see LogEntry), bounded as opts says. Call it before the detector
// is used.
func (d *Detector) SetLog(path string, opts logging.RotateOptions) error {
	log, err := openVerdictLog(path, opts)
	if err != nil {
		return err
	}
	d.log = log
	return nil
}

// ReopenLog closes the verdict log file; the next entry opens its path again, so a file
// moved away by an external logrotate is replaced by a new one.
func (d *Detector) ReopenLog() error {
	if d == nil {
		return nil
	}
	return d.log.reopen()
}

// Close closes the verdict log.
func (d *Detector) Close() {
	if d != nil {
		d.log.close()
	}
}

// Observe scores the files of one offer and counts them into the session's profile.
// The files are scored with the reasons the share has earned including this offer, so
// the offer that gives a share away is itself marked.
func (d *Detector) Observe(s *Session, pub Publisher, records []Record) {
	if d == nil || !d.scoring || s == nil || len(records) == 0 {
		return
	}
	for _, r := range records {
		s.profile.Add(r)
	}
	reasons := s.profile.Reasons()
	now := d.now()

	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked(now)
	if len(reasons) > 0 {
		d.notePublisherLocked(s, pub, reasons, now)
	}
	for _, r := range records {
		v := Assess(r, reasons)
		d.assessed.Add(1)
		if v.Band == BandClean || (d.exempt != nil && d.exempt(r.Hash)) {
			continue
		}
		d.bands[v.Band].Add(1)
		d.noteFileLocked(r, v, pub, now)
	}
}

// Stats returns the counters.
func (d *Detector) Stats() Stats {
	if d == nil {
		return Stats{}
	}
	return Stats{
		Assessed: d.assessed.Load(),
		Caution:  d.bands[BandCaution].Load(),
		Suspect:  d.bands[BandSuspect].Load(),
		Spam:     d.bands[BandSpam].Load(),
	}
}

// Files returns up to limit detections, highest score first.
func (d *Detector) Files(limit int) []FileDetection {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	out := make([]FileDetection, 0, len(d.files))
	for _, det := range d.files {
		out = append(out, *det)
	}
	d.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Verdict.Score != out[j].Verdict.Score {
			return out[i].Verdict.Score > out[j].Verdict.Score
		}
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Hash < out[j].Hash
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// File returns the detection of one file.
func (d *Detector) File(hash []byte) (FileDetection, bool) {
	if d == nil {
		return FileDetection{}, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	det := d.files[hex.EncodeToString(hash)]
	if det == nil {
		return FileDetection{}, false
	}
	return *det, true
}

// Decide records what the operator did with a listed file: it leaves the list, and
// the decision goes to the verdict log next to the verdict it answers. decision is
// the list the file was put on.
func (d *Detector) Decide(hash []byte, decision string) {
	if d == nil {
		return
	}
	key := hex.EncodeToString(hash)
	entry := LogEntry{Type: "decision", Hash: key, Decision: decision}
	d.mu.Lock()
	if det := d.files[key]; det != nil {
		entry.Name, entry.Size, entry.Score = det.Name, det.Size, det.Verdict.Score
		entry.Band, entry.Reasons = det.Verdict.Band.String(), det.Verdict.Reasons
		delete(d.files, key)
	}
	d.mu.Unlock()
	d.log.write(d.now(), entry)
}

// Publishers returns the flagged sessions, most recently seen first.
func (d *Detector) Publishers() []PublisherDetection {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	out := make([]PublisherDetection, 0, len(d.publishers))
	for _, det := range d.publishers {
		out = append(out, *det)
	}
	d.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].UserHash+out[i].Address < out[j].UserHash+out[j].Address
	})
	return out
}

func (d *Detector) noteFileLocked(r Record, v Verdict, pub Publisher, now time.Time) {
	key := hex.EncodeToString(r.Hash)
	det := d.files[key]
	if det == nil {
		if len(d.files) >= maxFileDetections {
			return
		}
		det = &FileDetection{Hash: key, FirstSeen: now}
		d.files[key] = det
		// Once per file, and only from suspect up: a caution is common enough to
		// drown the log.
		if v.Band >= BandSuspect {
			logging.Infof("spam detection: file hash=%s name=%q size=%d score=%d band=%s reasons=%v (observed, not withheld)",
				key, r.Name, r.Size, v.Score, v.Band, v.Reasons)
		}
	}
	// The highest score stays: a later offer from an ordinary share does not clear
	// what a spam share said about the file.
	if v.Score >= det.Verdict.Score {
		// Written when a file is first listed and whenever its score rises above
		// what was logged, so the log has the verdict the list shows.
		if v.Score > det.Verdict.Score && v.Score > d.logged[key] {
			d.noteLoggedLocked(key, v.Score)
			d.log.write(now, LogEntry{
				Type: "file", Hash: key, Name: r.Name, Size: r.Size,
				Score: v.Score, Band: v.Band.String(), Reasons: v.Reasons,
				FileType: r.Type, LengthSec: r.LengthSec, BitrateKbps: r.BitrateKbps, Codec: r.Codec,
				UserHash: hex.EncodeToString(pub.UserHash), Address: pub.Address,
			})
		}
		det.Name, det.Size, det.Verdict = r.Name, r.Size, v
	}
	det.Offers++
	det.LastSeen = now
}

// noteLoggedLocked remembers the score a file was logged with. The set is bounded like
// the list; when full it starts over, which at worst logs a file once more.
func (d *Detector) noteLoggedLocked(key string, score int) {
	if _, ok := d.logged[key]; !ok && len(d.logged) >= maxFileDetections {
		clear(d.logged)
	}
	d.logged[key] = score
}

func (d *Detector) notePublisherLocked(s *Session, pub Publisher, reasons []ReasonPoints, now time.Time) {
	userHash := hex.EncodeToString(pub.UserHash)
	key := userHash
	if key == "" {
		key = pub.Address
	}
	det := d.publishers[key]
	if det == nil {
		if len(d.publishers) >= maxPublisherDetections {
			return
		}
		det = &PublisherDetection{UserHash: userHash, FirstSeen: now}
		d.publishers[key] = det
	}
	det.Address, det.Files, det.Reasons, det.LastSeen = pub.Address, s.profile.Files(), reasons, now
	if !s.flagged {
		s.flagged = true
		d.log.write(now, LogEntry{
			Type: "publisher", UserHash: userHash, Address: pub.Address,
			Files: s.profile.Files(), Reasons: reasons,
		})
		logging.Warnf("spam detection: publisher hash=%s remote=%s files=%d reasons=%v (observed, not banned)",
			userHash, pub.Address, s.profile.Files(), reasons)
	}
}

// pruneLocked drops the detections not seen for detectionTTL, at most once a minute.
func (d *Detector) pruneLocked(now time.Time) {
	if now.Sub(d.lastPrune) < pruneEvery {
		return
	}
	d.lastPrune = now
	for key, det := range d.files {
		if now.Sub(det.LastSeen) > detectionTTL {
			delete(d.files, key)
		}
	}
	for key, det := range d.publishers {
		if now.Sub(det.LastSeen) > detectionTTL {
			delete(d.publishers, key)
		}
	}
}
