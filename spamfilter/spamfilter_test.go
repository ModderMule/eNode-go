package spamfilter

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enode/logging"
)

func testHash(b byte) []byte {
	h := make([]byte, 16)
	for i := range h {
		h[i] = b
	}
	return h
}

func hasReason(reasons []ReasonPoints, want Reason) bool {
	for _, r := range reasons {
		if r.Reason == want {
			return true
		}
	}
	return false
}

// TestAssessRecordReasons pins each per-record check and that an ordinary file scores
// nothing.
func TestAssessRecordReasons(t *testing.T) {
	cases := []struct {
		name      string
		record    Record
		want      []Reason
		wantScore int
	}{
		{"ordinary video", Record{Name: "Holiday.2019.mkv", Size: 700 << 20, Type: "Video", LengthSec: 5400, BitrateKbps: 1087}, nil, 0},
		{"no claims at all", Record{Name: "notes.txt", Size: 1200}, nil, 0},
		{"program claimed as video", Record{Name: "Movie.1080p.exe", Size: 3 << 20, Type: "Video"}, []Reason{ReasonClaimedTypeMismatch}, 15},
		{"video claimed as program", Record{Name: "Movie.avi", Size: 700 << 20, Type: "Pro"}, []Reason{ReasonClaimedTypeMismatch}, 15},
		{"archive claimed as archive", Record{Name: "album.zip", Size: 80 << 20, Type: "Arc"}, nil, 0},
		{"big video of ten seconds", Record{Name: "Movie.avi", Size: 700 << 20, LengthSec: 10}, []Reason{ReasonImplausibleMediaLength}, 10},
		{"audio at 9000 kbit/s", Record{Name: "song.mp3", Size: 5 << 20, BitrateKbps: 9000}, []Reason{ReasonImplausibleMediaBitrate}, 10},
		{"size ten times what length x bitrate gives", Record{Name: "Movie.avi", Size: 7000 << 20, LengthSec: 5400, BitrateKbps: 1087},
			[]Reason{ReasonMediaSizeMismatch}, 10},
		// The live log's usual case: an old XviD AVI whose bitrate tag is in the wrong
		// unit earns two reasons from the one tag, and that alone stays clean.
		{"avi with a bitrate tag of 5", Record{Name: "Peppa.Pig.1x20.DVDmux.XviD.iTA.ENG.avi", Size: 46_954_004, LengthSec: 300, BitrateKbps: 5},
			[]Reason{ReasonImplausibleMediaBitrate, ReasonMediaSizeMismatch}, 20},
		{"avi with a bitrate tag in bit/s", Record{Name: "Show 1x01 [HDRip][Spanish].avi", Size: 690 << 20, LengthSec: 2700, BitrateKbps: 1_000_000},
			[]Reason{ReasonImplausibleMediaBitrate, ReasonMediaSizeMismatch}, 20},
		{"all three media reasons", Record{Name: "Movie.avi", Size: 700 << 20, LengthSec: 10, BitrateKbps: 5},
			[]Reason{ReasonImplausibleMediaLength, ReasonImplausibleMediaBitrate, ReasonMediaSizeMismatch}, 30},
		{"bad signal word", Record{Name: "Movie.2024.FAKE.avi", Size: 700 << 20}, []Reason{ReasonBadSignalName}, 25},
		{"long audiobook the size pays for", Record{Name: "book.mp3", Size: 780 << 20, Type: "Audio", LengthSec: 27 * 3600, BitrateKbps: 64}, nil, 0},
	}
	for _, tc := range cases {
		v := Assess(tc.record, nil)
		t.Logf("input: %s %+v output: score=%d band=%s reasons=%v", tc.name, tc.record, v.Score, v.Band, v.Reasons)
		if v.Score != tc.wantScore || len(v.Reasons) != len(tc.want) {
			t.Errorf("%s: score=%d reasons=%v, want %d and %v", tc.name, v.Score, v.Reasons, tc.wantScore, tc.want)
			continue
		}
		for _, r := range tc.want {
			if !hasReason(v.Reasons, r) {
				t.Errorf("%s: reasons=%v, want %s among them", tc.name, v.Reasons, r)
			}
		}
	}
}

// TestAssessBandsAndPublisherReasons: the publisher's reasons add to the file's own,
// each reason counts once, and the bands start at 25, 50 and 75.
func TestAssessBandsAndPublisherReasons(t *testing.T) {
	bait := []ReasonPoints{{ReasonPublisherBait, pointsPublisher}}
	both := []ReasonPoints{{ReasonPublisherBait, pointsPublisher}, {ReasonPublisherTemplate, pointsPublisher}, {ReasonPublisherBait, pointsPublisher}}
	mismatch := Record{Name: "Movie.1080p.exe", Size: 3 << 20, Type: "Video"}
	cases := []struct {
		name      string
		record    Record
		publisher []ReasonPoints
		wantScore int
		wantBand  Band
	}{
		{"mismatch alone", mismatch, nil, 15, BandClean},
		{"clean file of a bait publisher", Record{Name: "a.txt", Size: 10}, bait, 30, BandCaution},
		{"mismatch of a bait publisher", mismatch, bait, 45, BandCaution},
		{"clean file, two publisher reasons, one repeated", Record{Name: "a.txt", Size: 10}, both, 60, BandSuspect},
		{"mismatch, two publisher reasons", mismatch, both, 75, BandSpam},
	}
	for _, tc := range cases {
		v := Assess(tc.record, tc.publisher)
		t.Logf("input: %s output: score=%d band=%s reasons=%v", tc.name, v.Score, v.Band, v.Reasons)
		if v.Score != tc.wantScore || v.Band != tc.wantBand {
			t.Errorf("%s: score=%d band=%s, want %d %s", tc.name, v.Score, v.Band, tc.wantScore, tc.wantBand)
		}
	}
}

// TestBadSignalName pins eMuleQt's default rules: whole words after folding, and the
// two masquerade patterns.
func TestBadSignalName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"Movie.2024.1080p.FAKE.mkv", true},
		{"Fäke release.avi", true},
		{"Album [Wrong_File].zip", true},
		{"archive (password protected).rar", true},
		{"movie.MP4.exe", true},
		{"clip.avi.scr", true},
		{"Trojan.War.1997.avi", true},
		{"Fakers.2004.avi", false},
		{"Password Recovery Tool 3.0.zip", false},
		{"movie.mp4", false},
		{"movie.exe.mp4", false},
		{"", false},
	}
	for _, tc := range cases {
		got := matchesBadSignal(tc.name)
		t.Logf("input: %q output: %t", tc.name, got)
		if got != tc.want {
			t.Errorf("matchesBadSignal(%q) = %t, want %t", tc.name, got, tc.want)
		}
	}
}

func profileOf(records []Record) *Profile {
	p := &Profile{}
	for _, r := range records {
		p.Add(r)
	}
	return p
}

// TestProfileShares runs whole shares through the profile: the two spam shapes are
// flagged, and the honest shares that resemble them are not.
func TestProfileShares(t *testing.T) {
	var bait, template, series, group, utilities, few []Record
	titles := []string{"Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "India", "Juliet", "Kilo", "Lima"}
	for i, title := range titles {
		// Small programs named like video releases, each named differently.
		bait = append(bait, Record{Name: fmt.Sprintf("%s.2024.1080p.BluRay.x264.%d.exe", title, i), Size: uint64(2<<20 + i*4096)})
		// One name with the keyword swapped, one size.
		template = append(template, Record{Name: title + " full crack keygen.zip", Size: uint64(1_500_000 + i)})
		// Episodes: same ending and near the same size, but the same beginning too.
		series = append(series, Record{Name: fmt.Sprintf("Show.S01E%02d.HDTV.XviD-GRP.avi", i+1), Size: uint64(350<<20 + i*1024)})
		// One group's releases: same ending, different beginnings, sizes far apart.
		group = append(group, Record{Name: title + ".2020.x264-GRP.mkv", Size: uint64(700<<20 + i*(300<<20))})
		// Small programs under their own names.
		utilities = append(utilities, Record{Name: title + "Tool-setup.exe", Size: uint64(3<<20 + i*100_000)})
	}
	few = template[:profileMinFiles-1]

	cases := []struct {
		name string
		recs []Record
		want []Reason
	}{
		{"small programs named like video releases", bait, []Reason{ReasonPublisherBait}},
		{"one name with the keyword swapped", template, []Reason{ReasonPublisherTemplate}},
		{"a series", series, nil},
		{"one release group", group, nil},
		{"a collection of utilities", utilities, nil},
		{"a template share below the minimum", few, nil},
	}
	for _, tc := range cases {
		p := profileOf(tc.recs)
		got := p.Reasons()
		t.Logf("input: %s, %d files, first %q output: reasons=%v", tc.name, p.Files(), tc.recs[0].Name, got)
		if len(got) != len(tc.want) {
			t.Errorf("%s: reasons=%v, want %v", tc.name, got, tc.want)
			continue
		}
		for _, r := range tc.want {
			if !hasReason(got, r) {
				t.Errorf("%s: reasons=%v, want %s", tc.name, got, r)
			}
		}
	}
}

// TestProfileTemplateGroupsAreBounded: a share of all-different endings must not grow
// the profile without limit.
func TestProfileTemplateGroupsAreBounded(t *testing.T) {
	p := &Profile{}
	for i := 0; i < 5000; i++ {
		p.Add(Record{Name: fmt.Sprintf("first second third fourth%d fifth%d.bin", i, i), Size: 1000})
	}
	t.Logf("input: 5000 names with distinct endings output: files=%d groups=%d", p.Files(), len(p.templates))
	if len(p.templates) != templateMaxGroups {
		t.Errorf("groups = %d, want the cap of %d", len(p.templates), templateMaxGroups)
	}
}

// TestDetectorObserves follows one spam session: nothing is listed for an ordinary
// offer, the offer that gives the share away marks its own files, and the detection
// expires.
func TestDetectorObserves(t *testing.T) {
	d := New()
	now := time.Unix(1_700_000_000, 0)
	d.now = func() time.Time { return now }
	s, pub := &Session{}, Publisher{UserHash: testHash(0x5a), Address: "203.0.113.7"}

	d.Observe(s, pub, []Record{{Hash: testHash(1), Name: "Holiday.2019.mkv", Size: 700 << 20, Type: "Video"}})
	t.Logf("input: one ordinary file output: stats=%+v files=%d publishers=%d", d.Stats(), len(d.Files(0)), len(d.Publishers()))
	if st := d.Stats(); st.Assessed != 1 || len(d.Files(0)) != 0 || len(d.Publishers()) != 0 {
		t.Fatalf("stats=%+v files=%d publishers=%d, want one file scored and nothing listed", st, len(d.Files(0)), len(d.Publishers()))
	}

	var offer []Record
	for i := 0; i < 20; i++ {
		offer = append(offer, Record{Hash: testHash(byte(10 + i)), Name: fmt.Sprintf("Title%d full crack keygen.zip", i), Size: 1_500_000, Type: "Video"})
	}
	d.Observe(s, pub, offer)
	files, pubs := d.Files(5), d.Publishers()
	t.Logf("input: 20 template-named archives claimed as video output: stats=%+v listed=%d (limit 5) top=%+v publishers=%+v",
		d.Stats(), len(files), files[0], pubs)
	if len(pubs) != 1 || pubs[0].Address != "203.0.113.7" || pubs[0].Files != 21 || !hasReason(pubs[0].Reasons, ReasonPublisherTemplate) {
		t.Fatalf("publishers = %+v, want the session once, with 21 files and the template reason", pubs)
	}
	if len(files) != 5 || len(d.Files(0)) != 20 {
		t.Fatalf("Files(5)=%d Files(0)=%d, want 5 and 20", len(files), len(d.Files(0)))
	}
	// 30 for the publisher and 15 for the claimed type.
	if files[0].Verdict.Score != 45 || files[0].Verdict.Band != BandCaution || files[0].Offers != 1 {
		t.Errorf("top file = %+v, want score 45, caution, one offer", files[0])
	}
	if st := d.Stats(); st.Assessed != 21 || st.Caution != 20 || st.Suspect != 0 || st.Spam != 0 {
		t.Errorf("stats = %+v, want 21 scored and 20 caution", st)
	}

	d.Observe(s, pub, offer[:1])
	var offers uint64
	for _, f := range d.Files(0) {
		offers += f.Offers
	}
	t.Logf("input: the first file offered again output: files=%d offers=%d publishers=%d", len(d.Files(0)), offers, len(d.Publishers()))
	if len(d.Files(0)) != 20 || offers != 21 || len(d.Publishers()) != 1 {
		t.Errorf("files=%d offers=%d publishers=%d after a re-offer, want 20, 21 and 1", len(d.Files(0)), offers, len(d.Publishers()))
	}

	now = now.Add(detectionTTL + 2*time.Minute)
	d.Observe(&Session{}, Publisher{Address: "198.51.100.1"}, []Record{{Hash: testHash(2), Name: "a.txt", Size: 5}})
	t.Logf("output after %s: files=%d publishers=%d", detectionTTL+2*time.Minute, len(d.Files(0)), len(d.Publishers()))
	if len(d.Files(0)) != 0 || len(d.Publishers()) != 0 {
		t.Errorf("files=%d publishers=%d, want the detections expired", len(d.Files(0)), len(d.Publishers()))
	}
}

// TestDetectorNilAndEmpty: a nil detector and an empty offer are no-ops.
func TestDetectorNilAndEmpty(t *testing.T) {
	var d *Detector
	d.Observe(&Session{}, Publisher{}, []Record{{Name: "a"}})
	t.Logf("input: nil detector output: stats=%+v files=%v publishers=%v", d.Stats(), d.Files(0), d.Publishers())
	if d.Stats() != (Stats{}) || d.Files(0) != nil || d.Publishers() != nil {
		t.Error("a nil detector must answer empty")
	}
	live := New()
	live.Observe(&Session{}, Publisher{}, nil)
	if live.Stats().Assessed != 0 {
		t.Error("an empty offer must score nothing")
	}
}

// TestDetectorScoringOff: with scoring off nothing is scored or listed, and a decision
// still works without a log.
func TestDetectorScoringOff(t *testing.T) {
	d := New()
	d.SetScoring(false)
	d.Observe(&Session{}, Publisher{Address: "203.0.113.7"}, []Record{{Hash: testHash(1), Name: "Movie.1080p.exe", Size: 3 << 20, Type: "Video"}})
	d.Decide(testHash(1), "filter")
	t.Logf("input: a type mismatch offered with scoring off output: scoring=%t stats=%+v files=%d", d.Scoring(), d.Stats(), len(d.Files(0)))
	if d.Scoring() || d.Stats() != (Stats{}) || len(d.Files(0)) != 0 {
		t.Errorf("scoring=%t stats=%+v files=%d, want nothing scored or listed", d.Scoring(), d.Stats(), len(d.Files(0)))
	}
	if !New().Scoring() {
		t.Error("a new detector must score")
	}
}

// TestVerdictLogOncePerFile: a file whose detection expired is not logged again when it
// comes back with the same score, and the line carries the tags it was scored on.
func TestVerdictLogOncePerFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verdicts.jsonl")
	d := New()
	if err := d.SetLog(path, logging.RotateOptions{}); err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	now := time.Unix(1_700_000_000, 0)
	d.now = func() time.Time { return now }
	r := Record{Hash: testHash(3), Name: "Movie.avi", Size: 700 << 20, Type: "Video", LengthSec: 10, BitrateKbps: 5, Codec: "xvid"}

	d.Observe(&Session{}, Publisher{Address: "203.0.113.7"}, []Record{r})
	now = now.Add(detectionTTL + 2*time.Minute)
	d.Observe(&Session{}, Publisher{Address: "198.51.100.1"}, []Record{{Hash: testHash(4), Name: "a.txt", Size: 5}})
	_, listed := d.File(r.Hash)
	d.Observe(&Session{}, Publisher{Address: "203.0.113.7"}, []Record{r})
	_, relisted := d.File(r.Hash)

	entries := readLog(t, path)
	t.Logf("input: one file offered, expired (listed=%t), offered again (listed=%t) output: %d lines %+v", listed, relisted, len(entries), entries)
	if listed || !relisted || len(entries) != 1 {
		t.Fatalf("listed=%t relisted=%t lines=%d, want the file expired, listed again and logged once", listed, relisted, len(entries))
	}
	e := entries[0]
	if e.FileType != "Video" || e.LengthSec != 10 || e.BitrateKbps != 5 || e.Codec != "xvid" || e.Score != 30 {
		t.Errorf("entry = %+v, want the tags it was scored on and score 30", e)
	}
}

func readLog(t *testing.T, path string) []LogEntry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []LogEntry
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var e LogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

// TestVerdictLogAndDecisions: the log gets one line when a file is listed and one when
// its score rises, one per flagged session, and one per operator decision; a decided
// file leaves the list and a whitelisted one is never listed.
func TestVerdictLogAndDecisions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "verdicts.jsonl")
	d := New()
	if err := d.SetLog(path, logging.RotateOptions{}); err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.SetExempt(func(hash []byte) bool { return hash[0] == 0x10 })
	s, pub := &Session{}, Publisher{UserHash: testHash(0x5a), Address: "203.0.113.7"}

	var offer []Record
	for i := 0; i < 12; i++ {
		offer = append(offer, Record{Hash: testHash(byte(0x10 + i)), Name: fmt.Sprintf("Title%d full crack keygen.zip", i), Size: 1_500_000})
	}
	d.Observe(s, pub, offer)
	d.Observe(s, pub, offer[1:2]) // same score again: nothing new to log
	risen := offer[2]
	risen.Type = "Video" // now also a type mismatch: the score rises
	d.Observe(s, pub, []Record{risen})
	d.Decide(testHash(0x13), "filter")
	d.Decide(testHash(0x77), "whitelist") // never listed: the decision is logged all the same

	entries := readLog(t, path)
	counts := map[string]int{}
	for _, e := range entries {
		counts[e.Type]++
	}
	_, exemptListed := d.File(testHash(0x10))
	_, decidedListed := d.File(testHash(0x13))
	t.Logf("input: 12 template files (one whitelisted), a re-offer, a score rise, two decisions")
	t.Logf("output: %d log lines by type %v; listed=%d exemptListed=%t decidedListed=%t; first=%+v last=%+v",
		len(entries), counts, len(d.Files(0)), exemptListed, decidedListed, entries[0], entries[len(entries)-1])

	// 11 listed files + 1 rise, 1 publisher, 2 decisions.
	if counts["file"] != 12 || counts["publisher"] != 1 || counts["decision"] != 2 {
		t.Fatalf("log lines by type = %v, want 12 file, 1 publisher, 2 decision", counts)
	}
	if exemptListed || decidedListed || len(d.Files(0)) != 10 {
		t.Errorf("listed=%d exempt=%t decided=%t, want 10 files and neither the whitelisted nor the decided one", len(d.Files(0)), exemptListed, decidedListed)
	}
	for _, e := range entries {
		if e.Time == "" {
			t.Fatalf("entry without a time: %+v", e)
		}
		switch {
		case e.Type == "file" && (len(e.Hash) != 32 || e.Score < cautionScore || e.Address != "203.0.113.7" || len(e.Reasons) == 0):
			t.Errorf("file entry = %+v, want hash, score, reasons and the publisher", e)
		case e.Type == "decision" && e.Hash == hex.EncodeToString(testHash(0x13)) && (e.Decision != "filter" || e.Score != 30 || e.Name == ""):
			t.Errorf("decision entry = %+v, want the list and the verdict it answers", e)
		}
	}
}

// TestVerdictLogRotates: at the limit the log is rotated to one backup, by default,
// and writing goes on in a new file.
func TestVerdictLogRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verdicts.jsonl")
	log, err := openVerdictLog(path, logging.RotateOptions{MaxSizeMB: 1, Rotate: true, MaxBackups: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer log.close()
	const entries = 25000 // about 3 MB of lines, so more than one rotation
	for i := 0; i < entries; i++ {
		log.write(time.Unix(1_700_000_000, 0), LogEntry{Type: "file", Hash: fmt.Sprintf("%032d", i), Name: "some name long enough to fill the log"})
	}
	current := readLog(t, path)
	info, _ := os.Stat(path)
	backups, _ := filepath.Glob(filepath.Join(dir, "verdicts-*.jsonl"))
	t.Logf("input: %d entries, limit 1 MB, 1 backup output: current=%d lines (%d bytes) backups=%v last=%s",
		entries, len(current), info.Size(), backups, current[len(current)-1].Hash)
	if info.Size() > 1<<20 || current[len(current)-1].Hash != fmt.Sprintf("%032d", entries-1) {
		t.Errorf("size=%d last=%s, want a bounded log that still ends with the last entry", info.Size(), current[len(current)-1].Hash)
	}
	// lumberjack removes the extra backups in the background.
	deadline := time.Now().Add(2 * time.Second)
	for len(backups) != 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		backups, _ = filepath.Glob(filepath.Join(dir, "verdicts-*.jsonl"))
	}
	if len(backups) != 1 {
		t.Errorf("backups = %v, want exactly one", backups)
	}
}

// TestVerdictLogTruncates: with rotation off, the log is emptied at the limit and no
// second file is made.
func TestVerdictLogTruncates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verdicts.jsonl")
	log, err := openVerdictLog(path, logging.RotateOptions{MaxSizeMB: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer log.close()
	const entries = 12000 // about 1.4 MB of lines
	for i := 0; i < entries; i++ {
		log.write(time.Unix(1_700_000_000, 0), LogEntry{Type: "file", Hash: fmt.Sprintf("%032d", i), Name: "some name long enough to fill the log"})
	}
	raw, _ := os.ReadFile(path)
	files, _ := os.ReadDir(dir)
	first, _, _ := strings.Cut(string(raw), "\n")
	t.Logf("input: %d entries, limit 1 MB, rotation off output: %d bytes, %d files, first line %q", entries, len(raw), len(files), first)
	if len(raw) > 1<<20 || len(files) != 1 || first != `{"type":"truncated"}` {
		t.Errorf("size=%d files=%d first=%q, want one bounded file starting with the JSON marker", len(raw), len(files), first)
	}
}
