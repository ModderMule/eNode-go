// Package spamfilter scores how likely an offered file is spam or a fake, and whether
// a publisher's share looks like one made to be found rather than shared.
//
// contentfilter refuses what a list or a word list names; this package judges what
// neither names, from what a publisher says about a file and from the share it comes
// in. It only observes: a verdict is listed and logged, and nothing is refused, withheld
// or banned because of it. See docs/spam-detection.md.
//
// The scale and the reason names are those of eMuleQt's FakeFileDetector, so a verdict
// reads the same on both sides.
package spamfilter

import (
	"strings"
	"unicode"

	"enode/storage"
)

// Reason is why a file or a publisher scored. The file reasons carry the ids eMuleQt
// uses for the same checks.
type Reason string

const (
	ReasonClaimedTypeMismatch     Reason = "claimed_type_mismatch"
	ReasonImplausibleMediaLength  Reason = "implausible_media_length"
	ReasonImplausibleMediaBitrate Reason = "implausible_media_bitrate"
	ReasonMediaSizeMismatch       Reason = "media_size_mismatch"
	// ReasonPublisherBait and ReasonPublisherTemplate are about the session the file
	// came in, and are added to every file it offers from then on.
	ReasonPublisherBait     Reason = "publisher_bait_programs"
	ReasonPublisherTemplate Reason = "publisher_name_template"
)

// Points per reason.
const (
	pointsClaimedTypeMismatch = 15
	pointsMediaLength         = 15
	pointsMediaBitrate        = 15
	pointsMediaSizeMismatch   = 15
	pointsPublisher           = 30

	maxScore = 100
)

// Band is what a score amounts to.
type Band int

const (
	BandClean Band = iota
	BandCaution
	BandSuspect
	BandSpam
)

// The lowest score of each band above BandClean.
const (
	cautionScore = 25
	suspectScore = 50
	spamScore    = 75
)

// Record is what a publisher says about one file.
type Record struct {
	Hash []byte
	Name string
	Size uint64
	// Type is the eD2K file type the publisher claimed ("Video", "Audio", "Pro", ...),
	// or "" when it claimed none.
	Type        string
	LengthSec   uint32
	BitrateKbps uint32
}

// ReasonPoints is one reason and what it added to the score.
type ReasonPoints struct {
	Reason Reason `json:"reason"`
	Points int    `json:"points"`
}

// Verdict is the score of one file. Each reason counts once; the score is capped at 100.
type Verdict struct {
	Score   int
	Reasons []ReasonPoints
	Band    Band
}

// String is the band's name as the admin surface shows it.
func (b Band) String() string {
	switch b {
	case BandCaution:
		return "caution"
	case BandSuspect:
		return "suspect"
	case BandSpam:
		return "spam"
	}
	return "clean"
}

// Assess scores one record on what it says about itself. publisher holds the reasons
// its session has earned, which count against every file of that session.
func Assess(r Record, publisher []ReasonPoints) Verdict {
	var v Verdict
	claimed, named := kindOfType(r.Type), kindOfName(r.Name)
	// Only media against program: the two a claimed type can be trusted to tell apart.
	if (claimed == kindMedia && named == kindProgram) || (claimed == kindProgram && named == kindMedia) {
		v.add(ReasonClaimedTypeMismatch, pointsClaimedTypeMismatch)
	}
	assessMedia(r, &v)
	for _, p := range publisher {
		v.add(p.Reason, p.Points)
	}
	for _, p := range v.Reasons {
		v.Score += p.Points
	}
	v.Score = min(v.Score, maxScore)
	v.Band = bandOf(v.Score)
	return v
}

type kind int

const (
	kindUnknown kind = iota
	kindMedia
	kindProgram
)

// executableExts are the program extensions storage.GetFileType does not know: it
// lists archives and disc images under "Pro" and nothing that runs.
var executableExts = map[string]struct{}{
	"exe": {}, "com": {}, "bat": {}, "cmd": {}, "scr": {}, "msi": {}, "pif": {}, "vbs": {},
	"lnk": {}, "apk": {}, "jar": {}, "dll": {},
}

// videoReleaseWords say a name describes a video release. Audio words are left out: a
// zipped album of a few megabytes is an ordinary file.
var videoReleaseWords = map[string]struct{}{
	"x264": {}, "x265": {}, "h264": {}, "h265": {}, "hevc": {}, "xvid": {}, "divx": {},
	"dvdrip": {}, "bdrip": {}, "brrip": {}, "bluray": {}, "webrip": {}, "webdl": {},
	"hdtv": {}, "hdrip": {}, "dvdscr": {}, "cam": {}, "hdcam": {}, "telesync": {},
	"screener": {}, "720p": {}, "1080p": {}, "2160p": {}, "480p": {},
}

func (v *Verdict) add(reason Reason, points int) {
	for _, p := range v.Reasons {
		if p.Reason == reason {
			return
		}
	}
	v.Reasons = append(v.Reasons, ReasonPoints{Reason: reason, Points: points})
}

func bandOf(score int) Band {
	switch {
	case score >= spamScore:
		return BandSpam
	case score >= suspectScore:
		return BandSuspect
	case score >= cautionScore:
		return BandCaution
	}
	return BandClean
}

// assessMedia checks length and bitrate against the size, with eMuleQt's thresholds.
func assessMedia(r Record, v *Verdict) {
	typ := storage.GetFileType(r.Name)
	if strings.EqualFold(r.Type, "Video") || strings.EqualFold(r.Type, "Audio") {
		typ = r.Type
	}
	video, audio := strings.EqualFold(typ, "Video"), strings.EqualFold(typ, "Audio")
	if !video && !audio {
		return
	}
	if length := r.LengthSec; length > 0 {
		// Very long is fine while the size still pays for it: a 27 h audiobook at 64 kbit/s.
		impliedKbps := float64(r.Size) * 8 / float64(length) / 1000
		if (video && ((r.Size >= 50<<20 && length < 60) || (length > 12*3600 && impliedKbps < 40))) ||
			(audio && ((r.Size >= 1<<20 && length < 2) || (length > 24*3600 && impliedKbps < 16))) {
			v.add(ReasonImplausibleMediaLength, pointsMediaLength)
		}
	}
	if rate := r.BitrateKbps; rate > 0 {
		if (video && (rate < 40 || rate > 500_000)) || (audio && (rate < 16 || rate > 2000)) {
			v.add(ReasonImplausibleMediaBitrate, pointsMediaBitrate)
		}
	}
	// Length x bitrate should come out near the size; real files stay within 2x.
	if r.LengthSec > 0 && r.BitrateKbps > 0 && r.Size > 0 {
		implied := float64(r.Size) * 8 / float64(r.LengthSec) / 1000
		if ratio := implied / float64(r.BitrateKbps); ratio > 3 || ratio < 1.0/3 {
			v.add(ReasonMediaSizeMismatch, pointsMediaSizeMismatch)
		}
	}
}

func kindOfType(typ string) kind {
	switch strings.ToLower(typ) {
	case "video", "audio":
		return kindMedia
	case "pro", "arc", "iso":
		return kindProgram
	}
	return kindUnknown
}

func kindOfName(name string) kind {
	switch storage.GetFileType(name) {
	case "Video", "Audio":
		return kindMedia
	case "Pro":
		return kindProgram
	}
	if _, ok := executableExts[storage.Ext(name)]; ok {
		return kindProgram
	}
	return kindUnknown
}

// nameTokens are the words of a name: runs of letters and digits, lower case.
func nameTokens(name string) []string {
	return strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}
