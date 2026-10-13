package spamfilter

import "strings"

const (
	// profileMinFiles is how many files a session must have offered before its share
	// is judged at all.
	profileMinFiles = 10
	// baitMinSize and baitMaxSize bound a "small program": eMule's own range for the
	// files spam servers push (srchybrid/SearchList.cpp:1030).
	baitMinSize = 100 << 10
	baitMaxSize = 10 << 20
	// templateSuffixTokens is how many trailing words make a name's template, and
	// templateMaxGroups how many templates one session is tracked for.
	templateSuffixTokens = 3
	templateMaxGroups    = 64
)

// Profile is what one session's share looks like so far. It keeps counters, never the
// names: a share can be tens of thousands of files.
//
// A file offered twice is counted twice. A client re-offers a file once, when its
// download completes, which moves no share across a threshold.
type Profile struct {
	files int
	// bait counts small programs and archives named like a video release.
	bait int
	// templates groups names by their last words.
	templates map[string]*templateGroup
}

// templateGroup is the names that end in the same words.
type templateGroup struct {
	count            int
	minSize, maxSize uint64
	// firsts holds the distinct first words, at most count of them.
	firsts map[string]struct{}
}

// Add counts one offered file.
func (p *Profile) Add(r Record) {
	p.files++
	tokens := nameTokens(r.Name)
	if kindOfName(r.Name) == kindProgram && r.Size > baitMinSize && r.Size < baitMaxSize && hasVideoReleaseWord(tokens) {
		p.bait++
	}
	// A template needs a word in front of it that can vary.
	if len(tokens) <= templateSuffixTokens {
		return
	}
	key := strings.Join(tokens[len(tokens)-templateSuffixTokens:], " ")
	g := p.templates[key]
	if g == nil {
		if len(p.templates) >= templateMaxGroups {
			return
		}
		if p.templates == nil {
			p.templates = make(map[string]*templateGroup)
		}
		g = &templateGroup{minSize: r.Size, maxSize: r.Size, firsts: make(map[string]struct{})}
		p.templates[key] = g
	}
	g.count++
	g.minSize, g.maxSize = min(g.minSize, r.Size), max(g.maxSize, r.Size)
	g.firsts[tokens[0]] = struct{}{}
}

// Files is how many files the session has offered.
func (p *Profile) Files() int { return p.files }

// Reasons judges the share. Nil below profileMinFiles files and for an ordinary share.
func (p *Profile) Reasons() []ReasonPoints {
	if p.files < profileMinFiles {
		return nil
	}
	var out []ReasonPoints
	// Half the share is small programs passed off as video releases.
	if p.bait*2 >= p.files {
		out = append(out, ReasonPoints{Reason: ReasonPublisherBait, Points: pointsPublisher})
	}
	for _, g := range p.templates {
		if g.isTemplate(p.files) {
			out = append(out, ReasonPoints{Reason: ReasonPublisherTemplate, Points: pointsPublisher})
			break
		}
	}
	return out
}

// isTemplate reports whether the group is one name with the leading words swapped:
// most of the share ends in the same words, starts differently every time, and is the
// same size within a tenth. Episodes of a series end alike too, but start alike as
// well; releases of one group end alike, but differ in size.
func (g *templateGroup) isTemplate(files int) bool {
	return g.count*10 >= files*8 &&
		len(g.firsts)*10 >= g.count*8 &&
		g.maxSize <= g.minSize+g.minSize/10
}

func hasVideoReleaseWord(tokens []string) bool {
	for _, t := range tokens {
		if _, ok := videoReleaseWords[t]; ok {
			return true
		}
	}
	return false
}
