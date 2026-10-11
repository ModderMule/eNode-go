package ed2k

import (
	"net"

	"enode/storage"
)

// ContentFilter decides which files this server refuses to index and to serve, and
// which publishers it has banned for offering them. Declared here rather than imported
// for the same reason AccessFilter is: the protocol package gains no dependency on the
// implementation (contentfilter) and a test can substitute a stub.
//
// Every method is called from connection and UDP worker goroutines at once, so
// implementations must be safe for concurrent use.
type ContentFilter interface {
	// CheckOffer judges one offered file. refused means it must not be indexed;
	// sanction means the refusal also counts against the publisher.
	CheckOffer(hash []byte, name string) (refused, sanction bool)
	// Withheld reports whether a file must not be served. An empty name tests the
	// hash alone, which is all a source request carries.
	Withheld(hash []byte, name string) bool
	// QueryBlocked reports whether a search with these terms is answered with nothing.
	QueryBlocked(terms []string) bool
	// BanThreshold is how many distinct sanctioned files one session may offer before
	// it is dropped and banned. Zero means never.
	BanThreshold() int
	// Ban refuses a publisher at login for a while, Banned reports whether one is.
	Ban(userHash []byte, ip net.IP)
	Banned(userHash []byte, ip net.IP) bool
}

// msgBanlisted is sent before a session is dropped for offering ban-list files, and
// msgBanned when such a publisher logs in again. "ERROR" so the client shows them and
// logs them as an error, like msgHardFileLimit; without one the user sees a server that
// keeps closing the connection for no stated reason.
const (
	msgBanlisted = "ERROR : You are sharing files this server does not accept. Closing the connection."
	msgBanned    = "ERROR : You are temporarily banned from this server for sharing files it does not accept."
)

// SetContentFilter attaches the hash-list and keyword filter. Like SetAccessFilter it
// is called before any listener binds; nil disables filtering.
func (s *ServerRuntime) SetContentFilter(f ContentFilter) {
	s.Content = f
}

// checkOffer judges one offered record; see ContentFilter.CheckOffer.
func (s *ServerRuntime) checkOffer(hash []byte, name string) (refused, sanction bool) {
	if s.Content == nil {
		return false, false
	}
	return s.Content.CheckOffer(hash, name)
}

// withheldHash reports whether source requests for hash are answered with nothing.
func (s *ServerRuntime) withheldHash(hash []byte) bool {
	return s.Content != nil && s.Content.Withheld(hash, "")
}

// queryBlocked reports whether a search asks for something the filter refuses by name.
func (s *ServerRuntime) queryBlocked(expr *storage.SearchExpr) bool {
	if s.Content == nil {
		return false
	}
	terms := searchTerms(expr, nil)
	return len(terms) > 0 && s.Content.QueryBlocked(terms)
}

// withholdFiles drops the rows the filter refuses to serve. It covers everything a
// search can return — the own index, other servers' files and catalogue rows — because
// a row from any of them may have been indexed before its hash or keyword was listed.
//
// The input is never modified: it can alias a result another search shares (the peer
// mirror, the catalogue cache), so the survivors are copied once the first refused row
// is found, and the common nothing-refused case allocates nothing.
func (s *ServerRuntime) withholdFiles(files []storage.File) []storage.File {
	if s.Content == nil {
		return files
	}
	for i := range files {
		if !s.Content.Withheld(files[i].Hash, files[i].Name) {
			continue
		}
		kept := make([]storage.File, i, len(files)-1)
		copy(kept, files[:i])
		for _, file := range files[i+1:] {
			if !s.Content.Withheld(file.Hash, file.Name) {
				kept = append(kept, file)
			}
		}
		return kept
	}
	return files
}

// noteBanlistHit records a sanctioned offer and reports whether the session has now
// offered more distinct such files than the filter tolerates. Distinct, so a client
// republishing one file every keepalive cycle is counted once.
func (c *tcpClient) noteBanlistHit(hash []byte) bool {
	threshold := c.server.Content.BanThreshold()
	if threshold <= 0 || len(hash) != 16 {
		return false
	}
	if c.banlistHits == nil {
		c.banlistHits = make(map[[16]byte]struct{})
	}
	c.banlistHits[[16]byte(hash)] = struct{}{}
	return len(c.banlistHits) > threshold
}

// recordName is the file name an offered record carries, or "" when it has none.
func recordName(record FileRecord) string {
	name, _ := record.Tags["name"].(string)
	return name
}

// searchTerms collects the words a search asks for. The excluded side of an AND-NOT is
// left out: asking for results without a word is not asking for it.
func searchTerms(expr *storage.SearchExpr, terms []string) []string {
	if expr == nil {
		return terms
	}
	switch expr.Kind {
	case storage.SearchText:
		if expr.Text != "" {
			terms = append(terms, expr.Text)
		}
	case storage.SearchString:
		if expr.TagType == storage.SearchTermTag && expr.ValueString != "" {
			terms = append(terms, expr.ValueString)
		}
	case storage.SearchAnd, storage.SearchOr:
		terms = searchTerms(expr.Left, terms)
		terms = searchTerms(expr.Right, terms)
	case storage.SearchAndNot:
		terms = searchTerms(expr.Left, terms)
	}
	return terms
}
