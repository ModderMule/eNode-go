// Package contentfilter decides which files this server refuses to index and to serve.
//
// netfilter answers "may this address talk to us"; this package answers "may this file
// be published here". It holds three eD2K hash lists in the format the ed2k-server
// update service publishes, plus the operator's filter.keywords:
//
//   - the ban list refuses a file and counts against whoever offered it;
//   - the filter list refuses a file and accuses nobody — decoys and takedowns, which
//     an ordinary user holds without having done anything;
//   - the whitelist overrides both lists and the keywords;
//   - a keyword in the file name refuses the file, and counts against whoever offered
//     it under a threshold of its own.
//
// Each hash list may have a local twin: a file the operator owns, which adds to the
// list and which the updater never replaces.
package contentfilter

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"enode/logging"
)

// Config describes the content filter as it appears in enode.config.yaml. A list is
// enabled by naming its file; an all-empty Config yields a nil Filter.
type Config struct {
	// Keywords is filter.keywords: bar-separated whole words.
	Keywords string
	// BanlistFile, FilterFile and WhitelistFile are the resolved list paths, or "" for
	// a list that is off.
	BanlistFile   string
	FilterFile    string
	WhitelistFile string
	// LocalBanlistFile, LocalFilterFile and LocalWhitelistFile are the operator's own
	// additions to the three lists, or "" for none. Such a file need not exist: it is
	// created by the first AddLocal.
	LocalBanlistFile   string
	LocalFilterFile    string
	LocalWhitelistFile string
	// AllowMissing lets an enabled list start empty when its file does not exist yet.
	// Set when the updater is on, since the first download is what creates the file.
	AllowMissing bool
	// ReloadMinutes re-reads changed list files on a timer. Zero disables reloading.
	ReloadMinutes int
	// BanThreshold is how many distinct ban-list files one session may offer before it
	// is disconnected and banned. Zero disables the sanction.
	BanThreshold int
	// KeywordBanThreshold is how many distinct keyword-refused files one session may
	// offer: the session that reaches it is disconnected and banned. Zero disables the
	// sanction.
	KeywordBanThreshold int
	// BanMinutes is how long such a ban lasts.
	BanMinutes int
	// BanFile is where the bans are kept across restarts, or "" for in memory only.
	BanFile string
	// KeepEmpty returns a Filter even when nothing is configured, so SetKeywords can
	// give it keywords later. Set by the server, whose config reload does that.
	KeepEmpty bool
}

// Stats is the admin view of the filter.
type Stats struct {
	BanlistEntries   int
	FilterEntries    int
	WhitelistEntries int
	Keywords         int
	// RefusedBanlist, RefusedFilter and RefusedKeyword count offered files refused by
	// each layer. WithheldServed counts rows and source requests withheld when serving,
	// BlockedQueries the searches answered with nothing because of their own terms.
	RefusedBanlist int64
	RefusedFilter  int64
	RefusedKeyword int64
	WithheldServed int64
	BlockedQueries int64
	// Bans is how many user hashes and addresses are currently refused at login.
	Bans int
}

// ListInfo is one enabled hash list file as it is on disk and in memory.
type ListInfo struct {
	Name     string
	Path     string
	Exists   bool
	Size     int64
	Modified time.Time
	// Entries is how many hashes the loaded list holds, which lags the file until
	// the next reload.
	Entries int
}

// verdict is why a file is refused.
type verdict int

const (
	verdictAllow verdict = iota
	verdictBanlist
	verdictFilter
	verdictKeyword
)

// LocalList names one of the operator's own lists.
type LocalList string

const (
	LocalBanlist   LocalList = "banlist"
	LocalFilter    LocalList = "filter"
	LocalWhitelist LocalList = "whitelist"
)

// ErrLocalList is returned for a list name that is none of the three, and
// ErrNoLocalLists when the local lists are not configured.
var (
	ErrLocalList    = errors.New("list must be banlist, filter or whitelist")
	ErrNoLocalLists = errors.New("the local hash lists are not enabled")
)

// listSlot is one hash list, its file, and what that file looked like when it was last
// read, so the reload timer can skip an unchanged multi-megabyte list.
type listSlot struct {
	name string
	path string
	// optional marks a local list, whose missing file is an empty list.
	optional bool
	list     atomic.Pointer[HashList]
	modTime  atomic.Int64
	size     atomic.Int64
}

// Filter is the seam the protocol layer consults. The lists sit behind atomic pointers:
// a reload replaces one wholesale, and the read path runs for every offered file and
// every served row. The keywords sit behind one too: SetKeywords replaces them when the
// config is reloaded. A nil *Filter refuses nothing.
type Filter struct {
	cfg       Config
	banlist   listSlot
	filter    listSlot
	whitelist listSlot
	// The operator's own additions to the three lists above.
	localBanlist   listSlot
	localFilter    listSlot
	localWhitelist listSlot
	// appendMu serializes AddLocal's writes.
	appendMu sync.Mutex
	keywords atomic.Pointer[Matcher]
	// The sanction settings, replaced by SetSanctions when the config is reloaded.
	banThreshold        atomic.Int64
	keywordBanThreshold atomic.Int64
	banMinutes          atomic.Int64
	bans                *banList
	banCount            atomic.Int64
	stats               struct {
		refusedBanlist atomic.Int64
		refusedFilter  atomic.Int64
		refusedKeyword atomic.Int64
		withheld       atomic.Int64
		blockedQueries atomic.Int64
	}
}

// New builds a Filter from config and starts the reload timer.
//
// An enabled list whose file is missing is an error, because the operator named it and
// silently indexing everything it was meant to refuse is the wrong failure mode —
// unless AllowMissing says the updater is about to fetch it. Nothing enabled returns
// (nil, nil): the caller stores no filter and pays nothing. KeepEmpty returns an idle
// Filter instead.
func New(ctx context.Context, cfg Config) (*Filter, error) {
	keywords, err := NewMatcher(cfg.Keywords)
	if err != nil {
		return nil, fmt.Errorf("filter.keywords: %w", err)
	}
	if !cfg.KeepEmpty && keywords.Empty() && cfg.BanlistFile == "" && cfg.FilterFile == "" && cfg.WhitelistFile == "" &&
		cfg.LocalBanlistFile == "" && cfg.LocalFilterFile == "" && cfg.LocalWhitelistFile == "" {
		return nil, nil
	}
	f := &Filter{cfg: cfg, bans: newBanList(cfg.BanFile)}
	f.keywords.Store(keywords)
	f.SetSanctions(cfg.BanThreshold, cfg.KeywordBanThreshold, cfg.BanMinutes)
	if err := f.bans.load(); err != nil {
		return nil, err
	}
	f.banCount.Store(int64(f.bans.sweep()))
	f.banlist.name, f.banlist.path = "hash ban list", cfg.BanlistFile
	f.filter.name, f.filter.path = "hash filter list", cfg.FilterFile
	f.whitelist.name, f.whitelist.path = "hash whitelist", cfg.WhitelistFile
	f.localBanlist = listSlot{name: "local hash ban list", path: cfg.LocalBanlistFile, optional: true}
	f.localFilter = listSlot{name: "local hash filter list", path: cfg.LocalFilterFile, optional: true}
	f.localWhitelist = listSlot{name: "local hash whitelist", path: cfg.LocalWhitelistFile, optional: true}

	for _, slot := range f.slots() {
		if slot.path == "" {
			continue
		}
		err := f.loadSlot(slot, true)
		switch {
		case err == nil:
		case cfg.AllowMissing && errors.Is(err, fs.ErrNotExist):
			logging.Warnf("content filter: %s %s does not exist yet; starting empty until the first update", slot.name, slot.path)
		default:
			return nil, err
		}
	}
	if !keywords.Empty() {
		logging.Infof("content filter: %d keyword(s)", keywords.Len())
	}
	if cfg.ReloadMinutes > 0 {
		go f.reloadLoop(ctx, time.Duration(cfg.ReloadMinutes)*time.Minute)
	}
	return f, nil
}

// CheckOffer judges one offered file. refused means it must not be indexed. banlist
// and keyword say which layer refused it when the refusal also counts against the
// publisher; a filter-list hit sets neither.
func (f *Filter) CheckOffer(hash []byte, name string) (refused, banlist, keyword bool) {
	if f == nil {
		return false, false, false
	}
	switch f.judge(hash, name) {
	case verdictBanlist:
		f.stats.refusedBanlist.Add(1)
		return true, true, false
	case verdictFilter:
		f.stats.refusedFilter.Add(1)
		return true, false, false
	case verdictKeyword:
		f.stats.refusedKeyword.Add(1)
		return true, false, true
	}
	return false, false, false
}

// Withheld reports whether a file must not be served: left out of search results, and
// answered with no sources. An empty name tests the hash lists only, which is all a
// source request can be tested against.
func (f *Filter) Withheld(hash []byte, name string) bool {
	if f == nil {
		return false
	}
	if f.judge(hash, name) == verdictAllow {
		return false
	}
	f.stats.withheld.Add(1)
	return true
}

// SetKeywords replaces the keywords with a new filter.keywords value; "" removes them.
// Offers and searches are judged against the new words from then on. A file indexed
// under the old words stays indexed, and is withheld from search results if its name
// matches a new one. A value that does not parse changes nothing.
func (f *Filter) SetKeywords(keywords string) error {
	m, err := NewMatcher(keywords)
	if err != nil {
		return fmt.Errorf("filter.keywords: %w", err)
	}
	if f == nil {
		if m.Empty() {
			return nil
		}
		return errors.New("filter.keywords: no content filter to give them to")
	}
	f.keywords.Store(m)
	logging.Infof("content filter: %d keyword(s)", m.Len())
	return nil
}

// SetSanctions replaces the two sanction thresholds and the ban length. A session is
// measured against the new thresholds from its next refused file on, and a ban already
// running keeps the length it was given.
func (f *Filter) SetSanctions(banThreshold, keywordBanThreshold, banMinutes int) {
	if f == nil {
		return
	}
	f.banThreshold.Store(int64(banThreshold))
	f.keywordBanThreshold.Store(int64(keywordBanThreshold))
	f.banMinutes.Store(int64(banMinutes))
}

// Idle reports whether the filter has nothing to refuse by: no keywords and no hash
// list. Only a filter built with KeepEmpty can be idle. Bans are apart from this and
// apply either way.
func (f *Filter) Idle() bool {
	if f == nil {
		return true
	}
	for _, slot := range f.slots() {
		if slot.path != "" {
			return false
		}
	}
	return f.keywords.Load().Empty()
}

// Whitelisted reports whether hash is on the whitelist or its local twin.
func (f *Filter) Whitelisted(hash []byte) bool {
	return f != nil && listed(&f.whitelist, &f.localWhitelist, hash)
}

// LocalListsEnabled reports whether AddLocal has somewhere to write.
func (f *Filter) LocalListsEnabled() bool {
	return f != nil && f.cfg.LocalBanlistFile != "" && f.cfg.LocalFilterFile != "" && f.cfg.LocalWhitelistFile != ""
}

// AddLocal appends hash to one of the operator's lists and loads it at once. comment
// is written after the hash, by convention the file name that justified the entry. A
// hash the list already holds is left alone.
func (f *Filter) AddLocal(list LocalList, hash []byte, comment string) error {
	if !f.LocalListsEnabled() {
		return ErrNoLocalLists
	}
	if len(hash) != HashSize {
		return fmt.Errorf("file hash is %d bytes, want %d", len(hash), HashSize)
	}
	var slot *listSlot
	switch list {
	case LocalBanlist:
		slot = &f.localBanlist
	case LocalFilter:
		slot = &f.localFilter
	case LocalWhitelist:
		slot = &f.localWhitelist
	default:
		return ErrLocalList
	}
	f.appendMu.Lock()
	defer f.appendMu.Unlock()
	if slot.list.Load().Contains(hash) {
		return nil
	}
	if err := appendHashLine(slot.path, hash, comment); err != nil {
		return fmt.Errorf("%s: %w", slot.name, err)
	}
	return f.loadSlot(slot, true)
}

// QueryBlocked reports whether a search asks for one of the keywords itself. Such a
// search is answered with nothing, without consulting the index.
func (f *Filter) QueryBlocked(terms []string) bool {
	if f == nil {
		return false
	}
	keywords := f.keywords.Load()
	if keywords.Empty() {
		return false
	}
	for _, term := range terms {
		if keywords.Match(term) {
			f.stats.blockedQueries.Add(1)
			return true
		}
	}
	return false
}

// BanThreshold is how many distinct ban-list files a session may offer before it is
// sanctioned. Zero means never.
func (f *Filter) BanThreshold() int {
	if f == nil {
		return 0
	}
	return int(f.banThreshold.Load())
}

// KeywordBanThreshold is how many distinct keyword-refused files get a session
// sanctioned. Zero means never.
func (f *Filter) KeywordBanThreshold() int {
	if f == nil {
		return 0
	}
	return int(f.keywordBanThreshold.Load())
}

// Ban refuses a publisher at login, by user hash and by address, for BanMinutes. reason
// is what the admin surface shows for it.
func (f *Filter) Ban(userHash []byte, ip net.IP, reason string) {
	if f == nil {
		return
	}
	minutes := f.banMinutes.Load()
	if minutes <= 0 {
		return
	}
	f.bans.add(userHash, ip, time.Duration(minutes)*time.Minute, reason)
	f.banCount.Store(int64(f.bans.sweep()))
}

// BanFor refuses a publisher at login for d, whatever BanMinutes says. It is the
// operator's own ban, set from the admin surface; one of userHash and ip may be nil.
func (f *Filter) BanFor(userHash []byte, ip net.IP, d time.Duration, reason string) {
	if f == nil || d <= 0 {
		return
	}
	f.bans.add(userHash, ip, d, reason)
	f.banCount.Store(int64(f.bans.sweep()))
}

// BanKey bans what a BanEntry.Key names for d.
func (f *Filter) BanKey(key string, d time.Duration, reason string) error {
	userHash, ip, err := parseBanKey(key)
	if err != nil {
		return err
	}
	f.BanFor(userHash, ip, d, reason)
	return nil
}

// Bans lists the bans still running, soonest to expire first.
func (f *Filter) Bans() []BanEntry {
	if f == nil {
		return nil
	}
	return f.bans.list()
}

// Unban lifts the ban a BanEntry.Key names and reports whether there was one.
func (f *Filter) Unban(key string) (bool, error) {
	if f == nil {
		return false, nil
	}
	userHash, ip, err := parseBanKey(key)
	if err != nil {
		return false, err
	}
	internal := hashKey(userHash)
	if internal == "" {
		internal = ipKey(ip)
	}
	removed := f.bans.remove(internal)
	f.banCount.Store(int64(f.bans.sweep()))
	return removed, nil
}

// Lists describes the enabled hash list files for the admin surface.
func (f *Filter) Lists() []ListInfo {
	if f == nil {
		return nil
	}
	var out []ListInfo
	for _, slot := range f.slots() {
		if slot.path == "" {
			continue
		}
		info := ListInfo{Name: slot.name, Path: slot.path, Entries: slot.list.Load().Len()}
		if st, err := os.Stat(slot.path); err == nil {
			info.Exists, info.Size, info.Modified = true, st.Size(), st.ModTime()
		}
		out = append(out, info)
	}
	return out
}

// Banned reports whether a login from this user hash or address is refused.
func (f *Filter) Banned(userHash []byte, ip net.IP) bool {
	if f == nil || f.banCount.Load() == 0 {
		return false
	}
	return f.bans.banned(userHash, ip)
}

// Reload re-reads every enabled list now, whether or not its file looks changed. The
// updater calls it after installing a file. A list that fails to load keeps its
// previous contents; the first such error is returned.
func (f *Filter) Reload() error {
	if f == nil {
		return nil
	}
	var first error
	for _, slot := range f.slots() {
		if slot.path == "" {
			continue
		}
		if err := f.loadSlot(slot, true); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Stats reports list sizes and counters for the admin surface.
func (f *Filter) Stats() Stats {
	if f == nil {
		return Stats{}
	}
	return Stats{
		BanlistEntries:   f.banlist.list.Load().Len() + f.localBanlist.list.Load().Len(),
		FilterEntries:    f.filter.list.Load().Len() + f.localFilter.list.Load().Len(),
		WhitelistEntries: f.whitelist.list.Load().Len() + f.localWhitelist.list.Load().Len(),
		Keywords:         f.keywords.Load().Len(),
		RefusedBanlist:   f.stats.refusedBanlist.Load(),
		RefusedFilter:    f.stats.refusedFilter.Load(),
		RefusedKeyword:   f.stats.refusedKeyword.Load(),
		WithheldServed:   f.stats.withheld.Load(),
		BlockedQueries:   f.stats.blockedQueries.Load(),
		Bans:             int(f.banCount.Load()),
	}
}

func (f *Filter) slots() [6]*listSlot {
	return [6]*listSlot{&f.banlist, &f.filter, &f.whitelist, &f.localBanlist, &f.localFilter, &f.localWhitelist}
}

// listed reports whether hash is on a list or its local twin.
func listed(slot, local *listSlot, hash []byte) bool {
	return slot.list.Load().Contains(hash) || local.list.Load().Contains(hash)
}

// judge applies the layers in order. The whitelist comes first and beats everything:
// an operator who put a hash there has looked at the file, and the mistakes that need
// overriding are keyword matches as often as hash ones. The filter list comes before
// the keywords so a decoy with a spam name is counted as what the operator ruled it.
func (f *Filter) judge(hash []byte, name string) verdict {
	if listed(&f.whitelist, &f.localWhitelist, hash) {
		return verdictAllow
	}
	if listed(&f.banlist, &f.localBanlist, hash) {
		return verdictBanlist
	}
	if listed(&f.filter, &f.localFilter, hash) {
		return verdictFilter
	}
	if name != "" && f.keywords.Load().Match(name) {
		return verdictKeyword
	}
	return verdictAllow
}

// loadSlot reads one list file and swaps it in. Without force, a file whose size and
// modification time are unchanged is left alone.
func (f *Filter) loadSlot(slot *listSlot, force bool) error {
	info, err := os.Stat(slot.path)
	if slot.optional && errors.Is(err, fs.ErrNotExist) {
		slot.list.Store(nil)
		slot.modTime.Store(0)
		slot.size.Store(0)
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", slot.name, err)
	}
	if !force && info.ModTime().UnixNano() == slot.modTime.Load() && info.Size() == slot.size.Load() {
		return nil
	}
	list, err := LoadHashList(slot.path)
	if err != nil {
		return fmt.Errorf("%s: %w", slot.name, err)
	}
	slot.list.Store(list)
	slot.modTime.Store(info.ModTime().UnixNano())
	slot.size.Store(info.Size())
	logging.Infof("content filter: %s %s loaded, %d hash(es), %d line(s) skipped",
		slot.name, slot.path, list.Len(), list.Skipped)
	return nil
}

// reloadLoop re-reads changed list files on a timer and sweeps expired bans. A failed
// reload keeps the previous list: an operator mid-edit must not disarm the filter.
func (f *Filter) reloadLoop(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			for _, slot := range f.slots() {
				if slot.path == "" {
					continue
				}
				if err := f.loadSlot(slot, false); err != nil && !errors.Is(err, fs.ErrNotExist) {
					logging.Errorf("content filter: reload failed, keeping the previous list: %v", err)
				}
			}
			f.banCount.Store(int64(f.bans.sweep()))
		case <-ctx.Done():
			return
		}
	}
}

// appendHashLine adds "<hash> ; <comment>" to a hash list file, creating it. A file
// edited by hand may lack its last newline, so one is written first when it does.
func appendHashLine(path string, hash []byte, comment string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	line := fmt.Sprintf("%x", hash)
	// One line per entry: a file name may hold anything, a line break included.
	comment = strings.Join(strings.FieldsFunc(comment, func(r rune) bool { return r < 0x20 || r == 0x7f }), " ")
	if comment != "" {
		line += " ; " + comment
	}
	if info, err := file.Stat(); err == nil && info.Size() > 0 {
		last := make([]byte, 1)
		if _, err := file.ReadAt(last, info.Size()-1); err == nil && last[0] != '\n' {
			line = "\n" + line
		}
	}
	if _, err := file.WriteString(line + "\n"); err != nil {
		return err
	}
	return file.Sync()
}
