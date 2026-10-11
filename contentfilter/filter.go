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
//   - a keyword in the file name refuses the file, again without accusing anybody.
package contentfilter

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
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
	// AllowMissing lets an enabled list start empty when its file does not exist yet.
	// Set when the updater is on, since the first download is what creates the file.
	AllowMissing bool
	// ReloadMinutes re-reads changed list files on a timer. Zero disables reloading.
	ReloadMinutes int
	// BanThreshold is how many distinct ban-list files one session may offer before it
	// is disconnected and banned. Zero disables the sanction.
	BanThreshold int
	// BanMinutes is how long such a ban lasts.
	BanMinutes int
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

// verdict is why a file is refused.
type verdict int

const (
	verdictAllow verdict = iota
	verdictBanlist
	verdictFilter
	verdictKeyword
)

// listSlot is one hash list, its file, and what that file looked like when it was last
// read, so the reload timer can skip an unchanged multi-megabyte list.
type listSlot struct {
	name    string
	path    string
	list    atomic.Pointer[HashList]
	modTime atomic.Int64
	size    atomic.Int64
}

// Filter is the seam the protocol layer consults. The lists sit behind atomic pointers:
// a reload replaces one wholesale, and the read path runs for every offered file and
// every served row. A nil *Filter refuses nothing.
type Filter struct {
	cfg       Config
	banlist   listSlot
	filter    listSlot
	whitelist listSlot
	keywords  *Matcher
	bans      *banList
	banCount  atomic.Int64
	stats     struct {
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
// (nil, nil): the caller stores no filter and pays nothing.
func New(ctx context.Context, cfg Config) (*Filter, error) {
	keywords, err := NewMatcher(cfg.Keywords)
	if err != nil {
		return nil, fmt.Errorf("filter.keywords: %w", err)
	}
	if keywords.Empty() && cfg.BanlistFile == "" && cfg.FilterFile == "" && cfg.WhitelistFile == "" {
		return nil, nil
	}
	f := &Filter{cfg: cfg, keywords: keywords, bans: newBanList()}
	f.banlist.name, f.banlist.path = "hash ban list", cfg.BanlistFile
	f.filter.name, f.filter.path = "hash filter list", cfg.FilterFile
	f.whitelist.name, f.whitelist.path = "hash whitelist", cfg.WhitelistFile

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

// CheckOffer judges one offered file. refused means it must not be indexed; sanction
// means the refusal also counts against the publisher, which only a ban-list hit does.
func (f *Filter) CheckOffer(hash []byte, name string) (refused, sanction bool) {
	if f == nil {
		return false, false
	}
	switch f.judge(hash, name) {
	case verdictBanlist:
		f.stats.refusedBanlist.Add(1)
		return true, true
	case verdictFilter:
		f.stats.refusedFilter.Add(1)
		return true, false
	case verdictKeyword:
		f.stats.refusedKeyword.Add(1)
		return true, false
	}
	return false, false
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

// QueryBlocked reports whether a search asks for one of the keywords itself. Such a
// search is answered with nothing, without consulting the index.
func (f *Filter) QueryBlocked(terms []string) bool {
	if f == nil || f.keywords.Empty() {
		return false
	}
	for _, term := range terms {
		if f.keywords.Match(term) {
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
	return f.cfg.BanThreshold
}

// Ban refuses a publisher at login, by user hash and by address, for BanMinutes.
func (f *Filter) Ban(userHash []byte, ip net.IP) {
	if f == nil || f.cfg.BanMinutes <= 0 {
		return
	}
	f.bans.add(userHash, ip, time.Duration(f.cfg.BanMinutes)*time.Minute)
	f.banCount.Store(int64(f.bans.sweep()))
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
		BanlistEntries:   f.banlist.list.Load().Len(),
		FilterEntries:    f.filter.list.Load().Len(),
		WhitelistEntries: f.whitelist.list.Load().Len(),
		Keywords:         f.keywords.Len(),
		RefusedBanlist:   f.stats.refusedBanlist.Load(),
		RefusedFilter:    f.stats.refusedFilter.Load(),
		RefusedKeyword:   f.stats.refusedKeyword.Load(),
		WithheldServed:   f.stats.withheld.Load(),
		BlockedQueries:   f.stats.blockedQueries.Load(),
		Bans:             int(f.banCount.Load()),
	}
}

func (f *Filter) slots() [3]*listSlot {
	return [3]*listSlot{&f.banlist, &f.filter, &f.whitelist}
}

// judge applies the layers in order. The whitelist comes first and beats everything:
// an operator who put a hash there has looked at the file, and the mistakes that need
// overriding are keyword matches as often as hash ones. The filter list comes before
// the keywords so a decoy with a spam name is counted as what the operator ruled it.
func (f *Filter) judge(hash []byte, name string) verdict {
	if f.whitelist.list.Load().Contains(hash) {
		return verdictAllow
	}
	if f.banlist.list.Load().Contains(hash) {
		return verdictBanlist
	}
	if f.filter.list.Load().Contains(hash) {
		return verdictFilter
	}
	if name != "" && f.keywords.Match(name) {
		return verdictKeyword
	}
	return verdictAllow
}

// loadSlot reads one list file and swaps it in. Without force, a file whose size and
// modification time are unchanged is left alone.
func (f *Filter) loadSlot(slot *listSlot, force bool) error {
	info, err := os.Stat(slot.path)
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
