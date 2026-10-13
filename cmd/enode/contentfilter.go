package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"enode/admin"
	"enode/config"
	"enode/contentfilter"
	"enode/ed2k"
	"enode/storage"
)

// buildContentFilter loads the hash lists and keywords of the filter section. It
// returns nil when none is configured; every consumer treats a nil filter as off.
func buildContentFilter(ctx context.Context, cfg config.Config) (*contentfilter.Filter, error) {
	f := cfg.Filter
	fc := contentfilter.Config{
		Keywords:      f.Keywords,
		AllowMissing:  f.Update.Enabled,
		ReloadMinutes: f.ReloadMinutesOrDefault(),
		BanThreshold:  f.BanThresholdOrDefault(),
		BanMinutes:    f.BanMinutes,
		BanFile:       cfg.BanFilePath(),

		KeywordBanThreshold: f.KeywordBanThresholdOrDefault(),
	}
	if f.HashBanlist.Enabled {
		fc.BanlistFile = cfg.HashBanlistPath()
	}
	if f.HashFilter.Enabled {
		fc.FilterFile = cfg.HashFilterPath()
	}
	if f.HashWhitelist.Enabled {
		fc.WhitelistFile = cfg.HashWhitelistPath()
	}
	if f.LocalLists.Enabled {
		fc.LocalBanlistFile = config.ResolveDataPath(f.LocalLists.BanlistFile)
		fc.LocalFilterFile = config.ResolveDataPath(f.LocalLists.FilterFile)
		fc.LocalWhitelistFile = config.ResolveDataPath(f.LocalLists.WhitelistFile)
	}
	return contentfilter.New(ctx, fc)
}

// buildFilterUpdater returns the updater for the enabled hash lists, or nil when
// filter.update is off. onInstalled runs after a list was replaced.
func buildFilterUpdater(cfg config.Config, udpSecret []byte, onInstalled func()) (*contentfilter.Updater, error) {
	u := cfg.Filter.Update
	if !u.Enabled {
		return nil, nil
	}
	publicKey, err := contentfilter.ParsePublicKey(u.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("filter.update.publicKey: %w", err)
	}
	reference, err := filterReferenceIP(cfg)
	if err != nil {
		return nil, err
	}
	uc := contentfilter.UpdateConfig{
		PublicKey:    publicKey,
		AccessKey:    ed2k.DeriveUDPKey(udpSecret, reference),
		UserAgent:    "eNode-go/" + ed2k.ENodeVersionStr,
		Interval:     time.Duration(u.IntervalHours) * time.Hour,
		MinKeepRatio: u.MinKeepRatio,
	}
	if cfg.Filter.HashBanlist.Enabled {
		uc.Targets = append(uc.Targets, contentfilter.UpdateTarget{Name: "hash ban list", URL: u.BanlistURL, Path: cfg.HashBanlistPath()})
	}
	if cfg.Filter.HashFilter.Enabled {
		uc.Targets = append(uc.Targets, contentfilter.UpdateTarget{Name: "hash filter list", URL: u.FilterURL, Path: cfg.HashFilterPath()})
	}
	if cfg.Filter.HashWhitelist.Enabled {
		uc.Targets = append(uc.Targets, contentfilter.UpdateTarget{Name: "hash whitelist", URL: u.WhitelistURL, Path: cfg.HashWhitelistPath()})
	}
	return contentfilter.NewUpdater(uc, onInstalled), nil
}

// runUpdateFilters is `enode -update-filters`: fetch the hash lists once, report each
// one on out, and fail if any did not install. A running server picks the new files up
// on its next filter.reloadMinutes tick.
func runUpdateFilters(ctx context.Context, configPath string, out io.Writer) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config load failed: %w", err)
	}
	if !cfg.Filter.Update.Enabled {
		return errors.New("filter.update.enabled is false; nothing to update")
	}
	udpSecret, err := loadUDPSecret(cfg)
	if err != nil {
		return err
	}
	// The default reference IP is this server's own address, so "auto" has to be
	// resolved here as it is at startup. A failed probe leaves `address` to decide.
	if cfg.Filter.Update.ReferenceIP == "" {
		cfg.DynIP, _, _ = resolveDynIPValue(cfg.DynIP, cfg.TestURLs, 0)
	}
	updater, err := buildFilterUpdater(cfg, udpSecret, nil)
	if err != nil {
		return err
	}
	failed := 0
	for _, res := range updater.UpdateAll(ctx) {
		if res.Err != nil {
			failed++
			fmt.Fprintf(out, "%s: FAILED: %v\n", res.Name, res.Err)
			continue
		}
		previous := "no file"
		if res.Previous >= 0 {
			previous = fmt.Sprintf("%d", res.Previous)
		}
		fmt.Fprintf(out, "%s: installed, %d hash(es) (was %s)\n", res.Name, res.Entries, previous)
	}
	if failed > 0 {
		return fmt.Errorf("%d list(s) were not updated", failed)
	}
	return nil
}

// contentFilterStats is the dashboard's view of the content filter; nil when it is off.
func contentFilterStats(f *contentfilter.Filter, u *contentfilter.Updater) *admin.ContentFilterStats {
	if f == nil {
		return nil
	}
	st := f.Stats()
	out := &admin.ContentFilterStats{
		BanlistEntries:   st.BanlistEntries,
		FilterEntries:    st.FilterEntries,
		WhitelistEntries: st.WhitelistEntries,
		Keywords:         st.Keywords,
		RefusedBanlist:   st.RefusedBanlist,
		RefusedFilter:    st.RefusedFilter,
		RefusedKeyword:   st.RefusedKeyword,
		Withheld:         st.WithheldServed,
		BlockedQueries:   st.BlockedQueries,
		Bans:             st.Bans,
	}
	if u != nil {
		out.UpdateEnabled = true
		status := u.Status()
		if !status.Last.IsZero() {
			out.LastUpdate = status.Last.Format(time.RFC3339)
			out.LastUpdateOK = status.OK
			out.LastUpdateMessage = status.Message
		}
	}
	return out
}

// contentWithheld and contentQueryBlocked adapt the filter for the Meta API's search,
// whose rows from other servers and from the catalogue daemons do not pass through the
// file store. Nil when the filter is off, which the Meta API reads as "no filter".
func contentWithheld(f *contentfilter.Filter) func(hash []byte, name string) bool {
	if f == nil {
		return nil
	}
	return f.Withheld
}

func contentQueryBlocked(f *contentfilter.Filter) func(query string) bool {
	if f == nil {
		return nil
	}
	return func(query string) bool { return f.QueryBlocked([]string{query}) }
}

// filteredFiles wraps the file store for everything that serves it outside the eD2K
// handlers — the server-to-server service and the Meta API — so a file the content
// filter refuses is withheld there too. The engine itself is left unwrapped: main
// type-asserts it for snapshots and accounts.
type filteredFiles struct {
	storage.Engine
	filter *contentfilter.Filter
}

// withFilter returns engine's files as other servers and the Meta API may see them.
func withFilter(engine storage.Engine, filter *contentfilter.Filter) storage.Engine {
	if filter == nil {
		return engine
	}
	return filteredFiles{Engine: engine, filter: filter}
}

func (f filteredFiles) FindBySearch(expr *storage.SearchExpr) []storage.File {
	return f.keep(f.Engine.FindBySearch(expr))
}

func (f filteredFiles) SharedFiles(hashes [][]byte) []storage.File {
	return f.keep(f.Engine.SharedFiles(hashes))
}

// BrowseFiles filters a page after the engine cut it, so a page can come back short.
// The cursor is the engine's own, which keeps the walk complete.
func (f filteredFiles) BrowseFiles(cursor []byte, limit int) ([]storage.File, []byte, error) {
	files, next, err := f.Engine.BrowseFiles(cursor, limit)
	return f.keep(files), next, err
}

// keep copies the rows that may be served; an engine may hand out a slice it still owns.
func (f filteredFiles) keep(files []storage.File) []storage.File {
	kept := make([]storage.File, 0, len(files))
	for _, file := range files {
		if !f.filter.Withheld(file.Hash, file.Name) {
			kept = append(kept, file)
		}
	}
	return kept
}

// filterReferenceIP is the IPv4 address the update access key is derived against:
// filter.update.referenceIP, or this server's own primary IPv4 when that is empty.
// cfg.DynIP must already be resolved.
func filterReferenceIP(cfg config.Config) (net.IP, error) {
	if configured := cfg.Filter.Update.ReferenceIP; configured != "" {
		ip := net.ParseIP(configured)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("filter.update.referenceIP %q is not an IPv4 address", configured)
		}
		return ip, nil
	}
	own := firstRoutableIP(cfg.Address, cfg.DynIP)
	if own == "" {
		return nil, fmt.Errorf("filter.update.referenceIP is empty and this server's own IPv4 is unknown (address=%q dynIp=%q); set one of the three", cfg.Address, cfg.DynIP)
	}
	return net.ParseIP(own), nil
}
