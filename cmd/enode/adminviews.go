package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	goruntime "runtime"
	"sync"
	"time"

	"enode/admin"
	"enode/config"
	"enode/contentfilter"
	"enode/ed2k"
	"enode/logging"
	"enode/netfilter"
	"enode/storage"
)

// memStatsTTL is how long the Runtime tab's memory figures are reused. Reading them
// stops the world briefly, and the page polls every few seconds.
const memStatsTTL = 10 * time.Second

// lowIDCeiling is the first client ID that is an IPv4 address rather than a LowID.
const lowIDCeiling = 0x1000000

// recentLogRows is how many warnings and errors the Health tab shows.
const recentLogRows = 100

// adminViews adapts the running server to the dashboard's Views, so the admin package
// keeps no dependency on ed2k, storage or config. Every filter may be nil: the nil
// receivers answer as "off".
type adminViews struct {
	runtime *ed2k.ServerRuntime
	engine  storage.Engine
	// served is the file store as other servers may see it: without what the content
	// filter withholds.
	served  storage.Engine
	access  *netfilter.Filter
	content *contentfilter.Filter
	updater *contentfilter.Updater

	// configPath is the absolute path of the config file the server was started with.
	configPath string

	// mu guards config, which the reloader replaces once it exists, and the cached
	// memory figures.
	mu       sync.Mutex
	config   func() config.Config
	mem      goruntime.MemStats
	memTaken time.Time
}

var _ admin.Views = (*adminViews)(nil)

// setConfig replaces the source of the effective configuration.
func (v *adminViews) setConfig(get func() config.Config) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.config = get
}

func (v *adminViews) Features() admin.Features {
	info := v.access.Info()
	return admin.Features{
		Bans:         v.content != nil,
		Bots:         v.runtime.UDPConfig().BotDetection.Enabled,
		FilterReload: info.IPFilterEnabled || info.GeoIPEnabled || len(v.content.Lists()) > 0,
		FilterUpdate: v.updater != nil,
	}
}

func (v *adminViews) Clients() []admin.ClientRow {
	now := time.Now()
	clients := v.runtime.ClientSnapshot()
	rows := make([]admin.ClientRow, 0, len(clients))
	for _, c := range clients {
		row := admin.ClientRow{
			Hash:             hex.EncodeToString(c.Hash[:]),
			IP:               c.IP.String(),
			Port:             c.Port,
			ID:               c.ID,
			LowID:            c.LowID,
			Country:          v.access.Country(c.IP),
			Software:         c.Software,
			Nick:             c.Nick,
			Files:            v.engine.OfferedCount(storage.ClientInfo{StoreID: c.StoreID, Hash: c.Hash[:]}),
			IPv6Capable:      c.IPv6Capable,
			ConnectedSeconds: int64(now.Sub(c.ConnectedAt).Seconds()),
		}
		if c.IPv6 != nil {
			row.IPv6 = c.IPv6.String()
		}
		rows = append(rows, row)
	}
	return rows
}

func (v *adminViews) DisconnectClient(hash string) error {
	raw, err := parseHash(hash)
	if err != nil {
		return err
	}
	if !v.runtime.DisconnectClient(raw) {
		return admin.ErrNotFound
	}
	return nil
}

func (v *adminViews) Files(q admin.FileQuery) (admin.FilePage, error) {
	if q.Search != "" {
		files := v.served.FindBySearch(&storage.SearchExpr{Kind: storage.SearchText, Text: q.Search})
		if len(files) > q.Limit {
			files = files[:q.Limit]
		}
		return admin.FilePage{Rows: fileRows(files)}, nil
	}
	var cursor []byte
	if q.Cursor != "" {
		var err error
		if cursor, err = base64.RawURLEncoding.DecodeString(q.Cursor); err != nil {
			return admin.FilePage{}, errors.New("invalid cursor")
		}
	}
	files, next, err := v.served.BrowseFiles(cursor, q.Limit)
	if errors.Is(err, storage.ErrBrowseCursor) {
		return admin.FilePage{}, errors.New("the file index changed under this page; start again from the first")
	}
	if err != nil {
		return admin.FilePage{}, err
	}
	page := admin.FilePage{Rows: fileRows(files)}
	if next != nil {
		page.Next = base64.RawURLEncoding.EncodeToString(next)
	}
	return page, nil
}

func (v *adminViews) FileSources(hash string) ([]admin.SourceRow, error) {
	raw, err := parseHash(hash)
	if err != nil {
		return nil, err
	}
	// A withheld file has no sources to show, as for any other reader of the store.
	if v.content.Withheld(raw, "") {
		return nil, nil
	}
	sources := v.engine.GetSourcesByHash(raw)
	rows := make([]admin.SourceRow, 0, len(sources))
	for _, s := range sources {
		row := admin.SourceRow{Port: s.Port, LowID: s.ID < lowIDCeiling}
		if row.LowID {
			row.IP = fmt.Sprintf("LowID %d", s.ID)
		} else {
			row.IP = net.IPv4(byte(s.ID), byte(s.ID>>8), byte(s.ID>>16), byte(s.ID>>24)).String()
		}
		if len(s.IPv6) == net.IPv6len {
			row.IPv6 = net.IP(s.IPv6).String()
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func (v *adminViews) Peers() admin.PeersView {
	peers := v.runtime.GossipPeers()
	view := admin.PeersView{
		GossipEnabled: v.runtime.GossipEnabled(),
		Gossip:        make([]admin.PeerRow, 0, len(peers)),
		Static:        []admin.ServerRow{},
	}
	for _, p := range peers {
		view.Gossip = append(view.Gossip, admin.PeerRow{
			IP:           p.IP,
			Port:         p.Port,
			Country:      v.access.Country(net.ParseIP(p.IP)),
			Name:         p.Name,
			Desc:         p.Desc,
			State:        p.State,
			Parked:       p.Parked,
			Users:        p.Users,
			Files:        p.Files,
			Failures:     p.Failures,
			Referer:      p.Referer,
			ServerSearch: p.ServerSearch,
			LastSeen:     admin.FormatTime(p.LastSeen),
			LastVerified: admin.FormatTime(p.LastVerified),
		})
	}
	for _, s := range v.engine.ServersAll() {
		view.Static = append(view.Static, admin.ServerRow{IP: s.IP, Port: s.Port})
	}
	return view
}

func (v *adminViews) AddServer(ip string, port uint16) error {
	if _, _, fam := ed2k.ClassifyServerIP(ip); fam == 0 {
		return fmt.Errorf("%s is not a valid IPv4 or public IPv6 address", ip)
	}
	v.engine.AddServer(storage.Server{IP: ip, Port: port})
	return nil
}

func (v *adminViews) RemoveServer(ip string, port uint16) error {
	if !v.engine.RemoveServer(storage.Server{IP: ip, Port: port}) {
		return admin.ErrNotFound
	}
	return nil
}

func (v *adminViews) Filter() admin.FilterView {
	info := v.access.Info()
	blockedIP, blockedGeo := v.access.Stats()
	view := admin.FilterView{
		IPFilter: admin.IPFilterInfo{
			Enabled: info.IPFilterEnabled, File: info.IPFilterFile,
			Parsed: info.Parsed, Blocking: info.Blocking, Merged: info.Merged, Skipped: info.Skipped,
			Blocked: blockedIP,
		},
		GeoIP: admin.GeoIPInfo{
			Enabled: info.GeoIPEnabled, Database: info.GeoIPDatabase,
			Loaded: info.GeoIPLoaded, BlockedCountries: info.BlockedCountries, Blocked: blockedGeo,
		},
		Content: contentFilterStats(v.content, v.updater),
		Files:   v.dataFiles(),
	}
	if info.IPFilterEnabled {
		view.IPFilter.LoadedAt = admin.FormatTime(info.IPFilterLoaded)
	}
	return view
}

func (v *adminViews) ReloadFilter() error {
	return errors.Join(v.access.Reload(), v.content.Reload())
}

func (v *adminViews) UpdateFilter(ctx context.Context) ([]admin.FilterUpdateRow, error) {
	if v.updater == nil {
		return nil, admin.ErrUnavailable
	}
	results := v.updater.UpdateAll(ctx)
	rows := make([]admin.FilterUpdateRow, 0, len(results))
	for _, res := range results {
		row := admin.FilterUpdateRow{Name: res.Name, Entries: res.Entries, Previous: res.Previous}
		if res.Err != nil {
			row.Error = res.Err.Error()
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func (v *adminViews) Bans() ([]admin.BanRow, error) {
	if v.content == nil {
		return nil, admin.ErrUnavailable
	}
	now := time.Now()
	bans := v.content.Bans()
	rows := make([]admin.BanRow, 0, len(bans))
	for _, b := range bans {
		rows = append(rows, admin.BanRow{
			Key: b.Key, Until: admin.FormatTime(b.Until), RemainingSeconds: int64(b.Until.Sub(now).Seconds()),
		})
	}
	return rows, nil
}

func (v *adminViews) AddBan(key string, minutes int) error {
	if v.content == nil {
		return admin.ErrUnavailable
	}
	return v.content.BanKey(key, time.Duration(minutes)*time.Minute)
}

func (v *adminViews) RemoveBan(key string) error {
	if v.content == nil {
		return admin.ErrUnavailable
	}
	removed, err := v.content.Unban(key)
	if err != nil {
		return err
	}
	if !removed {
		return admin.ErrNotFound
	}
	return nil
}

func (v *adminViews) Bots() []admin.BotRow {
	bots := v.runtime.Bots()
	rows := make([]admin.BotRow, 0, len(bots))
	for _, b := range bots {
		rows = append(rows, admin.BotRow{
			Source:           b.Source,
			Country:          v.access.Country(net.ParseIP(b.Source)),
			Detections:       b.Detections,
			QueriesPerMinute: b.QueriesPerMinute,
			IntervalStddevMs: b.IntervalStddevMs,
			Reason:           b.Reason,
			FirstSeen:        admin.FormatTime(b.FirstSeen),
			LastSeen:         admin.FormatTime(b.LastSeen),
		})
	}
	return rows
}

func (v *adminViews) Blocks() []admin.BlockRow {
	blockedIP, blockedGeo := v.access.Stats()
	rt := v.runtime.BlockStats()
	content := v.content.Stats()
	return []admin.BlockRow{
		{Reason: "IP filter", Count: uint64(blockedIP), What: "connections and datagrams from a blocked address range"},
		{Reason: "Country filter", Count: uint64(blockedGeo), What: "connections and datagrams from a blocked country"},
		{Reason: "Connections per address", Count: rt.ConnLimit, What: "TCP connections over tcp.maxConnectionsPerIP"},
		{Reason: "UDP rate limit", Count: rt.RateLimited, What: "UDP searches and source requests over udp.rateLimitPerIPPerMinute"},
		{Reason: "Banned login", Count: rt.BannedLogins, What: "logins from a banned user hash or address"},
		{Reason: "Offer over hard limit", Count: rt.HardLimit, What: "OP_OFFERFILES packets declaring files.hardLimit records or more; the client is disconnected"},
		{Reason: "Ban list file", Count: uint64(content.RefusedBanlist), What: "offered files on the hash ban list"},
		{Reason: "Filter list file", Count: uint64(content.RefusedFilter), What: "offered files on the hash filter list"},
		{Reason: "Keyword", Count: uint64(content.RefusedKeyword), What: "offered files whose name matches filter.keywords"},
		{Reason: "Withheld when serving", Count: uint64(content.WithheldServed), What: "result rows and source requests for a filtered file"},
		{Reason: "Blocked search", Count: uint64(content.BlockedQueries), What: "searches whose own terms match filter.keywords"},
		{Reason: "Bot detected", Count: rt.Bots, What: "times an address was listed as an automated querier (observed, not blocked)"},
	}
}

func (v *adminViews) Health() admin.HealthView {
	entries, total := logging.Recent(recentLogRows)
	view := admin.HealthView{Files: v.dataFiles(), LogTotal: total, Log: make([]admin.LogRow, 0, len(entries))}
	for _, e := range entries {
		view.Log = append(view.Log, admin.LogRow{Time: admin.FormatTime(e.Time), Level: e.Level.String(), Message: e.Message})
	}
	return view
}

func (v *adminViews) Runtime() admin.RuntimeView {
	mem, taken := v.memStats()
	cfg := v.cfg()
	_, files := v.runtime.Counts()
	view := admin.RuntimeView{
		GoVersion:    goruntime.Version(),
		NumCPU:       goruntime.NumCPU(),
		GoMaxProcs:   goruntime.GOMAXPROCS(0),
		Goroutines:   goruntime.NumGoroutine(),
		SampledAt:    admin.FormatTime(taken),
		HeapAlloc:    mem.HeapAlloc,
		HeapInUse:    mem.HeapInuse,
		HeapObjects:  mem.HeapObjects,
		Sys:          mem.Sys,
		NumGC:        mem.NumGC,
		GCPauseTotal: float64(mem.PauseTotalNs) / 1e6,
		Storage:      storageFacts(cfg),
	}
	if mem.LastGC != 0 {
		view.LastGC = admin.FormatTime(time.Unix(0, int64(mem.LastGC)))
	}
	if files > 0 {
		view.BytesPerFile = mem.HeapAlloc / uint64(files)
	}
	return view
}

func (v *adminViews) Config() (admin.ConfigView, error) {
	out, err := config.RedactedYAML(v.cfg())
	return admin.ConfigView{Path: v.configPath, YAML: string(out)}, err
}

// cfg is the configuration in effect now.
func (v *adminViews) cfg() config.Config {
	v.mu.Lock()
	get := v.config
	v.mu.Unlock()
	return get()
}

// memStats returns the Go memory figures, read at most once per memStatsTTL.
func (v *adminViews) memStats() (goruntime.MemStats, time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if time.Since(v.memTaken) >= memStatsTTL {
		goruntime.ReadMemStats(&v.mem)
		v.memTaken = time.Now()
	}
	return v.mem, v.memTaken
}

// dataFiles lists the files the enabled filters read.
func (v *adminViews) dataFiles() []admin.DataFileRow {
	rows := []admin.DataFileRow{}
	info := v.access.Info()
	for _, f := range v.access.Files() {
		row := admin.DataFileRow{Name: f.Name, Path: f.Path, Exists: f.Exists, Size: f.Size, Entries: -1}
		if f.Exists {
			row.Modified = admin.FormatTime(f.Modified)
		}
		if f.Path == info.IPFilterFile && info.IPFilterEnabled {
			row.Entries = info.Merged
		}
		rows = append(rows, row)
	}
	for _, l := range v.content.Lists() {
		row := admin.DataFileRow{Name: l.Name, Path: l.Path, Exists: l.Exists, Size: l.Size, Entries: l.Entries}
		if l.Exists {
			row.Modified = admin.FormatTime(l.Modified)
		}
		rows = append(rows, row)
	}
	return rows
}

// storageFacts are the storage settings the Runtime tab lists. Nothing here is a
// credential: the database addresses stay in the redacted config view.
func storageFacts(cfg config.Config) []admin.KeyValue {
	onOff := func(on bool, detail string) string {
		if !on {
			return "off"
		}
		return detail
	}
	st := cfg.Storage
	return []admin.KeyValue{
		{Key: "Engine", Value: st.Engine},
		{Key: "Count cache", Value: fmt.Sprintf("%d s", st.CountCacheSecondsOrDefault())},
		{Key: "Cleanup", Value: onOff(st.Cleanup.Enabled, fmt.Sprintf("every %d min, stale after %d h, zero-source files kept: %t",
			st.Cleanup.IntervalMinutes, st.Cleanup.StaleAfterHours, st.Cleanup.KeepZeroSourceFilesOrDefault()))},
		{Key: "Snapshot", Value: onOff(st.Snapshot.Enabled, fmt.Sprintf("every %d min to %s, compressed: %t",
			st.Snapshot.IntervalMinutes, cfg.StorageSnapshotPath(), st.Snapshot.Compress))},
		{Key: "Files per client", Value: fmt.Sprintf("soft limit %d, hard limit %d",
			cfg.Files.SoftLimitOrDefault(), cfg.Files.HardLimitOrDefault())},
	}
}

func fileRows(files []storage.File) []admin.FileRow {
	rows := make([]admin.FileRow, 0, len(files))
	for _, f := range files {
		rows = append(rows, admin.FileRow{
			Hash: hex.EncodeToString(f.Hash), Name: f.Name, Size: f.Size, Type: f.Type,
			Sources: f.Sources, Completed: f.Completed,
		})
	}
	return rows
}

// parseHash decodes a 32-digit hex eD2K hash.
func parseHash(s string) ([]byte, error) {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 16 {
		return nil, errors.New("a hash is 32 hex digits")
	}
	return raw, nil
}
