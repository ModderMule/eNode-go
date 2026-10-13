package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"enode/logging"
)

// Views is what the tabs beyond the status page read and do. The caller adapts the
// running server to it, so this package keeps no dependency on ed2k, storage or
// config. Every route built on it is sensitive: it needs loopback or credentials.
type Views interface {
	// Features says which optional tabs and buttons this server has.
	Features() Features

	Clients() []ClientRow
	// DisconnectClient closes the session of a user hash (32 hex digits).
	DisconnectClient(hash string) error

	Files(q FileQuery) (FilePage, error)
	FileSources(hash string) ([]SourceRow, error)

	Peers() PeersView
	AddServer(ip string, port uint16) error
	RemoveServer(ip string, port uint16) error

	Filter() FilterView
	// ReloadFilter re-reads the filter data files from disk.
	ReloadFilter() error
	// UpdateFilter fetches the hash lists from the update service now.
	UpdateFilter(ctx context.Context) ([]FilterUpdateRow, error)

	Bans() ([]BanRow, error)
	// AddBan bans "hash:<32 hex digits>" or "ip:<address>" for minutes.
	AddBan(key string, minutes int) error
	RemoveBan(key string) error

	Bots() []BotRow
	Spam() SpamView
	// SpamDecide puts a file on one of the operator's hash lists: "banlist", "filter"
	// or "whitelist".
	SpamDecide(hash, list string) error
	Blocks() []BlockRow
	Health() HealthView
	Runtime() RuntimeView
	// Config is the effective configuration as YAML with every secret hidden, and
	// the file it was loaded from.
	Config() (ConfigView, error)
}

// ErrNotFound is what a Views method returns for a client, server or ban that is not
// there, and ErrUnavailable for a feature this server runs without.
var (
	ErrNotFound    = errors.New("not found")
	ErrUnavailable = errors.New("not available on this server")
)

// Features are the optional parts of the admin UI. The page renders a tab or a button
// only when its feature is on.
type Features struct {
	// Bans is the content filter's publisher bans, which exist only with the filter.
	Bans bool
	// Bots is udp.botDetection.
	Bots bool
	// Spam is filter.spam, and SpamLists that filter.localLists is on too, so a
	// listed file can be put on a list.
	Spam      bool
	SpamLists bool
	// FilterReload is set when a filter that reads a file is enabled, and
	// FilterUpdate when filter.update is.
	FilterReload bool
	FilterUpdate bool
}

// ClientRow is one logged-in client.
type ClientRow struct {
	Hash     string `json:"hash"`
	IP       string `json:"ip"`
	Port     uint16 `json:"port"`
	ID       uint32 `json:"id"`
	LowID    bool   `json:"lowId"`
	Country  string `json:"country"`
	Software string `json:"software"`
	Nick     string `json:"nick"`
	Files    int    `json:"files"`
	// IPv6 is the address the client published, "" when it has none.
	IPv6             string `json:"ipv6"`
	IPv6Capable      bool   `json:"ipv6Capable"`
	ConnectedSeconds int64  `json:"connectedSeconds"`
}

// ClientPage is one page of the filtered, sorted client list.
type ClientPage struct {
	Total   int         `json:"total"`
	Matched int         `json:"matched"`
	Offset  int         `json:"offset"`
	Limit   int         `json:"limit"`
	Rows    []ClientRow `json:"rows"`
}

// CountRow is one bar of a distribution.
type CountRow struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// ClientSummary is the software and country distribution of the connected clients.
type ClientSummary struct {
	Total     int        `json:"total"`
	Software  []CountRow `json:"software"`
	Countries []CountRow `json:"countries"`
}

// FileQuery asks for one page of the file index: a search when Search is set,
// otherwise a walk continued from Cursor.
type FileQuery struct {
	Search string
	Cursor string
	Limit  int
}

// ConfigView is the configuration in effect.
type ConfigView struct {
	// Path is the absolute path of the config file on disk.
	Path string `json:"path"`
	// YAML is the configuration with every secret hidden.
	YAML string `json:"yaml"`
}

// FileRow is one indexed file.
type FileRow struct {
	Hash      string `json:"hash"`
	Name      string `json:"name"`
	Size      uint64 `json:"size"`
	Type      string `json:"type"`
	Sources   uint32 `json:"sources"`
	Completed uint32 `json:"completed"`
}

// FilePage is one page of files. Next continues a walk and is "" at its end and for
// a search, which returns its whole capped answer at once.
type FilePage struct {
	Rows []FileRow `json:"rows"`
	Next string    `json:"next"`
}

// SourceRow is one client offering a file.
type SourceRow struct {
	// IP is the source's IPv4 address, or its LowID spelled out.
	IP    string `json:"ip"`
	Port  uint16 `json:"port"`
	LowID bool   `json:"lowId"`
	IPv6  string `json:"ipv6"`
	// Software is the client and its version as it logged in, empty when unknown.
	Software string `json:"software"`
}

// PeersView is the server lists: what gossip learned and what was configured.
type PeersView struct {
	GossipEnabled bool        `json:"gossipEnabled"`
	Gossip        []PeerRow   `json:"gossip"`
	Static        []ServerRow `json:"static"`
}

// PeerRow is one gossip peer. Name and Desc are the peer's own strings.
type PeerRow struct {
	IP           string `json:"ip"`
	Port         uint16 `json:"port"`
	Country      string `json:"country"`
	Name         string `json:"name"`
	Desc         string `json:"desc"`
	State        string `json:"state"`
	Parked       bool   `json:"parked"`
	Users        uint32 `json:"users"`
	Files        uint32 `json:"files"`
	Failures     int    `json:"failures"`
	Referer      string `json:"referer"`
	ServerSearch bool   `json:"serverSearch"`
	LastSeen     string `json:"lastSeen"`
	LastVerified string `json:"lastVerified"`
}

// ServerRow is one entry of the static server list.
type ServerRow struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

// FilterView is the access and content filters as loaded.
type FilterView struct {
	IPFilter IPFilterInfo `json:"ipFilter"`
	GeoIP    GeoIPInfo    `json:"geoIP"`
	// Content is nil while the content filter is off.
	Content *ContentFilterStats `json:"content"`
	Files   []DataFileRow       `json:"files"`
}

// IPFilterInfo is the range list.
type IPFilterInfo struct {
	Enabled  bool   `json:"enabled"`
	File     string `json:"file"`
	Parsed   int    `json:"parsed"`
	Blocking int    `json:"blocking"`
	Merged   int    `json:"merged"`
	Skipped  int    `json:"skipped"`
	LoadedAt string `json:"loadedAt"`
	Blocked  int64  `json:"blocked"`
}

// GeoIPInfo is the country filter.
type GeoIPInfo struct {
	Enabled          bool   `json:"enabled"`
	Database         string `json:"database"`
	Loaded           bool   `json:"loaded"`
	BlockedCountries int    `json:"blockedCountries"`
	Blocked          int64  `json:"blocked"`
}

// DataFileRow is one data file a filter reads. Entries is -1 for a file that is not
// counted in entries.
type DataFileRow struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Exists   bool   `json:"exists"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
	Entries  int    `json:"entries"`
}

// FilterUpdateRow is the outcome of one hash list's update.
type FilterUpdateRow struct {
	Name     string `json:"name"`
	Entries  int    `json:"entries"`
	Previous int    `json:"previous"`
	Error    string `json:"error"`
}

// BanRow is one active ban.
type BanRow struct {
	Key              string `json:"key"`
	Until            string `json:"until"`
	RemainingSeconds int64  `json:"remainingSeconds"`
}

// BotRow is one address the bot detector flagged.
type BotRow struct {
	Source           string  `json:"source"`
	Country          string  `json:"country"`
	Detections       uint64  `json:"detections"`
	QueriesPerMinute float64 `json:"queriesPerMinute"`
	IntervalStddevMs float64 `json:"intervalStddevMs"`
	Reason           string  `json:"reason"`
	FirstSeen        string  `json:"firstSeen"`
	LastSeen         string  `json:"lastSeen"`
}

// SpamView is what the spam detector has scored. It observes: nothing listed here was
// refused.
type SpamView struct {
	// Assessed is how many offered files were scored since the start, and Caution,
	// Suspect and Spam how many of them fell into each band.
	Assessed   uint64             `json:"assessed"`
	Caution    uint64             `json:"caution"`
	Suspect    uint64             `json:"suspect"`
	Spam       uint64             `json:"spam"`
	Files      []SpamFileRow      `json:"files"`
	Publishers []SpamPublisherRow `json:"publishers"`
}

// SpamFileRow is one file that scored, with the reasons as "reason +points".
type SpamFileRow struct {
	Hash      string   `json:"hash"`
	Name      string   `json:"name"`
	Size      uint64   `json:"size"`
	Score     int      `json:"score"`
	Band      string   `json:"band"`
	Reasons   []string `json:"reasons"`
	Offers    uint64   `json:"offers"`
	FirstSeen string   `json:"firstSeen"`
	LastSeen  string   `json:"lastSeen"`
}

// SpamPublisherRow is one session whose share was judged spam.
type SpamPublisherRow struct {
	UserHash  string   `json:"userHash"`
	Address   string   `json:"address"`
	Country   string   `json:"country"`
	Files     int      `json:"files"`
	Reasons   []string `json:"reasons"`
	FirstSeen string   `json:"firstSeen"`
	LastSeen  string   `json:"lastSeen"`
}

// BlockRow is one reason something was refused and how often since the start.
type BlockRow struct {
	Reason string `json:"reason"`
	Count  uint64 `json:"count"`
	What   string `json:"what"`
}

// HealthView is the data files and the recent warnings and errors.
type HealthView struct {
	Files []DataFileRow `json:"files"`
	// LogTotal counts the warnings and errors since the start; Log is the newest.
	LogTotal uint64   `json:"logTotal"`
	Log      []LogRow `json:"log"`
}

// LogRow is one warning or error. Message may quote a peer, so it is inserted as text.
type LogRow struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// RuntimeView is the Go runtime's and the storage engine's figures.
type RuntimeView struct {
	GoVersion  string `json:"goVersion"`
	NumCPU     int    `json:"numCPU"`
	GoMaxProcs int    `json:"goMaxProcs"`
	Goroutines int    `json:"goroutines"`
	// The memory figures are read at most every few seconds; SampledAt says when.
	SampledAt    string  `json:"sampledAt"`
	HeapAlloc    uint64  `json:"heapAlloc"`
	HeapInUse    uint64  `json:"heapInUse"`
	HeapObjects  uint64  `json:"heapObjects"`
	Sys          uint64  `json:"sys"`
	NumGC        uint32  `json:"numGC"`
	LastGC       string  `json:"lastGC"`
	GCPauseTotal float64 `json:"gcPauseTotalMs"`
	// BytesPerFile is HeapAlloc over the indexed files, 0 with none.
	BytesPerFile uint64 `json:"bytesPerFile"`
	// Storage lists the storage engine's settings.
	Storage []KeyValue `json:"storage"`
}

// KeyValue is one labelled value.
type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

const (
	defaultClientPage = 100
	maxClientPage     = 500
	defaultFilePage   = 100
	maxFilePage       = 500
	maxBanMinutes     = 60 * 24 * 365
)

// SetViews enables the tabs beyond the status page. Call before Start.
func (s *Server) SetViews(v Views) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.views = v
}

// registerViews adds the routes of the tabs. All are sensitive.
func (s *Server) registerViews(mux *http.ServeMux) {
	get := func(pattern string, h func(Views, http.ResponseWriter, *http.Request)) {
		mux.HandleFunc(pattern, s.guard(true, s.withViews(h)))
	}
	get("GET /api/clients", handleClients)
	get("GET /api/clients/summary", handleClientSummary)
	get("POST /api/clients/{hash}/disconnect", handleClientDisconnect)
	get("GET /api/files", handleFiles)
	get("GET /api/files/{hash}/sources", handleFileSources)
	get("GET /api/peers", func(v Views, w http.ResponseWriter, _ *http.Request) { writeJSON(w, v.Peers()) })
	get("POST /api/servers", handleServerAdd)
	get("DELETE /api/servers/{ip}/{port}", handleServerRemove)
	get("GET /api/filter", func(v Views, w http.ResponseWriter, _ *http.Request) { writeJSON(w, v.Filter()) })
	get("POST /api/filter/reload", handleFilterReload)
	get("POST /api/filter/update", handleFilterUpdate)
	get("GET /api/bans", handleBans)
	get("POST /api/bans", handleBanAdd)
	get("DELETE /api/bans/{key...}", handleBanRemove)
	get("GET /api/bots", func(v Views, w http.ResponseWriter, _ *http.Request) { writeJSON(w, orEmpty(v.Bots())) })
	get("GET /api/spam", func(v Views, w http.ResponseWriter, _ *http.Request) {
		view := v.Spam()
		view.Files, view.Publishers = orEmpty(view.Files), orEmpty(view.Publishers)
		writeJSON(w, view)
	})
	get("POST /api/spam/files/{hash}/{list}", handleSpamDecide)
	get("GET /api/blocks", func(v Views, w http.ResponseWriter, _ *http.Request) { writeJSON(w, orEmpty(v.Blocks())) })
	get("GET /api/health", func(v Views, w http.ResponseWriter, _ *http.Request) { writeJSON(w, v.Health()) })
	get("GET /api/runtime", func(v Views, w http.ResponseWriter, _ *http.Request) { writeJSON(w, v.Runtime()) })
	get("GET /api/config", handleConfig)
}

// withViews answers 404 while no Views is attached.
func (s *Server) withViews(h func(Views, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		v := s.views
		s.mu.RUnlock()
		if v == nil {
			http.NotFound(w, r)
			return
		}
		h(v, w, r)
	}
}

func handleClients(v Views, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	writeJSON(w, pageClients(v.Clients(), clientQuery{
		Search: q.Get("q"), Country: q.Get("country"), Software: q.Get("software"), ID: q.Get("id"),
		Sort: q.Get("sort"), Ascending: q.Get("dir") == "asc", Offset: offset, Limit: limit,
	}))
}

func handleClientSummary(v Views, w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, summarizeClients(v.Clients()))
}

func handleClientDisconnect(v Views, w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	if err := v.DisconnectClient(hash); err != nil {
		writeViewError(w, err)
		return
	}
	logging.Infof("admin dashboard: client %s disconnected by %s", hash, r.RemoteAddr)
	writeJSON(w, map[string]bool{"ok": true})
}

func handleFiles(v Views, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = defaultFilePage
	}
	page, err := v.Files(FileQuery{Search: strings.TrimSpace(q.Get("q")), Cursor: q.Get("cursor"), Limit: min(limit, maxFilePage)})
	if err != nil {
		writeViewError(w, err)
		return
	}
	page.Rows = orEmpty(page.Rows)
	writeJSON(w, page)
}

func handleFileSources(v Views, w http.ResponseWriter, r *http.Request) {
	rows, err := v.FileSources(r.PathValue("hash"))
	if err != nil {
		writeViewError(w, err)
		return
	}
	writeJSON(w, orEmpty(rows))
}

// serverBody is the body of POST /api/servers.
type serverBody struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

func handleServerAdd(v Views, w http.ResponseWriter, r *http.Request) {
	var body serverBody
	if !readBody(w, r, &body) {
		return
	}
	ip := net.ParseIP(strings.TrimSpace(body.IP))
	if ip == nil || body.Port == 0 {
		writeJSONError(w, http.StatusBadRequest, errors.New("a server needs an IP address and a port"))
		return
	}
	if err := v.AddServer(ip.String(), body.Port); err != nil {
		writeViewError(w, err)
		return
	}
	logging.Infof("admin dashboard: server %s:%d added by %s", ip, body.Port, r.RemoteAddr)
	writeJSON(w, v.Peers())
}

func handleServerRemove(v Views, w http.ResponseWriter, r *http.Request) {
	port, err := strconv.ParseUint(r.PathValue("port"), 10, 16)
	ip := net.ParseIP(r.PathValue("ip"))
	if err != nil || port == 0 || ip == nil {
		writeJSONError(w, http.StatusBadRequest, errors.New("invalid server address"))
		return
	}
	if err := v.RemoveServer(ip.String(), uint16(port)); err != nil {
		writeViewError(w, err)
		return
	}
	logging.Infof("admin dashboard: server %s:%d removed by %s", ip, port, r.RemoteAddr)
	writeJSON(w, v.Peers())
}

func handleFilterReload(v Views, w http.ResponseWriter, r *http.Request) {
	if !v.Features().FilterReload {
		writeViewError(w, ErrUnavailable)
		return
	}
	if err := v.ReloadFilter(); err != nil {
		logging.Warnf("admin dashboard: filter reload by %s failed: %v", r.RemoteAddr, err)
		writeJSONError(w, http.StatusUnprocessableEntity, err)
		return
	}
	logging.Infof("admin dashboard: filters reloaded by %s", r.RemoteAddr)
	writeJSON(w, v.Filter())
}

func handleSpamDecide(v Views, w http.ResponseWriter, r *http.Request) {
	if !v.Features().SpamLists {
		writeViewError(w, ErrUnavailable)
		return
	}
	hash, list := r.PathValue("hash"), r.PathValue("list")
	if err := v.SpamDecide(hash, list); err != nil {
		writeViewError(w, err)
		return
	}
	logging.Infof("admin dashboard: file %s put on the local %s by %s", hash, list, r.RemoteAddr)
	view := v.Spam()
	view.Files, view.Publishers = orEmpty(view.Files), orEmpty(view.Publishers)
	writeJSON(w, view)
}

func handleFilterUpdate(v Views, w http.ResponseWriter, r *http.Request) {
	if !v.Features().FilterUpdate {
		writeViewError(w, ErrUnavailable)
		return
	}
	rows, err := v.UpdateFilter(r.Context())
	if err != nil {
		writeViewError(w, err)
		return
	}
	logging.Infof("admin dashboard: filter lists updated by %s: %+v", r.RemoteAddr, rows)
	writeJSON(w, orEmpty(rows))
}

func handleBans(v Views, w http.ResponseWriter, _ *http.Request) {
	rows, err := v.Bans()
	if err != nil {
		writeViewError(w, err)
		return
	}
	writeJSON(w, orEmpty(rows))
}

// banBody is the body of POST /api/bans.
type banBody struct {
	Key     string `json:"key"`
	Minutes int    `json:"minutes"`
}

func handleBanAdd(v Views, w http.ResponseWriter, r *http.Request) {
	var body banBody
	if !readBody(w, r, &body) {
		return
	}
	if body.Minutes <= 0 || body.Minutes > maxBanMinutes {
		writeJSONError(w, http.StatusBadRequest, errors.New("minutes must be between 1 and 525600"))
		return
	}
	if err := v.AddBan(strings.TrimSpace(body.Key), body.Minutes); err != nil {
		writeViewError(w, err)
		return
	}
	logging.Infof("admin dashboard: %s banned for %d min by %s", body.Key, body.Minutes, r.RemoteAddr)
	handleBans(v, w, r)
}

func handleBanRemove(v Views, w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if err := v.RemoveBan(key); err != nil {
		writeViewError(w, err)
		return
	}
	logging.Infof("admin dashboard: ban %s lifted by %s", key, r.RemoteAddr)
	handleBans(v, w, r)
}

func handleConfig(v Views, w http.ResponseWriter, _ *http.Request) {
	view, err := v.Config()
	if err != nil {
		writeViewError(w, err)
		return
	}
	writeJSON(w, view)
}

// clientQuery filters, sorts and pages the client list.
type clientQuery struct {
	// Search matches a substring of the address, nick, IPv6 address or user hash,
	// or an IPv4 CIDR such as 82.48.0.0/16.
	Search   string
	Country  string
	Software string
	// ID is "high", "low" or "" for both.
	ID        string
	Sort      string
	Ascending bool
	Offset    int
	Limit     int
}

// pageClients applies q to rows. Sorting is stable on the user hash, so paging through
// an unchanged list never repeats or skips a client.
func pageClients(rows []ClientRow, q clientQuery) ClientPage {
	if q.Limit <= 0 {
		q.Limit = defaultClientPage
	}
	q.Limit = min(q.Limit, maxClientPage)
	q.Offset = max(q.Offset, 0)

	match := clientMatcher(q)
	kept := make([]ClientRow, 0, len(rows))
	for _, row := range rows {
		if match(row) {
			kept = append(kept, row)
		}
	}
	less := clientLess(q.Sort)
	sort.Slice(kept, func(i, j int) bool {
		a, b := kept[i], kept[j]
		if !q.Ascending {
			a, b = b, a
		}
		if less(a, b) {
			return true
		}
		if less(b, a) {
			return false
		}
		return kept[i].Hash < kept[j].Hash
	})

	page := ClientPage{Total: len(rows), Matched: len(kept), Offset: q.Offset, Limit: q.Limit, Rows: []ClientRow{}}
	if q.Offset < len(kept) {
		page.Rows = kept[q.Offset:min(q.Offset+q.Limit, len(kept))]
	}
	return page
}

func clientMatcher(q clientQuery) func(ClientRow) bool {
	search := strings.ToLower(strings.TrimSpace(q.Search))
	var cidr *net.IPNet
	if strings.Contains(search, "/") {
		if _, n, err := net.ParseCIDR(search); err == nil {
			cidr = n
		}
	}
	return func(row ClientRow) bool {
		if q.Country != "" && row.Country != q.Country {
			return false
		}
		if q.Software != "" && softwareFamily(row.Software) != q.Software {
			return false
		}
		if (q.ID == "high" && row.LowID) || (q.ID == "low" && !row.LowID) {
			return false
		}
		switch {
		case search == "":
			return true
		case cidr != nil:
			return cidr.Contains(net.ParseIP(row.IP))
		}
		return strings.Contains(row.IP, search) || strings.Contains(strings.ToLower(row.Nick), search) ||
			strings.Contains(row.IPv6, search) || strings.Contains(row.Hash, search)
	}
}

// clientLess orders two rows by the named column; connected time is the default.
func clientLess(column string) func(a, b ClientRow) bool {
	switch column {
	case "files":
		return func(a, b ClientRow) bool { return a.Files < b.Files }
	case "ip":
		return func(a, b ClientRow) bool { return a.IP < b.IP }
	case "nick":
		return func(a, b ClientRow) bool { return strings.ToLower(a.Nick) < strings.ToLower(b.Nick) }
	case "country":
		return func(a, b ClientRow) bool { return a.Country < b.Country }
	case "software":
		return func(a, b ClientRow) bool { return a.Software < b.Software }
	}
	return func(a, b ClientRow) bool { return a.ConnectedSeconds < b.ConnectedSeconds }
}

// summarizeClients counts the connected clients by software family and by country,
// largest first.
func summarizeClients(rows []ClientRow) ClientSummary {
	software, countries := map[string]int{}, map[string]int{}
	for _, row := range rows {
		software[softwareFamily(row.Software)]++
		countries[row.Country]++
	}
	return ClientSummary{Total: len(rows), Software: countRows(software), Countries: countRows(countries)}
}

// softwareFamily is a client's software without its version: "eMule 0.50a" is "eMule".
func softwareFamily(software string) string {
	if i := strings.IndexByte(software, ' '); i > 0 {
		return software[:i]
	}
	return software
}

func countRows(counts map[string]int) []CountRow {
	out := make([]CountRow, 0, len(counts))
	for name, n := range counts {
		out = append(out, CountRow{Name: name, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// readBody decodes a small JSON request body, answering 400 itself when it cannot.
func readBody(w http.ResponseWriter, r *http.Request, into any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(into); err != nil {
		writeJSONError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
		return false
	}
	return true
}

// writeViewError maps a Views error: missing things are 404, anything else is the
// operator's input and is told to them.
func writeViewError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrUnavailable) {
		writeJSONError(w, http.StatusNotFound, err)
		return
	}
	writeJSONError(w, http.StatusBadRequest, err)
}

// orEmpty turns a nil list into an empty one, so the page can read .length unguarded.
func orEmpty[T any](rows []T) []T {
	if rows == nil {
		return []T{}
	}
	return rows
}
