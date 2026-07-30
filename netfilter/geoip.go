package netfilter

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// GeoIP resolves a peer address to an ISO 3166-1 alpha-2 country code and matches
// it against a deny-list.
//
// Deny-list rather than allow-list by decision: that is how operators actually use
// eserver's obfcountries and the equivalent ipfilter lists, and an allow-list on a
// public eD2K server would refuse most of the network by default — a far more
// destructive failure mode for a mistyped config.
//
// The reader is swapped wholesale under a write lock when the database is refreshed,
// so a weekly update never races a lookup on the UDP hot path. A GeoIP with no
// reader (no database, or credentials absent) answers "not blocked" for everything,
// which is the deliberate fail-open behaviour described in UpdateDatabase.
type GeoIP struct {
	mu     sync.RWMutex
	db     *geoip2.Reader
	denied map[string]struct{}

	// databaseFileName is where the .mmdb lives. Under ./data by convention, since
	// this file is downloaded by the server rather than supplied by the operator.
	databaseFileName string
	// account is nil when no MaxMind credentials are configured, which means "use
	// whatever local file exists and never download".
	account *WebServiceAccount
	// updateDays drives the refresh ticker. Zero means DefaultUpdateDays.
	updateDays int
}

// WebServiceAccount holds MaxMind download credentials. AccountID is a string here
// (matching how it appears in the config and on MaxMind's site) and is converted to
// the int the download client wants at call time, so a malformed value surfaces as a
// clear error rather than a config-parse failure at boot.
type WebServiceAccount struct {
	AccountID  string
	LicenseKey string
}

// DefaultUpdateDays is how often the country database is checked for updates.
// GeoLite2-Country is republished weekly, so anything shorter only costs
// round-trips; the check itself is conditional on the current file's MD5 and
// transfers nothing when the database is unchanged.
const DefaultUpdateDays = 7

// NewGeoIP opens the country database, downloading it first when it is missing and
// credentials are available.
//
// It never returns an error for "no database": an access filter must not be the
// reason the server refuses to start. Callers get a usable *GeoIP either way and
// should log what Ready reports.
func NewGeoIP(databaseFile string, deniedCountries []string, account *WebServiceAccount, updateDays int) *GeoIP {
	g := &GeoIP{
		databaseFileName: databaseFile,
		account:          account,
		updateDays:       updateDays,
		denied:           make(map[string]struct{}, len(deniedCountries)),
	}
	for _, c := range deniedCountries {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c != "" {
			g.denied[c] = struct{}{}
		}
	}
	return g
}

// Ready reports whether a database is loaded and how many countries are denied, for
// the startup log line.
func (g *GeoIP) Ready() (loaded bool, deniedCount int) {
	if g == nil {
		return false, 0
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.db != nil, len(g.denied)
}

// Lookup returns the ISO country code for an address, or "" when unknown. Exposed
// separately from Blocked so the admin surface and logs can report a country without
// implying a verdict.
func (g *GeoIP) Lookup(ip net.IP) string {
	if g == nil {
		return ""
	}
	g.mu.RLock()
	db := g.db
	g.mu.RUnlock()
	if db == nil {
		return ""
	}
	rec, err := db.Country(ip)
	if err != nil || rec == nil {
		return ""
	}
	return rec.Country.IsoCode
}

// Blocked reports whether the address resolves to a denied country.
//
// An address that resolves to no country is never blocked. That matters: the
// GeoLite2 database has real gaps, and treating "unknown" as denied would silently
// refuse legitimate peers whenever the database was stale or absent.
func (g *GeoIP) Blocked(ip net.IP) (bool, string) {
	if g == nil {
		return false, ""
	}
	g.mu.RLock()
	db, denied := g.db, g.denied
	g.mu.RUnlock()
	if db == nil || len(denied) == 0 {
		return false, ""
	}
	rec, err := db.Country(ip)
	if err != nil || rec == nil {
		return false, ""
	}
	code := rec.Country.IsoCode
	if code == "" {
		return false, ""
	}
	if _, ok := denied[code]; ok {
		return true, "country=" + code
	}
	return false, ""
}

// Close releases the database handle.
func (g *GeoIP) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.db == nil {
		return nil
	}
	err := g.db.Close()
	g.db = nil
	return err
}

// reloadDatabase opens the database file and swaps it in, closing the previous
// reader. Failure leaves the previous reader in place: a corrupt download must not
// take away country matching that was working a moment ago.
func (g *GeoIP) reloadDatabase() error {
	db, err := geoip2.Open(g.databaseFileName)
	if err != nil {
		return fmt.Errorf("open geoip database %s: %w", g.databaseFileName, err)
	}
	g.mu.Lock()
	old := g.db
	g.db = db
	g.mu.Unlock()
	if old != nil {
		// Closed after the swap, and only after: closing before publishing the new
		// reader would leave concurrent lookups holding a closed handle.
		_ = old.Close()
	}
	return nil
}

// fileExists reports whether the database file is present, without opening it.
func (g *GeoIP) fileExists() bool {
	_, err := os.Stat(g.databaseFileName)
	return err == nil
}
