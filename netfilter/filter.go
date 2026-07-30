package netfilter

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"enode/logging"
)

// Config describes the access filter as it appears in enode.config.yaml. Both halves
// are independently optional; an all-disabled Config yields a Filter that blocks
// nothing and costs one nil check per packet.
type Config struct {
	// IPFilterEnabled gates the static range list.
	IPFilterEnabled bool
	// IPFilterFile is an eMule ipfilter.dat or eserver ipfilter.srv. Operator-supplied,
	// so it lives wherever the operator put it rather than under ./data.
	IPFilterFile string
	// IPFilterMinLevel blocks ranges whose level is strictly below it. Zero means
	// DefaultMinLevel. Note the inverted convention — see DefaultMinLevel.
	IPFilterMinLevel int
	// IPFilterReloadMinutes re-reads the file on a timer so an operator can update a
	// range list without a restart. Zero disables reloading.
	IPFilterReloadMinutes int

	// GeoIPEnabled gates country matching.
	GeoIPEnabled bool
	// GeoIPDatabase is the .mmdb path. Written by the downloader, so under ./data.
	GeoIPDatabase string
	// BlockedCountries is a deny-list of ISO 3166-1 alpha-2 codes.
	BlockedCountries []string
	// Account holds MaxMind credentials, or nil to use only an existing local file.
	Account *WebServiceAccount
	// UpdateDays is the refresh interval. Zero means DefaultUpdateDays.
	UpdateDays int
}

// Filter is the single seam the protocol layer consults. It answers from the static
// range list first, since that is a binary search over merged ranges, and only then
// pays for a GeoIP lookup.
//
// The IP filter is held in an atomic.Pointer rather than behind a mutex: reloads
// replace it wholesale, and the read path is the hottest thing in the server — every
// inbound datagram and every accepted connection. A nil *Filter blocks nothing, so
// callers need no branch when filtering is off.
type Filter struct {
	ipf   atomic.Pointer[IPFilter]
	geo   *GeoIP
	cfg   Config
	stats struct {
		blockedIP  atomic.Int64
		blockedGeo atomic.Int64
	}
}

// New builds a Filter from config and starts whatever background work it needs: the
// ipfilter reload timer and the GeoIP download/refresh loop.
//
// A failure to load the ipfilter file is returned, because the operator explicitly
// named a file and silently allowing everything would be the wrong failure mode. A
// failure to obtain a GeoIP database is not: it is reported through the log and
// leaves country matching inactive, so an unreachable MaxMind cannot stop the server
// from booting. Both halves disabled returns (nil, nil) — the caller stores a nil
// *Filter and pays nothing.
func New(ctx context.Context, cfg Config) (*Filter, error) {
	if !cfg.IPFilterEnabled && !cfg.GeoIPEnabled {
		return nil, nil
	}
	f := &Filter{cfg: cfg}

	if cfg.IPFilterEnabled {
		ipf, err := LoadIPFilter(cfg.IPFilterFile, cfg.IPFilterMinLevel)
		if err != nil {
			return nil, err
		}
		f.ipf.Store(ipf)
		logging.Infof("ipfilter: %s loaded, %d range(s) parsed, %d blocking, %d merged, %d line(s) skipped",
			cfg.IPFilterFile, ipf.Parsed, ipf.Blocking, ipf.Len(), ipf.Skipped)
		if cfg.IPFilterReloadMinutes > 0 {
			go f.reloadIPFilterLoop(ctx, time.Duration(cfg.IPFilterReloadMinutes)*time.Minute)
		}
	}

	if cfg.GeoIPEnabled {
		f.geo = NewGeoIP(cfg.GeoIPDatabase, cfg.BlockedCountries, cfg.Account, cfg.UpdateDays)
		if len(f.geo.denied) == 0 {
			logging.Warnf("geoip: enabled but filter.geoip.blockedCountries is empty; no address will be blocked by country")
		}
		f.geo.Start(ctx)
	}
	return f, nil
}

// Blocked reports whether a peer address is refused, with a reason for the log.
// Called before any wire parsing on both transports, so it must stay cheap: the
// common answer is "not blocked" and reaching it costs one binary search plus, when
// GeoIP is on, one mmdb lookup.
func (f *Filter) Blocked(ip net.IP) (bool, string) {
	if f == nil || ip == nil {
		return false, ""
	}
	if ipf := f.ipf.Load(); ipf != nil {
		if blocked, desc := ipf.Blocked(ip); blocked {
			f.stats.blockedIP.Add(1)
			return true, "ipfilter " + desc
		}
	}
	if blocked, desc := f.geo.Blocked(ip); blocked {
		f.stats.blockedGeo.Add(1)
		return true, "geoip " + desc
	}
	return false, ""
}

// Stats reports how many addresses each half has refused, for the admin surface.
func (f *Filter) Stats() (byIPFilter, byGeoIP int64) {
	if f == nil {
		return 0, 0
	}
	return f.stats.blockedIP.Load(), f.stats.blockedGeo.Load()
}

// Country exposes the country code for an address, or "" when unknown or GeoIP is
// off. Separate from Blocked so logs and the dashboard can report a country without
// implying a verdict.
func (f *Filter) Country(ip net.IP) string {
	if f == nil {
		return ""
	}
	return f.geo.Lookup(ip)
}

// Close releases the GeoIP database handle.
func (f *Filter) Close() error {
	if f == nil {
		return nil
	}
	return f.geo.Close()
}

// reloadIPFilterLoop re-reads the range list on a timer. A failed reload keeps the
// previous list: an operator mid-edit must not accidentally disable filtering, and a
// truncated file read at the wrong moment is exactly how that would happen.
func (f *Filter) reloadIPFilterLoop(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ipf, err := LoadIPFilter(f.cfg.IPFilterFile, f.cfg.IPFilterMinLevel)
			if err != nil {
				logging.Errorf("ipfilter reload failed, keeping the previous list: %v", err)
				continue
			}
			prev := f.ipf.Load()
			if prev != nil && prev.Len() == ipf.Len() && prev.Parsed == ipf.Parsed {
				// Almost certainly unchanged. Compared on counts rather than content
				// because the alternative is hashing a multi-megabyte list every few
				// minutes to avoid one pointer store, which is not worth it.
				continue
			}
			f.ipf.Store(ipf)
			logging.Infof("ipfilter reloaded: %d range(s) parsed, %d blocking, %d merged, %d skipped",
				ipf.Parsed, ipf.Blocking, ipf.Len(), ipf.Skipped)
		case <-ctx.Done():
			return
		}
	}
}
