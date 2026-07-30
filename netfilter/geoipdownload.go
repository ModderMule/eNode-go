package netfilter

// GeoLite2 country-database download and refresh.
//
// Ported from verified-gateway/pkg/geoip/download.go, which in turn follows
// https://github.com/maxmind/geoipupdate/blob/main/client/download.go. Kept: the MD5
// conditional-download mechanic, the "missing file forces a download" contract, and
// the corrupt-file recovery on startup. Dropped as inapplicable here: the City and
// ASN editions, minFraud, and the viper-backed configuration.

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"enode/logging"

	"github.com/maxmind/geoipupdate/v7/client"
	"github.com/pkg/errors"
)

// DatabaseEdition is the MaxMind edition ID we fetch. Country, not City: the filter
// only ever needs an ISO code, and the City database is an order of magnitude larger
// for data this server has no use for.
const DatabaseEdition = "GeoLite2-Country"

// Start prepares the database and, when credentials are present, begins the refresh
// loop. It returns without an error even when no database could be obtained —
// country matching is simply inactive in that case, reported through Ready.
//
// The startup sequence mirrors the reference implementation's NewGeoIP:
//
//   - file absent  -> download an initial copy
//   - file present -> open it; if that fails, delete it and re-download
//
// Deleting before the retry is the non-obvious part and it is load-bearing: the
// download is conditional on the current file's MD5, so a corrupt-but-present file
// would hash successfully, match nothing on the server, and be reported as "no
// update available" — leaving the corrupt file in place forever.
func (g *GeoIP) Start(ctx context.Context) {
	if g == nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(g.databaseFileName), 0o755); err != nil {
		logging.Warnf("geoip: cannot create database directory: %v", err)
	}

	switch {
	case !g.fileExists():
		if g.account == nil {
			logging.Warnf("geoip: %s is missing and no MaxMind credentials are configured; country matching is disabled",
				g.databaseFileName)
			return
		}
		logging.Infof("geoip: %s not found, downloading initial copy", g.databaseFileName)
		if err := g.UpdateDatabase(ctx); err != nil {
			logging.Errorf("geoip: initial download failed, country matching is disabled: %+v", err)
			return
		}
	default:
		if err := g.reloadDatabase(); err != nil {
			logging.Errorf("geoip: cannot open %s: %+v", g.databaseFileName, err)
			if g.account == nil {
				logging.Warnf("geoip: no MaxMind credentials configured, cannot replace the unreadable database; country matching is disabled")
				return
			}
			// Remove it so UpdateDatabase cannot match its MD5 and skip the download.
			if err := os.Remove(g.databaseFileName); err != nil {
				logging.Errorf("geoip: cannot remove unreadable database: %v", err)
			}
			if err := g.UpdateDatabase(ctx); err != nil {
				logging.Errorf("geoip: re-download failed, country matching is disabled: %+v", err)
				return
			}
		}
	}

	if loaded, denied := g.Ready(); loaded {
		logging.Infof("geoip: %s loaded, %d denied country code(s)", g.databaseFileName, denied)
	}
	if g.account != nil {
		go g.scheduleUpdates(ctx)
	}
}

// UpdateDatabase checks MaxMind for a newer database and installs it.
//
// The check is conditional on the MD5 of the file already on disk, so a weekly tick
// against an unchanged database costs one request and transfers nothing. A missing
// file hashes to "", which the server treats as "send me the database".
func (g *GeoIP) UpdateDatabase(ctx context.Context) error {
	if g == nil || g.account == nil {
		// No credentials: local file only, never download. Not an error.
		return nil
	}
	accountID, err := strconv.Atoi(g.account.AccountID)
	if err != nil {
		return errors.Wrapf(err, "maxmind accountID %q is not numeric", g.account.AccountID)
	}
	geoClient, err := client.New(accountID, g.account.LicenseKey)
	if err != nil {
		return errors.Wrap(err, "creating maxmind client")
	}

	currentMD5, err := g.currentDatabaseMD5() // "" forces a download
	if err != nil {
		logging.Errorf("geoip: cannot hash the current database, forcing a full download: %+v", err)
		currentMD5 = ""
	}

	res, err := geoClient.Download(ctx, DatabaseEdition, currentMD5)
	if err != nil {
		return errors.Wrapf(err, "downloading %s", DatabaseEdition)
	}
	if !res.UpdateAvailable {
		logging.Infof("geoip: no update available for %s", DatabaseEdition)
		// The client documents Reader as always non-nil on success, so close it even
		// when there is no update to read.
		if res.Reader != nil {
			_ = res.Reader.Close()
		}
		return nil
	}
	defer res.Reader.Close()

	// Write to a temporary file in the destination directory and rename into place.
	// The reference truncates the live file with os.Create; that leaves a zero-length
	// or half-written database on disk if the transfer fails, which the next startup
	// would then have to detect and repair. A rename is atomic, so the live file is
	// either the old database or the complete new one.
	dir := filepath.Dir(g.databaseFileName)
	tmp, err := os.CreateTemp(dir, filepath.Base(g.databaseFileName)+".tmp-*")
	if err != nil {
		return errors.Wrap(err, "creating temporary database file")
	}
	tmpName := tmp.Name()
	defer func() {
		// No-op once the rename has succeeded.
		_ = os.Remove(tmpName)
	}()

	if _, err := io.Copy(tmp, res.Reader); err != nil {
		_ = tmp.Close()
		return errors.Wrap(err, "writing database file")
	}
	if err := tmp.Close(); err != nil {
		return errors.Wrap(err, "closing temporary database file")
	}
	if err := os.Rename(tmpName, g.databaseFileName); err != nil {
		return errors.Wrap(err, "installing database file")
	}

	logging.Infof("geoip: downloaded %s (modified %s, MD5 %s)",
		DatabaseEdition, res.LastModified.Format(time.DateTime), res.MD5)
	return g.reloadDatabase()
}

// scheduleUpdates re-checks for a new database every updateDays, until ctx is done.
func (g *GeoIP) scheduleUpdates(ctx context.Context) {
	days := g.updateDays
	if days <= 0 {
		days = DefaultUpdateDays
	}
	ticker := time.NewTicker(time.Duration(days) * 24 * time.Hour)
	defer ticker.Stop()
	logging.Infof("geoip: checking for %s updates every %d day(s)", DatabaseEdition, days)
	for {
		select {
		case <-ticker.C:
			if err := g.UpdateDatabase(ctx); err != nil {
				logging.Errorf("geoip: update check failed: %+v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// currentDatabaseMD5 hashes the database on disk. A missing file yields "" with no
// error, which is what makes the download unconditional on first run.
func (g *GeoIP) currentDatabaseMD5() (string, error) {
	f, err := os.Open(g.databaseFileName)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", errors.Wrap(err, "opening database file")
	}
	defer f.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", errors.Wrap(err, "reading database file")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
