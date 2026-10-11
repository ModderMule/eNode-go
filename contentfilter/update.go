package contentfilter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"enode/logging"
)

// DefaultKeyHeader is the request header the update service reads the access key from.
const DefaultKeyHeader = "X-Server-Key"

// maxListBytes caps one download. The lists are text files of 33-byte lines; a body
// past this is not a list.
const maxListBytes = 256 << 20

// updateRetryInterval is how soon a failed scheduled update is tried again.
const updateRetryInterval = time.Hour

// UpdateTarget is one list the update service publishes.
type UpdateTarget struct {
	// Name labels the list in logs and results.
	Name string
	// URL is the list; its signature is fetched from URL + ".sig".
	URL string
	// Path is where the verified list is installed.
	Path string
}

// UpdateConfig describes the update service.
type UpdateConfig struct {
	Targets []UpdateTarget
	// PublicKey verifies the Ed25519 signature every list must carry.
	PublicKey ed25519.PublicKey
	// AccessKey is the credential: the UDP key this server hands the reference server
	// in OP_GLOBSERVSTATRES, which that server exported to the update service.
	AccessKey uint32
	// KeyHeader overrides DefaultKeyHeader.
	KeyHeader string
	UserAgent string
	// Interval is how often the scheduled update runs.
	Interval time.Duration
	// MinKeepRatio refuses a list that would shrink below this fraction of the
	// installed one. Zero disables the check.
	MinKeepRatio float64
	// Client overrides the HTTP client, for tests.
	Client *http.Client
}

// UpdateResult is the outcome of one list's update.
type UpdateResult struct {
	Name     string
	Entries  int
	Previous int // entries in the file that was replaced, -1 when there was none
	Err      error
}

// UpdateStatus is the admin view of the updater.
type UpdateStatus struct {
	// Last is when an update last ran, zero if never.
	Last time.Time
	// OK reports whether every list installed. Message says what went wrong otherwise.
	OK      bool
	Message string
}

// Updater pulls the hash lists from an ed2k-server update service.
//
// Nothing is written until a download is complete, signed and parses, so a failed
// update leaves a working filter rather than a disarmed one.
type Updater struct {
	cfg         UpdateConfig
	client      *http.Client
	onInstalled func()

	mu     sync.RWMutex
	status UpdateStatus
}

// NewUpdater returns an updater. onInstalled, when set, runs after an update installed
// at least one list — the caller passes Filter.Reload.
func NewUpdater(cfg UpdateConfig, onInstalled func()) *Updater {
	if cfg.KeyHeader == "" {
		cfg.KeyHeader = DefaultKeyHeader
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{
			Timeout: 120 * time.Second,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
				TLSHandshakeTimeout:   15 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
			},
		}
	}
	return &Updater{cfg: cfg, client: client, onInstalled: onInstalled}
}

// ParsePublicKey decodes the hex Ed25519 key of filter.update.publicKey.
func ParsePublicKey(hexKey string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("public key is not hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// Run updates on a schedule until ctx is cancelled. The first run is immediate when a
// list is missing or older than the interval, so a restart does not push the next
// update a full interval away.
func (u *Updater) Run(ctx context.Context) {
	if u == nil || u.cfg.Interval <= 0 {
		return
	}
	timer := time.NewTimer(u.firstDelay())
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			next := u.cfg.Interval
			for _, res := range u.UpdateAll(ctx) {
				if res.Err != nil {
					logging.Warnf("content filter update: %s: %v", res.Name, res.Err)
					next = min(next, updateRetryInterval)
					continue
				}
				logging.Infof("content filter update: %s installed, %d hash(es) (was %s)",
					res.Name, res.Entries, previousLabel(res.Previous))
			}
			timer.Reset(next)
		case <-ctx.Done():
			return
		}
	}
}

// UpdateAll updates every list once and reports each outcome. One list failing does
// not stop the others.
func (u *Updater) UpdateAll(ctx context.Context) []UpdateResult {
	if u == nil {
		return nil
	}
	results := make([]UpdateResult, 0, len(u.cfg.Targets))
	installed := false
	status := UpdateStatus{Last: time.Now(), OK: true}
	for _, target := range u.cfg.Targets {
		res := u.update(ctx, target)
		if res.Err == nil {
			installed = true
		} else if status.OK {
			status.OK = false
			status.Message = res.Name + ": " + res.Err.Error()
		}
		results = append(results, res)
	}
	if installed && u.onInstalled != nil {
		u.onInstalled()
	}
	u.mu.Lock()
	u.status = status
	u.mu.Unlock()
	return results
}

// Status returns the outcome of the last update.
func (u *Updater) Status() UpdateStatus {
	if u == nil {
		return UpdateStatus{}
	}
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.status
}

// update downloads, verifies and installs one list.
func (u *Updater) update(ctx context.Context, target UpdateTarget) UpdateResult {
	res := UpdateResult{Name: target.Name, Previous: -1}

	body, err := u.get(ctx, target.URL, maxListBytes)
	if err != nil {
		res.Err = err
		return res
	}
	// The signature covers the bytes as served and is checked before they are parsed:
	// a hijacked host could otherwise push an empty list, or one legal hash that bans
	// its publishers everywhere at once.
	sigFile, err := u.get(ctx, target.URL+".sig", 4096)
	if err != nil {
		res.Err = fmt.Errorf("signature: %w", err)
		return res
	}
	sig, err := parseSignature(sigFile)
	if err != nil {
		res.Err = err
		return res
	}
	if !ed25519.Verify(u.cfg.PublicKey, body, sig) {
		res.Err = errors.New("signature does not verify; nothing was written")
		return res
	}

	list, err := ParseHashList(bytes.NewReader(body))
	if err != nil {
		res.Err = fmt.Errorf("downloaded list does not parse: %w", err)
		return res
	}
	res.Entries = list.Len()

	if old, err := LoadHashList(target.Path); err == nil {
		res.Previous = old.Len()
		// The failure this catches is the ordinary one: a proxy hands back a prefix
		// that parses cleanly and is simply much shorter.
		if u.cfg.MinKeepRatio > 0 && old.Len() > 0 && float64(list.Len()) < float64(old.Len())*u.cfg.MinKeepRatio {
			res.Err = fmt.Errorf("refusing to install: %d hash(es) would replace %d, below filter.update.minKeepRatio %.2f",
				list.Len(), old.Len(), u.cfg.MinKeepRatio)
			return res
		}
	}

	if err := installAtomic(target.Path, body); err != nil {
		res.Err = err
	}
	return res
}

// get fetches one URL with the access key, refusing a body past limit or shorter than
// the server declared.
func (u *Updater) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(u.cfg.KeyHeader, fmt.Sprintf("%08x", u.cfg.AccessKey))
	if u.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", u.cfg.UserAgent)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		// The service's own line tells a wrong key from a pending approval.
		reason, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("HTTP %d %q: this server's public IPv4 is not on the update service's allow list (ask its operator to add it), or the access key is not the one the service expects (filter.update.referenceIP, a changed udp secret, or a different public IP)", resp.StatusCode, strings.TrimSpace(string(reason)))
	default:
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("download %s: larger than %d bytes", url, limit)
	}
	// A dropped connection yields a prefix of a valid list, which parses cleanly.
	if resp.ContentLength >= 0 && int64(len(body)) != resp.ContentLength {
		return nil, fmt.Errorf("download %s: got %d of %d bytes", url, len(body), resp.ContentLength)
	}
	return body, nil
}

// firstDelay is immediate when any list is missing or stale, otherwise the time left
// until the oldest list is one interval old.
func (u *Updater) firstDelay() time.Duration {
	delay := u.cfg.Interval
	for _, target := range u.cfg.Targets {
		info, err := os.Stat(target.Path)
		if err != nil {
			return 0
		}
		delay = min(delay, max(0, u.cfg.Interval-time.Since(info.ModTime())))
	}
	return delay
}

// parseSignature accepts the raw 64 bytes `openssl pkeyutl -sign -rawin` writes, or the
// same in hex.
func parseSignature(raw []byte) ([]byte, error) {
	if len(raw) == ed25519.SignatureSize {
		return raw, nil
	}
	sig, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature file is %d bytes, want %d raw or hex", len(raw), ed25519.SignatureSize)
	}
	return sig, nil
}

// installAtomic writes data beside path and renames it into place, so a reader never
// sees a half-written list and a failed write leaves the old one.
func installAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

func previousLabel(previous int) string {
	if previous < 0 {
		return "no file"
	}
	return fmt.Sprintf("%d", previous)
}
