package admin

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"enode/logging"
)

// ReleaseRepoURL is the GitHub repository whose published releases the update check
// follows.
const ReleaseRepoURL = "https://github.com/ModderMule/eNode-go"

const (
	updateFirstCheckDelay = 30 * time.Second
	updateCheckInterval   = 24 * time.Hour
)

// UpdateInfo is the result of the last successful release check, served to the
// dashboard inside LiveStats.
type UpdateInfo struct {
	Latest    string `json:"latest"`
	URL       string `json:"url"`
	Available bool   `json:"available"`
	CheckedAt string `json:"checkedAt"`
}

// UpdateChecker periodically asks GitHub for the latest published release and caches
// the answer. It reads the tag from the redirect of <repo>/releases/latest, which
// points at <repo>/releases/tag/<tag>: no API call, no body to parse. Drafts and
// pre-releases never become "latest", so a version is announced only once its
// release has been published.
type UpdateChecker struct {
	current string
	repoURL string
	client  *http.Client

	mu   sync.RWMutex
	info *UpdateInfo
}

// NewUpdateChecker returns a checker comparing releases against current (vX.Y.Z).
func NewUpdateChecker(current string) *UpdateChecker {
	return &UpdateChecker{
		current: current,
		repoURL: ReleaseRepoURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
			// The redirect target is the answer; following it would fetch a whole page.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Start runs the first check shortly after startup and then once a day, until ctx is
// cancelled or the returned stop function is called. stop waits for the goroutine.
func (c *UpdateChecker) Start(ctx context.Context) func() {
	// Stopping cancels an in-flight request too, so shutdown never waits on GitHub.
	runCtx, cancel := context.WithCancel(ctx)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		timer := time.NewTimer(updateFirstCheckDelay)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				if err := c.Check(runCtx); err != nil {
					logging.Debugf("update check failed: %v", err)
				}
				timer.Reset(updateCheckInterval)
			case <-runCtx.Done():
				return
			}
		}
	}()
	return func() {
		cancel()
		<-finished
	}
}

// Info returns the last successful check, or nil when no check has succeeded yet.
func (c *UpdateChecker) Info() *UpdateInfo {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.info == nil {
		return nil
	}
	info := *c.info
	return &info
}

// Check asks GitHub once. On failure the previous result is kept.
func (c *UpdateChecker) Check(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.repoURL+"/releases/latest", nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "eNode-go/"+c.current)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return fmt.Errorf("status code %d, want a redirect", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	tag, url, ok := tagFromLocation(location, c.repoURL)
	if !ok {
		return fmt.Errorf("unexpected redirect %q", location)
	}
	info := &UpdateInfo{
		Latest:    tag,
		URL:       url,
		Available: newerVersion(tag, c.current),
		CheckedAt: time.Now().Format(time.RFC3339),
	}
	c.mu.Lock()
	c.info = info
	c.mu.Unlock()
	if info.Available {
		logging.Infof("update available: %s (running %s) %s", tag, c.current, url)
	} else {
		logging.Debugf("update check: latest=%s running=%s", tag, c.current)
	}
	return nil
}

// tagFromLocation extracts the release tag from a <repo>/releases/tag/<tag> redirect.
// Only that exact shape with a vX.Y.Z tag is accepted, so the page never links to
// anything but the repository's own release page.
func tagFromLocation(location, repoURL string) (tag, url string, ok bool) {
	prefix := repoURL + "/releases/tag/"
	if !strings.HasPrefix(location, prefix) {
		return "", "", false
	}
	tag = strings.TrimPrefix(location, prefix)
	if _, ok := parseVersion(tag); !ok {
		return "", "", false
	}
	return tag, location, true
}

// newerVersion reports whether latest is a strictly higher vX.Y.Z than current. A
// malformed value on either side is never "newer".
func newerVersion(latest, current string) bool {
	l, ok := parseVersion(latest)
	if !ok {
		return false
	}
	c, ok := parseVersion(current)
	if !ok {
		return false
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

// parseVersion parses the release tag format enforced by scripts/publish-release.sh.
func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	rest, found := strings.CutPrefix(v, "v")
	if !found {
		return out, false
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		if p == "" || strings.TrimLeft(p, "0123456789") != "" {
			return out, false
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
