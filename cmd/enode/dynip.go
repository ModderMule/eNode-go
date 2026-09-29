package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"enode/ed2k"
	"enode/logging"
)

const defaultDynIPResolveTimeout = 3 * time.Second

func resolveDynIPValue(dynIP string, testURLs []string, timeout time.Duration) (string, string, error) {
	trimmed := strings.TrimSpace(dynIP)
	if !strings.EqualFold(trimmed, "auto") {
		return trimmed, "", nil
	}
	return fetchPublicIPv4(testURLs, timeout)
}

// resolveDynIP6Value resolves the server's public IPv6. An empty value means "no
// IPv6 self-advertisement"; "auto" probes testURLs6 and, if every endpoint fails,
// falls back to a global-scope address on a local interface (the normal case for a
// server with a real routable v6). Any other value is used verbatim.
//
// With "auto" the probe reports whichever source address the kernel picked for the
// outbound connection, which on a SLAAC host with privacy extensions is a temporary
// address that rotates away within a day. pickStableIPv6 swaps such an address for a
// stable one on the same host, so the advertised address outlives the process start.
func resolveDynIP6Value(dynIP6 string, testURLs6 []string, timeout time.Duration) (string, string, error) {
	trimmed := strings.TrimSpace(dynIP6)
	if trimmed == "" {
		return "", "", nil
	}
	if !strings.EqualFold(trimmed, "auto") {
		return trimmed, "", nil
	}
	probed, url, probeErr := fetchPublicIPv6(testURLs6, timeout)
	if probeErr != nil {
		probed, url = "", ""
	}
	choice := pickStableIPv6(probed, localIPv6Candidates())
	if choice.IP == "" {
		return "", "", probeErr
	}
	via := url
	if via == "" {
		via = "local-interface"
	}
	if choice.Note != "" {
		via += " (" + choice.Note + ")"
	}
	if choice.Unstable {
		logging.Warnf("dynIp6 %s is a temporary/deprecated address and will stop working when it rotates; set ipv6.dynIp6 to a stable address", choice.IP)
	}
	if choice.StableCount > 1 {
		logging.Infof("dynIp6: %d stable public IPv6 addresses on this host, advertising %s; set ipv6.dynIp6 to choose another", choice.StableCount, choice.IP)
	}
	return choice.IP, via, nil
}

func fetchPublicIPv4(testURLs []string, timeout time.Duration) (string, string, error) {
	return fetchPublicIP("IPv4", "tcp4", testURLs, timeout, isPublicIPv4)
}

func fetchPublicIPv6(testURLs []string, timeout time.Duration) (string, string, error) {
	return fetchPublicIP("IPv6", "tcp6", testURLs, timeout, ed2k.IsPublicIPv6)
}

// fetchPublicIP probes the echo endpoints concurrently over the given network and
// returns the first that answers with an address the validator accepts.
//
// Concurrent and first-answer-wins: sequentially, several endpoints at a 3 s
// timeout each stalled startup for many seconds before any port was bound, and
// every one has to fail for that to be the answer anyway. The network is forced
// (tcp4/tcp6) so a dual-stack endpoint reports the family we can actually use.
func fetchPublicIP(kind, network string, testURLs []string, timeout time.Duration, valid func(net.IP) bool) (string, string, error) {
	logging.Debugf("fetchPublic%s request: testUrls=%v timeout=%s", kind, testURLs, timeout)
	if timeout <= 0 {
		timeout = defaultDynIPResolveTimeout
	}

	urls := make([]string, 0, len(testURLs))
	for _, rawURL := range testURLs {
		if url := strings.TrimSpace(rawURL); url != "" {
			urls = append(urls, url)
		}
	}
	if len(urls) == 0 {
		err := fmt.Errorf("no valid testUrls configured")
		logging.Debugf("fetchPublic%s response: ip=\"\" resolvedBy=\"\" err=%v", kind, err)
		return "", "", err
	}

	client := newDynIPClientNet(timeout, network)
	type probeResult struct {
		ip  string
		url string
		err error
	}
	results := make(chan probeResult, len(urls))
	for _, url := range urls {
		go func(url string) {
			logging.Debugf("fetchPublic%s try: url=%s", kind, url)
			ip, err := fetchIPFromURL(client, url, valid)
			results <- probeResult{ip: ip, url: url, err: err}
		}(url)
	}

	for range urls {
		res := <-results
		if res.err == nil {
			logging.Debugf("fetchPublic%s response: ip=%s resolvedBy=%s err=<nil>", kind, res.ip, res.url)
			return res.ip, res.url, nil
		}
		logging.Debugf("fetchPublic%s response: ip=\"\" resolvedBy=\"\" url=%s err=%v", kind, res.url, res.err)
	}

	err := fmt.Errorf("all testUrls failed to return a valid %s", kind)
	logging.Debugf("fetchPublic%s response: ip=\"\" resolvedBy=\"\" err=%v", kind, err)
	return "", "", err
}

func fetchIPv4FromURL(client *http.Client, url string) (string, error) {
	return fetchIPFromURL(client, url, isPublicIPv4)
}

func fetchIPFromURL(client *http.Client, url string, valid func(net.IP) bool) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status code %d", resp.StatusCode)
	}
	// Cloudflare's /cdn-cgi/trace body runs to a few hundred bytes, so the old
	// 128-byte cap was not reliably enough to reach its ip= line. The limit is
	// here to bound a hostile response, and 4 KiB does that just as well.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	value := parseIPResponse(string(body))
	ip := net.ParseIP(value)
	if ip == nil || !valid(ip) {
		return "", fmt.Errorf("invalid address %q", value)
	}
	return ip.String(), nil
}

// isPublicIPv4 accepts any IPv4 (or IPv4-mapped) address. The endpoints already
// return the caller's public address, so no further scope filtering is applied,
// preserving the original behaviour. (The genuine-public-IPv6 test lives in
// ed2k.IsPublicIPv6, reused directly as the v6 validator.)
func isPublicIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

// newDynIPClient forces IPv4 for the probe. Kept for callers/tests that only need
// the v4 path; newDynIPClientNet is the general form.
func newDynIPClient(timeout time.Duration) *http.Client {
	return newDynIPClientNet(timeout, "tcp4")
}

// newDynIPClientNet forces a specific address family (tcp4/tcp6) for the probe.
//
// On a dual-stack host these endpoints report whichever family the connection
// used, so forcing the network is what makes the reply the one we can actually
// use — for every URL in the list, not just Cloudflare's.
func newDynIPClientNet(timeout time.Duration, forceNetwork string) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if network == "tcp" {
					network = forceNetwork
				}
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
}

// ipv6Candidate is one public IPv6 on a local interface. FlagsKnown is false when
// the platform could not report address state, in which case the address is taken
// at face value, as it was before flags were read.
type ipv6Candidate struct {
	IP         net.IP
	Temporary  bool
	Deprecated bool
	Tentative  bool
	FlagsKnown bool
}

// stable reports whether the address is fit to advertise: not a privacy address,
// not past its preferred lifetime, and done with duplicate address detection.
func (c ipv6Candidate) stable() bool {
	return !c.FlagsKnown || (!c.Temporary && !c.Deprecated && !c.Tentative)
}

// ipv6Choice is pickStableIPv6's verdict. Note explains a substitution for the log;
// Unstable marks a choice made only because nothing stable was available.
type ipv6Choice struct {
	IP          string
	Note        string
	Unstable    bool
	StableCount int
}

// fallbackIPv6Candidates lists public IPv6 addresses via net.InterfaceAddrs, which
// carries no address state, so every entry has FlagsKnown=false.
func fallbackIPv6Candidates() []ipv6Candidate {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []ipv6Candidate
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || !ed2k.IsPublicIPv6(ipNet.IP) {
			continue
		}
		out = append(out, ipv6Candidate{IP: ipNet.IP})
	}
	return out
}

// pickStableIPv6 decides which IPv6 to advertise from the probe's answer (empty if
// every probe failed) and the local candidates:
//
//  1. probed address is local and stable (or its state is unknown) -> keep it
//  2. probed address is not local (NPTv6, NAT66, a tunnel) -> keep it; we cannot
//     judge an address this host does not own
//  3. probed address is local but temporary/deprecated/tentative -> the best stable
//     local address instead, preferring the probed one's /64; kept, flagged
//     Unstable, if there is none
//  4. no probe answer -> the best stable local address, else any local one flagged
//     Unstable
func pickStableIPv6(probed string, cands []ipv6Candidate) ipv6Choice {
	stableCount := 0
	for _, c := range cands {
		if c.FlagsKnown && c.stable() {
			stableCount++
		}
	}
	probedIP := net.ParseIP(probed)
	if probedIP != nil {
		for _, c := range cands {
			if !c.IP.Equal(probedIP) {
				continue
			}
			if c.stable() {
				return ipv6Choice{IP: probedIP.String(), StableCount: stableCount}
			}
			if best := bestStableIPv6(cands, probedIP); best != nil {
				return ipv6Choice{
					IP:          best.String(),
					Note:        fmt.Sprintf("replaced %s %s with stable %s", ipv6StateName(c), probedIP, best),
					StableCount: stableCount,
				}
			}
			return ipv6Choice{IP: probedIP.String(), Unstable: true, StableCount: stableCount}
		}
		return ipv6Choice{IP: probedIP.String(), StableCount: stableCount}
	}
	if best := bestStableIPv6(cands, nil); best != nil {
		return ipv6Choice{IP: best.String(), StableCount: stableCount}
	}
	// Nothing stable. A tentative address may not even be usable yet, so prefer
	// a temporary or deprecated one over it.
	for _, c := range cands {
		if !c.Tentative {
			return ipv6Choice{IP: c.IP.String(), Unstable: true, StableCount: stableCount}
		}
	}
	if len(cands) > 0 {
		return ipv6Choice{IP: cands[0].IP.String(), Unstable: true, StableCount: stableCount}
	}
	return ipv6Choice{}
}

// bestStableIPv6 returns the first stable candidate in near's /64 (the same link
// and prefix the kernel routed the probe from), else the first stable candidate at
// all, else nil.
func bestStableIPv6(cands []ipv6Candidate, near net.IP) net.IP {
	if near != nil {
		prefix := net.CIDRMask(64, 128)
		for _, c := range cands {
			if c.stable() && c.IP.Mask(prefix).Equal(near.Mask(prefix)) {
				return c.IP
			}
		}
	}
	for _, c := range cands {
		if c.stable() {
			return c.IP
		}
	}
	return nil
}

func ipv6StateName(c ipv6Candidate) string {
	switch {
	case c.Temporary:
		return "temporary"
	case c.Deprecated:
		return "deprecated"
	default:
		return "tentative"
	}
}

// parseIPResponse extracts an address from an echo-service body.
//
// Most endpoints return a bare IP, but Cloudflare's /cdn-cgi/trace returns
// key=value lines (fl=, h=, ip=, ts=, ...) — so a bare net.ParseIP over the
// whole body rejects it outright.
func parseIPResponse(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "ip="); ok {
			return strings.TrimSpace(rest)
		}
	}
	return strings.Trim(strings.TrimSpace(body), "\"")
}
