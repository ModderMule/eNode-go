package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"enode/admin"
	"enode/config"
	"enode/contentfilter"
	"enode/ed2k"
	"enode/ed3k"
	"enode/ed3k/ident"
	"enode/internal/handoff"
	"enode/logging"
	"enode/storage"
)

// ed3kRuntime is the optional ed3k index node: built before the eD2K runtime, so
// OP_SERVERIDENT and the description reply can advertise its link, and started
// with the other services. See docs/ed3k-index-node.md.
type ed3kRuntime struct {
	node   *ed3k.Node
	cfg    config.Ed3kConfig
	link   string
	bridge *ed3kBridgeEngine
}

// buildEd3k builds the index node when ed3k.enabled is on, or returns nil. Its
// socket is bound here, through the handover registry, so a successor process
// adopts it like the eD2K sockets.
func buildEd3k(ctx context.Context, cfg config.Config, engine storage.Engine, advertisedIP string, serverIPv6 []byte, filter *contentfilter.Filter) (*ed3kRuntime, error) {
	c := cfg.Ed3k
	if !c.Enabled {
		return nil, nil
	}
	store, ok := engine.(storage.Ed3kStore)
	if !ok {
		if store, ok = storage.UnwrapEngine(engine).(storage.Ed3kStore); !ok {
			return nil, errors.New("the storage engine has no ed3k store")
		}
	}
	initCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	err := store.InitEd3k(initCtx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("preparing the ed3k store: %w", err)
	}
	key, err := ident.LoadOrCreateKey(cfg.Ed3kKeyPath())
	if err != nil {
		return nil, err
	}
	port := c.Port
	if port == 0 {
		port = cfg.TCP.Port
	}
	udp, err := handoff.ListenUDP("udp", net.JoinHostPort(c.Listen, strconv.Itoa(int(port))))
	if err != nil {
		return nil, fmt.Errorf("binding udp port %d: %w", port, err)
	}
	adv4, adv6 := ed3kAdvertised(c, advertisedIP, serverIPv6, port)
	named := c.Network != ""
	if adv4.IsValid() && !ident.AcceptableEndpoint(adv4, named) {
		logging.Warnf("ed3k: advertised address %v is not a public address; clients outside a named network refuse the link", adv4)
	}
	var reject func(string) bool
	if filter != nil {
		reject = func(name string) bool { return filter.Withheld(nil, name) }
	}
	node, err := ed3k.New(ed3k.Config{
		Key: key, Conn: udp, Network: c.Network, Advertise4: adv4, Advertise6: adv6,
		Agent: "eNode-go " + ed2k.ENodeVersionStr, Nick: c.Nick, Store: store,
		Limits: storage.Ed3kLimits{RecordsPerHost: c.Limits.RecordsPerHost, RecordsPerSite: c.Limits.RecordsPerSite,
			MaxRecords: c.Limits.MaxRecords},
		Budget: ed3k.Budget{MaxConns: c.Limits.MaxConnections, PerHost: c.Limits.ConnectionsPerHost,
			PerSite: c.Limits.ConnectionsPerSite, NewPerHostMin: c.Limits.NewPerHostPerMinute,
			NewPerNodeIDMin: ed3k.DefaultBudget.NewPerNodeIDMin},
		Relay:             ed3k.RelayLimits{Leaves: c.Limits.RelayLeaves, PerHost: c.Limits.RelayPerHost, PerSite: c.Limits.RelayPerSite},
		RequestsPerMinute: c.RequestsPerMinute,
		Reject:            reject,
	})
	if err != nil {
		udp.Close()
		return nil, err
	}
	node.SetBridgeTestTTL(time.Duration(c.Bridge.TCPTestMinutes) * time.Minute)
	rt := &ed3kRuntime{node: node, cfg: c}
	if adv4.IsValid() || adv6.IsValid() {
		rt.link = node.Link().String()
	} else {
		logging.Warnf("ed3k: no address to advertise (address, dynIp and ed3k.advertise are empty); ST_ED3K is not sent")
	}
	return rt, nil
}

// advertisement is the ST_ED3K value; "" when off.
func (rt *ed3kRuntime) advertisement() string {
	if rt == nil {
		return ""
	}
	return rt.link
}

// wrapSources puts the eD2K bridge in front of the engine the eD2K runtime serves
// sources from, when ed3k.bridge.enabled is on.
func (rt *ed3kRuntime) wrapSources(engine storage.Engine) storage.Engine {
	if rt == nil || !rt.cfg.Bridge.Enabled {
		return engine
	}
	rt.bridge = &ed3kBridgeEngine{Engine: engine, node: rt.node, max: rt.cfg.Bridge.MaxPerAnswer}
	return rt.bridge
}

// attach gives the bridge the eD2K sessions, for the user hashes of CT_ED3K logins.
func (rt *ed3kRuntime) attach(runtime *ed2k.ServerRuntime) {
	if rt != nil && rt.bridge != nil {
		rt.bridge.pairing = runtime.Ed3kPairing
	}
}

// start brings the node up and returns its stop.
func (rt *ed3kRuntime) start(ctx context.Context) (func(), error) {
	if rt == nil {
		return func() {}, nil
	}
	if err := rt.node.Start(ctx); err != nil {
		return nil, err
	}
	if rt.link != "" {
		logging.Infof("ed3k: advertising %s in OP_SERVERIDENT", rt.link)
	}
	if rt.cfg.Bridge.Enabled {
		logging.Infof("ed3k: bridge on: ed3k nodes that pass a TCP test are listed as eD2K sources")
	}
	return func() { rt.node.Close() }, nil
}

// adminStats are the dashboard figures; nil when off.
func (rt *ed3kRuntime) adminStats() *admin.Ed3kStats {
	if rt == nil {
		return nil
	}
	st := rt.node.Stats()
	out := &admin.Ed3kStats{
		NodeID: rt.node.ID().String(), Link: rt.link, Network: rt.cfg.Network != "",
		Connections: st.Connections, Accepted: st.Accepted, Refused: st.Refused, Exchanges: st.Exchanges,
		Searches: st.Index.Searches, Stores: st.Index.Stores, Busy: st.Index.Busy, Malformed: st.Index.Malformed,
		RelayLeaves: st.RelayLeaves, Punches: st.Punches, PunchFailed: st.PunchFailed,
		ObfsDropped: st.ObfsDropped, Probes: st.ObfsProbes, Bridge: rt.cfg.Bridge.Enabled, BridgeListed: st.BridgeListed,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if rs, err := rt.node.StoreStats(ctx); err == nil {
		out.Sources, out.Keywords, out.Notes, out.Kept = rs.Sources, rs.Keywords, rs.Notes, rs.Kept
	}
	return out
}

// ed3kAdvertised picks the endpoints of the node's link: ed3k.advertise and
// ed3k.advertiseIPv6, else the server's advertised IPv4 and its IPv6.
func ed3kAdvertised(c config.Ed3kConfig, advertisedIP string, serverIPv6 []byte, port uint16) (v4, v6 netip.AddrPort) {
	ip4 := c.Advertise
	if ip4 == "" {
		ip4 = advertisedIP
	}
	if a, err := netip.ParseAddr(ip4); err == nil && a.Unmap().Is4() {
		v4 = netip.AddrPortFrom(a.Unmap(), port)
	}
	if c.AdvertiseIPv6 != "" {
		if a, err := netip.ParseAddr(c.AdvertiseIPv6); err == nil && !a.Is4() {
			v6 = netip.AddrPortFrom(a, port)
		}
	} else if len(serverIPv6) == 16 {
		v6 = netip.AddrPortFrom(netip.AddrFrom16([16]byte(serverIPv6)), port)
	}
	return v4, v6
}
