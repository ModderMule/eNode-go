package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"enode/accounts"
	"enode/accounts/payment"
	"enode/accounts/payment/woocommerce"
	"enode/admin"
	"enode/config"
	"enode/ed2k"
	"enode/logging"
	"enode/meta"
	"enode/metaapi"
	"enode/serverlink"
	"enode/storage"
)

// metaAPIRuntime is the client-facing Meta API with its optional accounts: built
// before the eD2K runtime, so OP_SERVERIDENT can advertise it, and started once the
// runtime exists. See docs/meta-api.md.
type metaAPIRuntime struct {
	server   *metaapi.Server
	svc      *metaapi.Service
	fetcher  *metaapi.Fetcher
	accounts *accounts.Service
	advert   ed2k.MetaAPIAdvert
	grpcURL  string
	httpURL  string
	// searcher backs MetaApi.Search's daemon networks; nil when it has none.
	searcher *meta.Searcher
	// searchMode is "off", "public" or "account", for the dashboard.
	searchMode string
	// publicStatus is whether the HTTP listener serves GET /status.
	publicStatus bool
	// tls is whether the listeners serve TLS, for the logged local URLs.
	tls bool
}

// buildMetaAPI builds the Meta API when metaApi.enabled is on, or returns nil.
//
// servers is the searcher that asks other servers, or nil. With
// metaApi.search.servers on, MetaApi.Search answers with their files and this
// server's own as the servers network.
func buildMetaAPI(ctx context.Context, cfg config.Config, engine storage.Engine, searcher *meta.Searcher, servers *serverlink.Searcher, advertisedIP string) (*metaAPIRuntime, error) {
	c := cfg.MetaAPI
	if !c.Enabled {
		return nil, nil
	}
	if searcher == nil {
		logging.Warnf("meta api: enabled while metaSearch has no network on, so there are no rows to serve metafiles for")
	}

	var accts *accounts.Service
	var web *accounts.Web
	if c.Accounts.Enabled {
		store, ok := engine.(storage.AccountStore)
		if !ok {
			return nil, fmt.Errorf("metaApi.accounts: storage engine %q cannot store accounts", cfg.Storage.Engine)
		}
		if err := store.InitAccounts(ctx); err != nil {
			return nil, fmt.Errorf("metaApi.accounts: %w", err)
		}
		if !store.DurableAccounts() {
			logging.Warnf("meta api: accounts are kept by the memory engine and are lost on restart; use mysql or mongodb")
		}
		var err error
		accts, err = accounts.New(accounts.ConfigFrom(c.Accounts), store, accountStepRegistry(), c.Accounts.Steps, &http.Client{Timeout: 20 * time.Second})
		if err != nil {
			return nil, err
		}
		web = accounts.NewWeb(accts, accounts.PortalConfig{ServerName: cfg.Name, TrustForwardedFor: c.TrustForwardedFor})
	}

	var source metaapi.MetaFileSource
	if searcher != nil { // never a typed nil in the interface
		source = searcher
	}
	fetcher := metaapi.NewFetcher(source,
		time.Duration(c.FetchTimeoutMs)*time.Millisecond, c.MaxMetafileBytes, c.MetafileCache.MaxBytes,
		time.Duration(c.MetafileCache.TTLSeconds)*time.Second, time.Duration(c.MetafileCache.NegativeTTLSeconds)*time.Second)

	tls := c.TLSEnabled()
	rt := &metaAPIRuntime{fetcher: fetcher, accounts: accts, publicStatus: c.PublicStatusEnabled(), tls: tls}
	if c.GRPCEnabled() {
		rt.grpcURL = metaAPIURL(c.AdvertiseURL, c.GRPC.Listen, tls, advertisedIP)
	}
	if c.HTTPAPIEnabled() {
		rt.httpURL = metaAPIURL(c.HTTPAdvertiseURL, c.HTTP.Listen, tls, advertisedIP)
	}
	svcCfg := metaapi.ServiceConfig{
		HTTPURL:             rt.httpURL,
		MaxMetafileBytes:    c.MaxMetafileBytes,
		PerIPPerMinute:      c.RateLimit.PerIPPerMinute,
		PerAccountPerMinute: c.RateLimit.PerAccountPerMinute,
		TrustForwardedFor:   c.TrustForwardedFor,
	}
	rt.searchMode = "off"
	if c.SearchEnabled() && (searcher != nil || c.Search.Servers) {
		s := c.Search
		catalog := &combinedCatalog{meta: searcher}
		if searcher != nil {
			searcher.EnableCatalog(meta.CatalogConfig{
				Timeout:    time.Duration(s.TimeoutMs) * time.Millisecond,
				MaxEntries: s.Cache.MaxEntries,
				TTL:        time.Duration(s.Cache.TTLSeconds) * time.Second,
			})
		}
		if s.Servers {
			if servers == nil {
				// Nobody to ask: the network is this server's own files.
				servers = serverlink.NewSearcher(serverlink.SearcherConfig{})
			}
			servers.EnableCatalog(serverlink.CatalogConfig{
				Own:     engine,
				Window:  s.Window,
				Timeout: time.Duration(s.TimeoutMs) * time.Millisecond,
				// The cache is sized in chunks; an answer here is a whole search.
				MaxEntries: max(1, s.Cache.MaxEntries/max(1, s.Window/meta.ChunkSize)),
				TTL:        time.Duration(s.Cache.TTLSeconds) * time.Second,
			})
			catalog.servers = servers
		}
		if len(catalog.CatalogNetworks()) == 0 {
			logging.Warnf("meta api: search is enabled but no metaSearch network has liveSearch on and metaApi.search.servers is off; MetaApi.Search finds nothing")
		}
		svcCfg.Search = &metaapi.SearchConfig{
			Catalog:             catalog,
			OwnFiles:            engine,
			RequireAccount:      c.SearchRequiresAccount(),
			MaxLimit:            s.MaxLimit,
			Window:              s.Window,
			PerIPPerMinute:      s.RateLimit.PerIPPerMinute,
			PerAccountPerMinute: s.RateLimit.PerAccountPerMinute,
		}
		rt.searcher = searcher
		rt.searchMode = "public"
		if c.SearchRequiresAccount() {
			rt.searchMode = "account"
		}
	}
	rt.svc = metaapi.NewService(svcCfg, fetcher, accts)

	scfg := metaapi.ServerConfig{
		HTTPAPI:           c.HTTPAPIEnabled(),
		CertFile:          c.TLS.CertFile,
		KeyFile:           c.TLS.KeyFile,
		TrustForwardedFor: c.TrustForwardedFor,
		MaxMetafileBytes:  c.MaxMetafileBytes,
		PublicStatus:      c.PublicStatusEnabled(),
	}
	if c.GRPCEnabled() {
		scfg.GRPCListen = c.GRPC.Listen
	}
	if c.HTTPListenerEnabled() {
		scfg.HTTPListen = c.HTTP.Listen
	}
	server, err := metaapi.NewServer(scfg, rt.svc, web)
	if err != nil {
		return nil, err
	}
	rt.server = server

	// ST_META_API names the gRPC endpoint, or the HTTP one when gRPC is off.
	rt.advert.URL = rt.grpcURL
	if rt.advert.URL == "" {
		rt.advert.URL = rt.httpURL
	}
	if rt.advert.URL == "" && (c.GRPCEnabled() || c.HTTPAPIEnabled()) {
		logging.Warnf("meta api: no advertised server IP and no metaApi.advertiseURL, so clients are not told where the API is")
	}
	rt.advert.Version = metaapi.ContractVersion
	if c.TLS.AdvertiseFingerprint {
		rt.advert.Fingerprint = server.Fingerprint()
	}
	return rt, nil
}

// start binds the listeners and starts the account reconciler. The returned
// function stops both.
func (rt *metaAPIRuntime) start(ctx context.Context) (func(), error) {
	if err := rt.server.Start(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if rt.accounts != nil {
			rt.accounts.Run(ctx)
		}
	}()
	mode := "public"
	if rt.accounts != nil {
		mode = fmt.Sprintf("accounts (%d registration steps, register at %s)", len(rt.accounts.Steps()), rt.accounts.RegistrationURL())
	}
	logging.Infof("meta api: grpc=%s http=%s mode=%s", orOff(rt.grpcURL), orOff(rt.httpURL), mode)
	if addr := rt.server.HTTPAddr(); addr != nil {
		base := metaAPILocalURL(addr, rt.tls)
		status := "off"
		if rt.publicStatus {
			status = base + "/status (public server name, user and file counts, uptime)"
		}
		logging.Infof("meta api: health %s/healthz (liveness probe), status %s", base, status)
	}
	return func() {
		cancel()
		<-done
		rt.server.Close()
	}, nil
}

// setStatus attaches the eD2K runtime as the source of the public GET /status. Read
// through the runtime on every request, so a config reload shows up.
func (rt *metaAPIRuntime) setStatus(runtime *ed2k.ServerRuntime, startTime time.Time) {
	rt.server.SetStatus(func() metaapi.Status {
		st := runtime.PublicStatus()
		return metaapi.Status{
			Name:          st.Name,
			Description:   st.Description,
			Version:       ed2k.ENodeVersionStr,
			Users:         st.Users,
			LowIDUsers:    st.LowIDUsers,
			Files:         st.Files,
			Servers:       st.Servers,
			MaxUsers:      st.MaxUsers,
			SoftFileLimit: st.SoftFileLimit,
			HardFileLimit: st.HardFileLimit,
			UptimeSeconds: int64(time.Since(startTime).Seconds()),
		}
	})
}

// adminStats is the dashboard's view of the API. Nil-receiver safe: nil when off.
func (rt *metaAPIRuntime) adminStats() *admin.MetaAPIStats {
	if rt == nil {
		return nil
	}
	fs, ss := rt.fetcher.Stats(), rt.svc.Stats()
	out := &admin.MetaAPIStats{
		AuthMode:       "public",
		GRPCURL:        rt.grpcURL,
		HTTPURL:        rt.httpURL,
		Served:         fs.Served.Load(),
		CacheHits:      fs.CacheHits.Load(),
		CacheBytes:     rt.fetcher.CacheBytes(),
		NotFound:       fs.NotFound.Load(),
		VerifyFailed:   fs.VerifyFailed.Load(),
		UpstreamErrors: fs.UpstreamError.Load(),
		RateLimited:    ss.RateLimited.Load(),
		AuthFailures:   ss.AuthFailures.Load(),
		Logins:         ss.Logins.Load(),
		Search:         rt.searchMode,
		Searches:       ss.Searches.Load(),
	}
	if rt.searcher != nil {
		out.SearchCacheEntries = rt.searcher.CatalogCacheEntries()
	}
	if rt.accounts != nil {
		out.AuthMode = "account"
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if counts, err := rt.accounts.Counts(ctx); err == nil {
			out.AccountsPending = counts[storage.AccountPending]
			out.AccountsActive = counts[storage.AccountActive]
			out.AccountsExpired = counts[storage.AccountExpired]
			out.AccountsDisabled = counts[storage.AccountDisabled]
		}
	}
	return out
}

// advertisement is the OP_SERVERIDENT view. Nil-receiver safe: zero when off.
func (rt *metaAPIRuntime) advertisement() ed2k.MetaAPIAdvert {
	if rt == nil {
		return ed2k.MetaAPIAdvert{}
	}
	return rt.advert
}

// accountStepRegistry names every registration step type and payment provider this
// binary knows. A new step type or provider is registered here.
func accountStepRegistry() accounts.Registry {
	reg := accounts.Registry{}
	reg.Register(payment.TypeName, payment.NewFactory(payment.Providers{
		woocommerce.Name: woocommerce.Factory,
	}))
	return reg
}

// metaAPIURL is an explicit URL, or one built from the listen address, with the
// wildcard host replaced by the advertised server IP.
func metaAPIURL(explicit, listen string, tls bool, advertisedIP string) string {
	if explicit != "" {
		return strings.TrimRight(explicit, "/")
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return ""
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = advertisedIP
	}
	if host == "" {
		return ""
	}
	scheme := "http"
	if tls {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

func orOff(s string) string {
	if s == "" {
		return "off"
	}
	return s
}

// metaAPILocalURL is the bound HTTP listener as a URL to open from this machine:
// a wildcard bind becomes localhost, so the logged link is clickable.
func metaAPILocalURL(addr net.Addr, tls bool) string {
	hostPort := addr.String()
	if host, port, err := net.SplitHostPort(hostPort); err == nil {
		if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
			host = "localhost"
		}
		hostPort = net.JoinHostPort(host, port)
	}
	scheme := "http"
	if tls {
		scheme = "https"
	}
	return scheme + "://" + hostPort
}
