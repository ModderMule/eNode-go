package admin

import (
	"net/http"

	"enode/logging"
)

// ReloadResult is the body of a successful POST /api/reload-config. Both lists hold
// config key paths (tcp.loginTimeout), never values.
type ReloadResult struct {
	// Applied are the keys whose new values are now in effect.
	Applied []string `json:"applied"`
	// RestartRequired are the keys that differ from the running server and only take
	// effect after a restart.
	RestartRequired []string `json:"restartRequired"`
}

// SetReloader enables the "Reload config" button. reload re-reads the config file and
// applies what can change without a restart; an error means nothing was applied. May
// be called after Start.
func (s *Server) SetReloader(reload func() (ReloadResult, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reload = reload
	s.static.Reload = reload != nil
}

// SetStatic replaces the facts rendered into the pages, for a config reload that changed
// the server name or description. The Accounts and Reload flags are kept: they describe
// what this dashboard serves, not the config.
func (s *Server) SetStatic(static StaticInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	static.Accounts = s.static.Accounts
	static.Reload = s.static.Reload
	s.static = static
}

// SetCredentials replaces the Basic-auth credentials while the server runs. Both empty
// returns non-loopback access to the status page only.
func (s *Server) SetCredentials(username, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.Username = username
	s.cfg.Password = password
}

func (s *Server) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	reload := s.reload
	s.mu.RUnlock()
	if reload == nil {
		http.NotFound(w, r)
		return
	}
	res, err := reload()
	if err != nil {
		logging.Warnf("admin dashboard: config reload by %s failed: %v", r.RemoteAddr, err)
		writeJSONError(w, http.StatusUnprocessableEntity, err)
		return
	}
	// Empty lists rather than null, so the page can read .length without a guard.
	if res.Applied == nil {
		res.Applied = []string{}
	}
	if res.RestartRequired == nil {
		res.RestartRequired = []string{}
	}
	logging.Infof("admin dashboard: config reload by %s", r.RemoteAddr)
	writeJSON(w, res)
}

// credentials and staticInfo read the two values a reload can replace.
func (s *Server) credentials() (username, password string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Username, s.cfg.Password
}

func (s *Server) staticInfo() StaticInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.static
}
