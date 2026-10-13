package admin

import (
	"embed"
	"html/template"
)

// dashboardFS embeds the dashboard page at build time (stdlib embed — no external
// dependency, no runtime file I/O, so the binary is self-contained). The file is
// authored as real HTML under html/ for editing/highlighting; it carries the
// StaticInfo template actions ({{.Name}}, …) that pageTemplate substitutes. Only
// static data is interpolated — the live counters render as placeholder elements
// (id="clients", …) that the page script fills from /stats.json, so no dynamic
// value is ever baked into the served HTML.
//
// The tabs beyond Status are one file each under html/tabs/, defining the tab's markup
// ("tab-<name>") and its script ("js-<name>"). They too render static facts only and
// load everything else from their /api/ endpoints.
//
//go:embed html/dashboard.html html/tabs/*.html
var dashboardFS embed.FS

// pageTemplate is parsed once at startup from the embedded files.
var pageTemplate = template.Must(template.ParseFS(dashboardFS, "html/dashboard.html", "html/tabs/*.html"))

// pageData is what the page template renders: the static facts, and which tabs and
// buttons this server has.
type pageData struct {
	StaticInfo
	// Tabs is set when the tabs beyond Status are served.
	Tabs     bool
	Features Features
}
