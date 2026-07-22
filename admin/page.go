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
//go:embed html/dashboard.html
var dashboardFS embed.FS

// pageTemplate is parsed once at startup from the embedded file.
var pageTemplate = template.Must(template.ParseFS(dashboardFS, "html/dashboard.html"))
