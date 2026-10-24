package admin

import (
	"html/template"
	"net/http"
	"net/url"
	"runtime/pprof"
	"strings"
)

// pprofPage is what a browser gets for a binary profile: the profile itself would only
// start a download of a file named after the profile, with no page to show.
var pprofPage = template.Must(template.New("pprof").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Name}} profile</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 16px;background:#fff;color:#222}
code,pre{font:13px ui-monospace,monospace;background:#f2f2f2;border-radius:4px}
pre{padding:.75rem;overflow-x:auto}
a.btn{display:inline-block;padding:.4rem .9rem;border-radius:4px;background:#2563eb;color:#fff;text-decoration:none}
@media (prefers-color-scheme:dark){body{background:#16181c;color:#ddd}code,pre{background:#24272d}}
</style></head><body>
<h1>{{.Name}} profile</h1>
<p>This profile is a binary file for <code>go tool pprof</code>, so it downloads instead of showing here.{{if .Slow}} Collecting it takes the requested time (default 30 s) before the download starts.{{end}}</p>
<p><a class="btn" href="{{.Download}}" download="{{.File}}">Download {{.File}}</a>
{{if .Text}} &nbsp; <a href="{{.Text}}">View as text</a>{{end}}
 &nbsp; <a href="./">All profiles</a></p>
<p>Read it with:</p>
<pre>go tool pprof -top {{.File}}
go tool pprof -http=:8081 {{.File}}</pre>
</body></html>
`))

// pprofDownloadPage puts pprofPage in front of the binary profiles when a browser asks,
// and passes everything else through: curl and go tool pprof get the file, as do the
// text views (?debug=1), the index, cmdline, symbol and unknown names.
func pprofDownloadPage(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name, ok := binaryProfile(r)
		if !ok {
			next(w, r)
			return
		}
		q := r.URL.Query()
		q.Set("download", "1")
		data := struct {
			Name, File     string
			Download, Text string
			Slow           bool
		}{
			Name:     name,
			File:     name + ".pb.gz",
			Download: "?" + q.Encode(),
			Slow:     name == "profile" || name == "trace",
		}
		if name == "trace" {
			data.File = "trace.out"
		}
		if name != "profile" && name != "trace" {
			data.Text = "?" + url.Values{"debug": {"1"}}.Encode()
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = pprofPage.Execute(w, data)
	}
}

// binaryProfile reports the profile name when r is a browser asking for a binary
// profile without the download flag.
func binaryProfile(r *http.Request) (string, bool) {
	q := r.URL.Query()
	if q.Has("download") || (q.Get("debug") != "" && q.Get("debug") != "0") {
		return "", false
	}
	if !strings.Contains(r.Header.Get("Accept"), "text/html") {
		return "", false
	}
	name, ok := strings.CutPrefix(r.URL.Path, "/debug/pprof/")
	if !ok || name == "" {
		return "", false
	}
	if name == "profile" || name == "trace" || pprof.Lookup(name) != nil {
		return name, true
	}
	return "", false
}
