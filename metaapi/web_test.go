package metaapi

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect/v2"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/metahash"
	"github.com/ModderMule/enodemeta/weblinks"
)

// testWebLinks is a two-file link container and the meta hash of its second file.
func testWebLinks(t *testing.T) ([]byte, metahash.Hash) {
	t.Helper()
	doc := &weblinks.Document{
		Title: "Web.Release.2026",
		Links: []weblinks.Link{
			{URL: "https://examplehost.test/f/abc123", File: 0, Name: "web.release.part1.rar", Hoster: "examplehost"},
			{URL: "https://otherhost.test/d/xyz789", File: 0, Hoster: "otherhost"},
			{URL: "https://examplehost.test/f/def456", File: 1, Name: "web.release.part2.rar", Hoster: "examplehost"},
		},
	}
	in, err := doc.MintInput(1)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := metahash.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	return doc.Bytes(), hash
}

// TestFetcherServesWebLinks: the links behind a web row are its metafile. The fetcher
// asks the web daemon for it, checks it against the row's hash and serves it as a
// text/uri-list; a container with a link swapped is refused.
func TestFetcherServesWebLinks(t *testing.T) {
	container, hash := testWebLinks(t)
	src := newFakeSource()
	src.networks = []string{networkTorrent, networkWeb}
	src.files["web:good"] = &metav1.MetaFile{Kind: metav1.MetaKind_META_KIND_WEB, Content: container, ContentType: weblinks.ContentType}
	src.files["web:swapped"] = &metav1.MetaFile{
		Kind:    metav1.MetaKind_META_KIND_WEB,
		Content: []byte("https://examplehost.test/f/abc123\nhttps://elsewhere.test/f/def456\n"),
	}
	f := newTestFetcher(src)
	t.Logf("input: a %d-byte container, row hash %s", len(container), hash)

	mf, err := f.Get(context.Background(), hash[:], "web:good")
	if err != nil {
		t.Fatalf("fetching a web row's links: %v", err)
	}
	t.Logf("output: kind=%s contentType=%q bytes=%d", mf.GetKind(), mf.GetContentType(), len(mf.GetContent()))
	if mf.GetKind() != metav1.MetaKind_META_KIND_WEB || string(mf.GetContent()) != string(container) {
		t.Fatalf("got kind %s and %d bytes, want the container unchanged", mf.GetKind(), len(mf.GetContent()))
	}
	if got := ContentType(mf.GetKind()); got != "text/uri-list" {
		t.Fatalf("default content type %q, want text/uri-list", got)
	}

	// A fresh fetcher: the first answer is cached by hash, whatever id asks next.
	_, err = newTestFetcher(src).Get(context.Background(), hash[:], "web:swapped")
	var fe *FetchError
	t.Logf("input: a container with one link swapped; output: %v", err)
	if !errors.As(err, &fe) || fe.MsgCode != CodeVerifyFailed {
		t.Fatalf("got %v, want %s", err, CodeVerifyFailed)
	}

	// The kind is served only while the web network is on.
	if fmt.Sprint(f.Kinds()) != "[META_KIND_BT_V1 META_KIND_BT_V2 META_KIND_WEB]" {
		t.Fatalf("kinds %v, want the torrent kinds and WEB", f.Kinds())
	}
	off := newTestFetcher(newFakeSource())
	_, err = off.Get(context.Background(), hash[:], "web:good")
	t.Logf("input: the same row with the web network off; output: %v", err)
	if !errors.As(err, &fe) || fe.Code != connect.CodeNotFound {
		t.Fatalf("got %v, want not found", err)
	}
}

// TestSearchWebNetwork: web is a network to search and WEB is its kind. Its releases
// come after those of the four networks whose order the contract fixed.
func TestSearchWebNetwork(t *testing.T) {
	cat := newFakeCatalog()
	cat.releases[networkTorrent] = releases("t", 2)
	cat.releases[networkKad] = releases("k", 2)
	cat.releases[networkWeb] = releases("w", 2)
	svc := searchService(cat)

	for _, tc := range []struct {
		name    string
		network metav1.MetaNetwork
		kinds   []metav1.MetaKind
		want    string
	}{
		{"every network", metav1.MetaNetwork_META_NETWORK_UNSPECIFIED, nil, "[t0 k0 w0 t1 k1 w1]"},
		{"web", metav1.MetaNetwork_META_NETWORK_WEB, nil, "[w0 w1]"},
		{"web kind", metav1.MetaNetwork_META_NETWORK_UNSPECIFIED, []metav1.MetaKind{metav1.MetaKind_META_KIND_WEB}, "[w0 w1]"},
		{"torrent network, web kind", metav1.MetaNetwork_META_NETWORK_TORRENT, []metav1.MetaKind{metav1.MetaKind_META_KIND_WEB}, "[]"},
		{"web network, ed2k kind", metav1.MetaNetwork_META_NETWORK_WEB, []metav1.MetaKind{metav1.MetaKind_META_KIND_ED2K}, "[]"},
	} {
		resp, err := svc.Search(context.Background(), &metav1.SearchRequest{Query: "x", Network: tc.network, Kinds: tc.kinds})
		got := fmt.Sprint(names(resp))
		t.Logf("input: %s; output: %s err=%v", tc.name, got, err)
		if err != nil || got != tc.want {
			t.Fatalf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}

	caps, _ := svc.GetCaps(context.Background(), &metav1.GetCapsRequest{})
	t.Logf("input: torrent, kad and web on; output: caps.networks=%v", caps.GetNetworks())
	if fmt.Sprint(caps.GetNetworks()) != "[META_NETWORK_TORRENT META_NETWORK_KAD META_NETWORK_WEB]" {
		t.Fatalf("caps.networks %v, want torrent, kad and web", caps.GetNetworks())
	}
}
