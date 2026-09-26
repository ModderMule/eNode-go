package meta

import (
	"context"
	"errors"
	"testing"

	"enode/config"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connectinprocess"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
	"github.com/ModderMule/enodemeta/gen/enode/meta/v1/metav1connect"
)

// metafileDaemon answers FetchMetaFile from a map; everything else is unimplemented.
type metafileDaemon struct {
	metav1connect.UnimplementedMetaIngestHandler
	files map[string][]byte
	asked []string
}

func (d *metafileDaemon) FetchMetaFile(_ context.Context, req *metav1.FetchMetaFileRequest) (*metav1.MetaFile, error) {
	d.asked = append(d.asked, req.GetCatalogId())
	b, ok := d.files[req.GetCatalogId()]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, "unknown release")
	}
	return &metav1.MetaFile{Kind: metav1.MetaKind_META_KIND_BT_V1, Content: b, ContentType: "application/x-bittorrent"}, nil
}

// TestFetchMetaFileRoutesByNetwork checks the call reaches the named network's
// daemon, passes the daemon's errors through, and refuses a disabled network.
func TestFetchMetaFileRoutesByNetwork(t *testing.T) {
	d := &metafileDaemon{files: map[string][]byte{"bt:v1:AA": []byte("d4:infod...ee")}}
	server := connect.NewServer()
	metav1connect.RegisterMetaIngestHandler(server, d)
	client := metav1connect.NewMetaIngestClient(connect.NewClient(connectinprocess.New(server)))
	s := NewWithClients(testConfig(t, true, false), func(string, config.MetaNetworkConfig) metav1connect.MetaIngestClient { return client })

	mf, err := s.FetchMetaFile(context.Background(), NetworkTorrent, "bt:v1:AA")
	t.Logf("input: torrent bt:v1:AA output: %d bytes %s err=%v (asked %v)", len(mf.GetContent()), mf.GetContentType(), err, d.asked)
	if err != nil || string(mf.GetContent()) != "d4:infod...ee" {
		t.Fatalf("FetchMetaFile: %v", err)
	}
	if _, err := s.FetchMetaFile(context.Background(), NetworkTorrent, "bt:v1:BB"); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("unknown release: %v, want not_found from the daemon", err)
	}
	if _, err := s.FetchMetaFile(context.Background(), NetworkUsenet, "nzb:CC"); !errors.Is(err, ErrNetworkDisabled) {
		t.Fatalf("disabled network: %v, want ErrNetworkDisabled", err)
	}
	if len(d.asked) != 2 {
		t.Fatalf("daemon asked %d times, want 2 (never for the disabled network)", len(d.asked))
	}
}
