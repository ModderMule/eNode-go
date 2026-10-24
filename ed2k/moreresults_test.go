package ed2k

import (
	"testing"
	"time"

	"enode/storage"
)

// setMoreResults applies a tcp.moreResults setting to the client's runtime.
func setMoreResults(t *testing.T, client *tcpClient, maxRows int, ttl time.Duration) {
	t.Helper()
	tcp, udp := client.server.TCPConfig(), client.server.UDPConfig()
	tcp.MoreResultsMax, tcp.MoreResultsTTL = maxRows, ttl
	client.server.ApplyRuntimeConfig(tcp, udp)
	t.Logf("input: moreResults maxRows=%d ttl=%s; applied max=%d ttl=%s",
		maxRows, ttl, client.server.tcp().MoreResultsMax, client.server.tcp().MoreResultsTTL)
}

// TestMoreResultsKeepsTwoPagesByDefault is the memory bound: a search that hits the
// 1000-row cap keeps two more pages, in an array of their own.
func TestMoreResultsKeepsTwoPagesByDefault(t *testing.T) {
	client, conn := searchPagingClient(t, storage.MaxSearchResults)

	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	count, more, _ := decodeSearchResult(t, conn.takeWritten())
	rows := client.pendingRows()
	t.Logf("input: %d matching files; output: page1=%d more=0x%02x pending=%d cap=%d",
		storage.MaxSearchResults, count, more, len(rows), cap(rows))
	if count != storage.MaxSearchPage || more != 1 {
		t.Fatalf("page 1 = %d rows more=0x%02x, want %d with the more byte", count, more, storage.MaxSearchPage)
	}
	if len(rows) != defaultMoreResultsMax {
		t.Fatalf("pending = %d rows, want %d", len(rows), defaultMoreResultsMax)
	}
	// A tail sliced from the result would have the cap of everything after page 1;
	// a copy has its own array, rounded up to an allocation size class at most.
	if cap(rows) >= storage.MaxSearchResults-storage.MaxSearchPage {
		t.Fatalf("pending cap = %d for %d rows: the whole result is still pinned", cap(rows), len(rows))
	}

	pages := []uint32{count}
	for range 3 {
		client.handleED2K(OpQueryMoreResult, NewBufferFromBytes(nil))
		n, m, _ := decodeSearchResult(t, conn.takeWritten())
		t.Logf("output: More page=%d more=0x%02x pending=%d", n, m, len(client.pendingRows()))
		pages = append(pages, n)
	}
	want := []uint32{storage.MaxSearchPage, storage.MaxSearchPage, storage.MaxSearchPage, 0}
	for i := range want {
		if pages[i] != want[i] {
			t.Fatalf("pages = %v, want %v", pages, want)
		}
	}
}

// TestMoreResultsOffSetsNoMoreFlag covers maxRows 0: only the first page, and no More
// button for a page that would return nothing.
func TestMoreResultsOffSetsNoMoreFlag(t *testing.T) {
	client, conn := searchPagingClient(t, storage.MaxSearchPage+40)
	setMoreResults(t, client, -1, 0)

	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	count, more, _ := decodeSearchResult(t, conn.takeWritten())
	t.Logf("output: page1=%d more=0x%02x pending=%d", count, more, len(client.pendingRows()))
	if count != storage.MaxSearchPage || more != 0 {
		t.Fatalf("page 1 = %d rows more=0x%02x, want %d without the more byte", count, more, storage.MaxSearchPage)
	}
	if len(client.pendingRows()) != 0 {
		t.Fatal("paging off must keep nothing")
	}
}

// TestMoreResultsExpire covers the TTL: a More request after the deadline gets the empty
// final page, and the status ticker's sweep frees an idle session's rows.
func TestMoreResultsExpire(t *testing.T) {
	client, conn := searchPagingClient(t, storage.MaxSearchPage+40)
	setMoreResults(t, client, 0, time.Minute)

	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	_ = conn.takeWritten()
	kept := client.pendingResults.Load()
	if kept == nil || len(kept.rows) != 40 {
		t.Fatalf("pending = %v, want 40 rows", kept)
	}
	t.Logf("output: pending=%d expires in %s", len(kept.rows), time.Until(kept.expires).Round(time.Second))

	client.dropExpiredResults(kept.expires.Add(-time.Second))
	t.Logf("input: sweep before the deadline; output: pending=%d", len(client.pendingRows()))
	if len(client.pendingRows()) != 40 {
		t.Fatal("a sweep before the deadline must keep the rows")
	}
	client.dropExpiredResults(kept.expires)
	t.Logf("input: sweep at the deadline; output: pending=%d", len(client.pendingRows()))
	if client.pendingResults.Load() != nil {
		t.Fatal("a sweep at the deadline must drop the rows")
	}

	// Expired rows not yet swept: the More handler checks the deadline itself.
	client.pendingResults.Store(&pendingSearch{rows: kept.rows, expires: time.Now().Add(-time.Second)})
	client.handleED2K(OpQueryMoreResult, NewBufferFromBytes(nil))
	count, more, _ := decodeSearchResult(t, conn.takeWritten())
	t.Logf("input: More after the deadline; output: count=%d more=0x%02x", count, more)
	if count != 0 || more != 0 {
		t.Fatalf("count=%d more=0x%02x, want the empty final page", count, more)
	}
}

// TestMoreResultsKeepDeadlineAcrossPages pins that paging does not extend the deadline:
// each More request would otherwise grant the rows another TTL.
func TestMoreResultsKeepDeadlineAcrossPages(t *testing.T) {
	client, conn := searchPagingClient(t, storage.MaxSearchResults)
	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	_ = conn.takeWritten()
	first := client.pendingResults.Load().expires

	client.handleED2K(OpQueryMoreResult, NewBufferFromBytes(nil))
	_ = conn.takeWritten()
	second := client.pendingResults.Load()
	t.Logf("output: deadline after search=%s, after More=%s, pending=%d",
		first.Format(time.RFC3339Nano), second.expires.Format(time.RFC3339Nano), len(second.rows))
	if !second.expires.Equal(first) {
		t.Fatal("a More request moved the deadline")
	}
}

// TestMoreResultsSurviveHandoff covers a handover: the rows move to the new process.
func TestMoreResultsSurviveHandoff(t *testing.T) {
	client, conn := searchPagingClient(t, storage.MaxSearchPage+40)
	client.handleED2K(OpSearchRequest, searchFor(t, "paging-"))
	_ = conn.takeWritten()

	st := client.exportState()
	next := newTCPClient(client.server, &recordingConn{}, false)
	next.applyState(st)
	t.Logf("input: %d rows exported; output: %d rows after import", len(st.PendingResults), len(next.pendingRows()))
	if len(next.pendingRows()) != 40 {
		t.Fatalf("pending after handover = %d, want 40", len(next.pendingRows()))
	}
	if next.pendingResults.Load().expires.Before(time.Now()) {
		t.Fatal("imported rows must get a fresh deadline")
	}
}
