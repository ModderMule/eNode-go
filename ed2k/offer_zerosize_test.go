package ed2k

import (
	"testing"

	"enode/storage"
)

// A record whose FT_FILESIZE tag is absent, or present but not an integer, leaves
// FileRecord.Size at 0 (buffer.go:637-644). Such a file is unusable and permanent: a
// client only ever asks for sources by (hash, size), and eMule discards a zero-size
// search result outright (srchybrid/SearchList.cpp:355). buffer_test.go:272-276 already
// records the symptom — "published but never returned any sources". handleOfferFiles
// refuses them instead, at the one site before Storage.AddFile so every engine agrees.

// zeroSizeOfferItems builds an OP_OFFERFILES carrying one good record and two bad ones:
// a tag of FT_FILESIZE = 0, and a record with no size tag at all. AddFile in packet.go
// always emits FT_FILESIZE, so the second bad record is assembled by hand.
func zeroSizeOfferItems() []PacketItem {
	offer := []PacketItem{
		{Type: TypeUint8, Value: OpOfferFiles},
		{Type: TypeUint32, Value: uint32(3)},
	}
	AddFile(&offer, SharedFile{
		Name: "good.bin", Size: 4096, Hash: offerHash(1),
		SourceID: ValCompleteID, SourcePort: ValCompletePort, Completed: 1, Sources: 1,
	})
	AddFile(&offer, SharedFile{
		Name: "zero-tag.bin", Size: 0, Hash: offerHash(2),
		SourceID: ValCompleteID, SourcePort: ValCompletePort, Completed: 1, Sources: 1,
	})
	offer = append(offer,
		PacketItem{Type: TypeHash, Value: offerHash(3)},
		PacketItem{Type: TypeUint32, Value: ValCompleteID},
		PacketItem{Type: TypeUint16, Value: ValCompletePort},
		PacketItem{Type: TypeTags, Value: []Tag{
			{Type: TypeString, Code: TagName, Data: "no-tag.bin"},
			{Type: TypeUint32, Code: TagSources, Data: uint32(1)},
		}},
	)
	return offer
}

func TestOfferFilesDropsZeroSizeRecords(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 0, 0)

	t.Logf("input:  OP_OFFERFILES with 3 records - good.bin size=4096, zero-tag.bin with FT_FILESIZE=0, no-tag.bin with no FT_FILESIZE")
	dispatchIncomingTCPPacket(t, client, zeroSizeOfferItems())

	names := []string{}
	for _, f := range engine.FindByNameContains("") {
		names = append(names, f.Name)
	}
	t.Logf("output: FilesCount=%d stored=%v offeredFiles=%d closed=%d",
		engine.FilesCount(), names, client.offeredFiles, conn.closed)

	if engine.FilesCount() != 1 {
		t.Fatalf("only the sized record may be stored: FilesCount=%d want 1 (stored %v)",
			engine.FilesCount(), names)
	}
	if len(names) != 1 || names[0] != "good.bin" {
		t.Fatalf("the wrong record survived: %v, want [good.bin]", names)
	}
	// Charged against neither publish limit: a client is not penalised for a record
	// the server refuses.
	if client.offeredFiles != 1 {
		t.Fatalf("a refused record must not burn the publish quota: offeredFiles=%d want 1",
			client.offeredFiles)
	}
	if conn.closed != 0 {
		t.Fatalf("a zero-size record is dropped, not a drop-worthy offence: closed=%d want 0",
			conn.closed)
	}
	if msgs := serverMessages(t, conn); len(msgs) != 0 {
		t.Fatalf("no message is owed for a dropped record, got %v", msgs)
	}
}

// TestOfferFilesZeroSizeDoesNotDisplaceARealRecord is the pair of the storage-side test:
// a zero-size offer for a hash that is already indexed used to overwrite that record
// outright. It is now refused at the door, and would land in its own (hash, 0) bucket
// even if it were not.
func TestOfferFilesZeroSizeDoesNotDisplaceARealRecord(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, _ := newOfferLimitClient(t, engine, 0, 0)

	hash := offerHash(9)
	good := []PacketItem{
		{Type: TypeUint8, Value: OpOfferFiles},
		{Type: TypeUint32, Value: uint32(1)},
	}
	AddFile(&good, SharedFile{
		Name: "real.mkv", Size: 700000000, Hash: hash,
		SourceID: ValCompleteID, SourcePort: ValCompletePort, Completed: 1, Sources: 1,
	})
	bad := []PacketItem{
		{Type: TypeUint8, Value: OpOfferFiles},
		{Type: TypeUint32, Value: uint32(1)},
	}
	AddFile(&bad, SharedFile{
		Name: "displaced.mkv", Size: 0, Hash: hash,
		SourceID: ValCompleteID, SourcePort: ValCompletePort, Completed: 1, Sources: 1,
	})

	t.Logf("input:  hash=%x offered at size=700000000, then the same hash at size=0", hash)
	dispatchIncomingTCPPacket(t, client, good)
	dispatchIncomingTCPPacket(t, client, bad)

	sources := engine.GetSources(hash, 700000000)
	found := engine.FindByNameContains("")
	t.Logf("output: FilesCount=%d GetSources(hash,700000000)=%d records=%d",
		engine.FilesCount(), len(sources), len(found))

	if engine.FilesCount() != 1 {
		t.Fatalf("the zero-size offer must not be indexed: FilesCount=%d want 1", engine.FilesCount())
	}
	if len(found) != 1 || found[0].Name != "real.mkv" || found[0].Size != 700000000 {
		t.Fatalf("the real record was displaced: %+v", found)
	}
	if len(sources) != 1 {
		t.Fatalf("the real record must still resolve sources, got %d want 1", len(sources))
	}
}
