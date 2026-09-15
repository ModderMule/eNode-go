package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"enode/ed2k"
	"enode/logging"
	"enode/storage"

	"gopkg.in/yaml.v3"
)

// debugFixtures is the top-level shape of a debug fixtures file (see
// tests/data/debug_fixtures.yaml). It describes dummy peers and the files each
// offers, so the storage engine can be pre-populated for debugging the search and
// source-list paths without live clients.
type debugFixtures struct {
	Peers []debugPeer `yaml:"peers"`
}

type debugPeer struct {
	IPv4          string          `yaml:"ipv4"`
	ID            uint32          `yaml:"id"`
	LowID         bool            `yaml:"lowID"`
	Port          uint16          `yaml:"port"`
	UserHash      string          `yaml:"userHash"`
	CryptOptions  uint            `yaml:"cryptOptions"`
	IPv6          string          `yaml:"ipv6"`
	IPv6Reachable bool            `yaml:"ipv6Reachable"`
	Files         []debugFileSpec `yaml:"files"`
}

type debugFileSpec struct {
	Hash      string `yaml:"hash"`
	Name      string `yaml:"name"`
	Size      uint64 `yaml:"size"`
	Type      string `yaml:"type"`
	Completed bool   `yaml:"completed"`
}

// seedDebugFixtures loads the fixtures file at path and injects its peers and files
// into store, using the same Engine.Connect / Engine.AddFile calls a real login and
// file offer take — so it exercises the chosen engine's path as well as populating
// data to debug against.
//
// A missing or unparseable file is a hard error (the operator explicitly enabled
// seeding). An individual malformed peer or file is skipped with a warning, so one
// typo cannot empty the whole fixture set — the same tolerance seedServers applies
// to a bad server-list entry.
func seedDebugFixtures(store storage.Engine, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read fixtures %q: %w", path, err)
	}
	var fx debugFixtures
	if err := yaml.Unmarshal(b, &fx); err != nil {
		return fmt.Errorf("parse fixtures %q: %w", path, err)
	}

	// Each AddFile is one file offered by one peer — a source. filesSeeded is that
	// count; the distinct-file total is not tracked because the engine dedupes on
	// (hash, size) and reporting the offer count is what matches "sources the server
	// will send".
	var peersSeeded, offersSeeded int
	for i, p := range fx.Peers {
		info, ok := clientInfoFromPeer(i, p)
		if !ok {
			continue
		}
		storeID, err := store.Connect(info)
		if err != nil {
			logging.Warnf("debug fixtures: peer %d (id=%d) connect failed: %v", i, info.ID, err)
			continue
		}
		info.StoreID = storeID
		peersSeeded++

		for j, f := range p.Files {
			file, ok := fileFromSpec(i, j, f)
			if !ok {
				continue
			}
			store.AddFile(file, info)
			offersSeeded++
		}
	}

	logging.Infof("debug fixtures: injected %d peer(s) and %d file offer(s) from %q",
		peersSeeded, offersSeeded, path)
	return nil
}

// clientInfoFromPeer builds a storage.ClientInfo from a fixture peer. For a HighID
// peer the ed2k ID is derived from its IPv4 (as eMule does); a LowID peer supplies
// its ID explicitly. Returns false (with a warning) for a peer that cannot be turned
// into a usable, addressable source.
func clientInfoFromPeer(idx int, p debugPeer) (storage.ClientInfo, bool) {
	hash, err := decodeHash(p.UserHash)
	if err != nil {
		logging.Warnf("debug fixtures: skipping peer %d: userHash %q: %v", idx, p.UserHash, err)
		return storage.ClientInfo{}, false
	}

	var id, ipv4 uint32
	if p.IPv4 != "" {
		v, err := ed2k.IPv4ToInt32LE(p.IPv4)
		if err != nil {
			logging.Warnf("debug fixtures: skipping peer %d: ipv4 %q: %v", idx, p.IPv4, err)
			return storage.ClientInfo{}, false
		}
		ipv4 = v
		if !p.LowID {
			// A HighID *is* the packed IPv4, so an address ending in .0 packs into
			// the LowID range and would seed a source every client reads as a LowID
			// but that the server never registered in its LowID pool — nobody could
			// reach it. The login path forces such a client to LowID; a fixture has
			// to say so explicitly, since it supplies its own id.
			if !ed2k.HasHighID(v) {
				logging.Warnf("debug fixtures: skipping peer %d: ipv4 %q packs to 0x%08x, which clients read as a LowID (set lowID: true and an explicit id)", idx, p.IPv4, v)
				return storage.ClientInfo{}, false
			}
			id = v
		}
	}
	if p.ID != 0 {
		id = p.ID
	}
	if id == 0 {
		logging.Warnf("debug fixtures: skipping peer %d: no id (set ipv4 for a HighID peer or id for a LowID peer)", idx)
		return storage.ClientInfo{}, false
	}

	var ipv6 []byte
	if p.IPv6 != "" {
		v6, ok := ed2k.ParsePublicIPv6(p.IPv6)
		if !ok {
			logging.Warnf("debug fixtures: peer %d: ipv6 %q is not a usable public IPv6, ignoring", idx, p.IPv6)
		} else {
			ipv6 = append([]byte(nil), v6[:]...)
		}
	}

	return storage.ClientInfo{
		ID:            id,
		IPv4:          ipv4,
		Port:          p.Port,
		Hash:          hash,
		LowID:         p.LowID,
		CryptOptions:  byte(p.CryptOptions),
		IPv6:          ipv6,
		IPv6Reachable: p.IPv6Reachable && ipv6 != nil,
	}, true
}

// fileFromSpec builds a storage.File from a fixture file spec. AddFile normalizes the
// metadata, so only the hash needs validating here. Returns false (with a warning)
// for an unusable hash.
func fileFromSpec(peerIdx, fileIdx int, f debugFileSpec) (storage.File, bool) {
	hash, err := decodeHash(f.Hash)
	if err != nil {
		logging.Warnf("debug fixtures: skipping peer %d file %d: hash %q: %v", peerIdx, fileIdx, f.Hash, err)
		return storage.File{}, false
	}
	var completed uint32
	if f.Completed {
		completed = 1
	}
	return storage.File{
		Hash:      hash,
		Name:      f.Name,
		Size:      f.Size,
		Type:      f.Type,
		Completed: completed,
	}, true
}

// decodeHash parses a 32-hex-character ed2k hash into its 16 raw bytes.
func decodeHash(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("want 16 bytes, got %d", len(b))
	}
	return b, nil
}
