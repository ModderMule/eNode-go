package contentfilter

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// HashSize is the length of an eD2K file hash (MD4).
const HashSize = 16

// HashList is a set of eD2K file hashes loaded from a list file. It is immutable once
// built — a reload builds a new one and swaps the pointer — so lookups take no lock.
// A nil *HashList holds nothing.
type HashList struct {
	set map[[HashSize]byte]struct{}
	// Parsed counts the lines that yielded a hash (duplicates included), Skipped the
	// lines that were neither a hash, a comment nor blank.
	Parsed  int
	Skipped int
}

// LoadHashList reads a hash list file. A missing file is an error.
func LoadHashList(path string) (*HashList, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open hash list: %w", err)
	}
	defer f.Close()
	list, err := ParseHashList(f)
	if err != nil {
		return nil, fmt.Errorf("read hash list %s: %w", path, err)
	}
	return list, nil
}

// ParseHashList reads the format the ed2k-server update service publishes: one eD2K
// hash (32 hex characters) per line, a '#' line is a comment, and anything after a ';'
// is an inline comment — by convention the file name that justified the entry.
//
// Lines are handled as bytes, never decoded: those comments carry eD2K file names,
// which are arbitrary bytes in any encoding, and a strict UTF-8 read would fail the
// whole list on the first one. A malformed line is counted and skipped, never fatal,
// for the same reason — one bad line must not disarm the list.
func ParseHashList(r io.Reader) (*HashList, error) {
	list := &HashList{set: make(map[[HashSize]byte]struct{})}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if i := bytes.IndexByte(line, ';'); i >= 0 {
			line = bytes.TrimSpace(line[:i])
			if len(line) == 0 {
				continue
			}
		}
		var hash [HashSize]byte
		if len(line) != hex.EncodedLen(HashSize) {
			list.Skipped++
			continue
		}
		if _, err := hex.Decode(hash[:], line); err != nil {
			list.Skipped++
			continue
		}
		list.set[hash] = struct{}{}
		list.Parsed++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

// Len is the number of distinct hashes.
func (l *HashList) Len() int {
	if l == nil {
		return 0
	}
	return len(l.set)
}

// Contains reports whether hash is listed. Anything but a 16-byte hash is not.
func (l *HashList) Contains(hash []byte) bool {
	if l == nil || len(hash) != HashSize {
		return false
	}
	_, ok := l.set[[HashSize]byte(hash)]
	return ok
}
