// Package byteorder stands in for internal/byteorder.
package byteorder

import "encoding/binary"

// LEUint32 reads a little-endian uint32.
func LEUint32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

// BEUint16 reads a big-endian uint16.
func BEUint16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }

// BEUint32 reads a big-endian uint32.
func BEUint32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }

// BEUint64 reads a big-endian uint64.
func BEUint64(b []byte) uint64 { return binary.BigEndian.Uint64(b) }

// BEAppendUint16 appends a big-endian uint16.
func BEAppendUint16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }

// BEAppendUint32 appends a big-endian uint32.
func BEAppendUint32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }

// BEAppendUint64 appends a big-endian uint64.
func BEAppendUint64(b []byte, v uint64) []byte { return binary.BigEndian.AppendUint64(b, v) }

// BEPutUint64 writes a big-endian uint64.
func BEPutUint64(b []byte, v uint64) { binary.BigEndian.PutUint64(b, v) }
