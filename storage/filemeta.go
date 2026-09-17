package storage

import (
	"bytes"
	"path/filepath"
	"sort"
	"strings"
)

// Column widths from misc/enode.sql. MySQL counts varchar in characters, so the
// truncation below is by rune.
const (
	maxNameLen   = 255 // sources.name    varchar(255)
	maxExtLen    = 8   // sources.ext     varchar(8)
	maxTitleLen  = 128 // sources.title   varchar(128)
	maxArtistLen = 128 // sources.artist  varchar(128)
	maxAlbumLen  = 128 // sources.album   varchar(128)
	maxCodecLen  = 32  // sources.codec   varchar(32)
)

// enumFileTypes is sources.type: enum('Image','Audio','Video','Pro','Doc',”).
var enumFileTypes = map[string]struct{}{
	"Image": {}, "Audio": {}, "Video": {}, "Pro": {}, "Doc": {}, "": {},
}

// ed2kTypeAliases maps eMule's ED2KFTSTR_* values that are not ENUM members onto
// ones that are (srchybrid/opcodes.h:459-468, src/core/utils/Opcodes.h:516-524).
// Arc and Iso both land in Pro, which is also where GetFileType classifies their
// extensions. EmuleCollection has no reasonable member and is resolved from the
// filename instead.
var ed2kTypeAliases = map[string]string{
	"Arc": "Pro",
	"Iso": "Pro",
}

// NormalizeFile clamps client-supplied metadata to what the schema accepts.
//
// Every string here arrives verbatim from a client tag with no validation. Under
// STRICT_TRANS_TABLES (default since MySQL 5.7) an over-length value or a type
// outside the ENUM aborts the whole sources INSERT, so the file is published but
// never becomes searchable. eMule sends "EmuleCollection" for collection files
// routinely, and any filename whose final dot-suffix exceeds 8 characters
// overflows sources.ext.
//
// Truncating rather than rejecting matches what the non-strict MySQL 5.5 the
// original targeted did — but deliberately, and identically across all engines,
// so MongoDB and MySQL cannot disagree about what they stored for one offer.
func NormalizeFile(file File) File {
	file.Name = truncateRunes(file.Name, maxNameLen)
	file.Title = truncateRunes(file.Title, maxTitleLen)
	file.Artist = truncateRunes(file.Artist, maxArtistLen)
	file.Album = truncateRunes(file.Album, maxAlbumLen)
	file.Codec = truncateRunes(file.Codec, maxCodecLen)
	file.Type = normalizeFileType(file.Type, file.Name)
	return file
}

// NormalizeExt returns an extension that fits sources.ext, or "" when it does
// not. Dropping beats truncating here: a clipped extension would not match an
// "ext = " search term, so it is worse than absent.
func NormalizeExt(name string) string {
	ext := Ext(name)
	if len([]rune(ext)) > maxExtLen {
		return ""
	}
	return ext
}

func Ext(name string) string {
	if name == "" {
		return ""
	}
	ext := filepath.Ext(name)
	if ext == "" {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(ext, "."))
}

func GetFileType(name string) string {
	ext := Ext(name)
	if ext == "" {
		return ""
	}
	video := map[string]struct{}{
		"3gp": {}, "aaf": {}, "asf": {}, "avchd": {}, "avi": {}, "fla": {}, "flv": {},
		"m1v": {}, "m2v": {}, "m4v": {}, "mp4": {}, "mpg": {}, "mpe": {}, "mpeg": {},
		"mov": {}, "mkv": {}, "ogg": {}, "rm": {}, "svi": {},
	}
	audio := map[string]struct{}{
		"aiff": {}, "au": {}, "wav": {}, "flac": {}, "la": {}, "pac": {}, "m4a": {}, "ape": {},
		"rka": {}, "shn": {}, "tta": {}, "wv": {}, "wma": {}, "brstm": {}, "amr": {}, "mp2": {},
		"mp3": {}, "ogg": {}, "aac": {}, "mpc": {}, "ra": {}, "ots": {}, "vox": {}, "voc": {},
		"mid": {}, "mod": {}, "s3m": {}, "xm": {}, "it": {}, "asf": {},
	}
	image := map[string]struct{}{
		"cr2": {}, "pdn": {}, "pgm": {}, "pict": {}, "bmp": {}, "png": {}, "dib": {}, "djvu": {},
		"gif": {}, "psd": {}, "pdd": {}, "icns": {}, "ico": {}, "rle": {}, "tga": {}, "jpeg": {},
		"jpg": {}, "tiff": {}, "tif": {}, "jp2": {}, "jps": {}, "mng": {}, "xbm": {}, "xcf": {},
		"pcx": {},
	}
	pro := map[string]struct{}{
		"7z": {}, "ace": {}, "arc": {}, "arj": {}, "bzip2": {}, "cab": {}, "gzip": {}, "rar": {},
		"tar": {}, "zip": {}, "iso": {}, "nrg": {}, "img": {}, "adf": {}, "dmg": {}, "cue": {},
		"bin": {}, "cif": {}, "ccd": {}, "sub": {}, "raw": {},
	}
	if _, ok := video[ext]; ok {
		return "Video"
	}
	if _, ok := audio[ext]; ok {
		return "Audio"
	}
	if _, ok := image[ext]; ok {
		return "Image"
	}
	if _, ok := pro[ext]; ok {
		return "Pro"
	}
	return ""
}

func normalizeFileType(typ, name string) string {
	if _, ok := enumFileTypes[typ]; ok {
		return typ
	}
	if mapped, ok := ed2kTypeAliases[typ]; ok {
		return mapped
	}
	// Unrecognised (EmuleCollection, Text, Program, or anything a client invents):
	// fall back to classifying the filename, which can only yield ENUM members.
	return GetFileType(name)
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

// offerKey identifies one offered file inside a batch. A struct rather than
// fileMapKey: that packs the hash into a fixed 16-byte buffer, and a batch key
// must never let two different hashes collide, whatever their length.
type offerKey struct {
	hash string
	size uint64
}

// prepareOfferBatch turns one client's offer into what the DB engines write in a
// single multi-row statement.
//
// Each file is normalized exactly as AddFile always did, including the filename
// fallback for an empty type. Duplicates of one (hash, size) are collapsed to the
// last occurrence, which is what a sequence of per-file upserts produced. Leaving
// them in is not safe: MongoDB runs an unordered bulk's upserts concurrently, so
// two upserts of one new key race each other into a duplicate-key error.
//
// The result is sorted by (hash, size). Two clients offering overlapping files
// then take the files/sources index locks in the same order, which is what keeps
// concurrent batches from deadlocking each other the way unordered rows would.
func prepareOfferBatch(files []File) []File {
	index := make(map[offerKey]int, len(files))
	out := make([]File, 0, len(files))
	for _, file := range files {
		file = NormalizeFile(file)
		if file.Type == "" {
			file.Type = GetFileType(file.Name)
		}
		key := offerKey{hash: string(file.Hash), size: file.Size}
		if i, ok := index[key]; ok {
			out[i] = file
			continue
		}
		index[key] = len(out)
		out = append(out, file)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := bytes.Compare(out[i].Hash, out[j].Hash); c != 0 {
			return c < 0
		}
		return out[i].Size < out[j].Size
	})
	return out
}
