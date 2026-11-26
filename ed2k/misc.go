package ed2k

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

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

func Hex(n int64, length int) string {
	s := strconv.FormatInt(n, 16)
	for len(s) < length {
		s = "0" + s
	}
	return s
}

// IPv4ToInt32LE parses a dotted IPv4 address into eD2K's little-endian uint32. Each
// part is a decimal byte; leading zeros are allowed. It runs for every
// OP_SERVERIDENT, so it walks the string instead of splitting it.
func IPv4ToInt32LE(ipv4 string) (uint32, error) {
	var out uint32
	rest := ipv4
	for i := range 4 {
		part, tail, found := strings.Cut(rest, ".")
		if found == (i == 3) {
			return 0, fmt.Errorf("invalid ipv4: %q", ipv4)
		}
		v, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return 0, fmt.Errorf("invalid ipv4: %q", ipv4)
		}
		out |= uint32(v) << (8 * i)
		rest = tail
	}
	return out, nil
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

func IsProtocol(protocol uint8) bool {
	return protocol == PrED2K || protocol == PrEMule || protocol == PrZlib
}

func Box(text string) string {
	l := len(text) + 2
	line := "+" + strings.Repeat("-", l) + "+"
	return line + "\n| " + text + " |\n" + line
}

func UnixTimestamp() int64 {
	return time.Now().Unix()
}
