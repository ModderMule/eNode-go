package ed2k

import (
	"crypto/md5"
	crand "crypto/rand"
	"math/rand"
)

const (
	EmObfuscate = 0
	EmPreferred = EmObfuscate
	EmSupported = EmObfuscate

	CryptPrimeSize = 96
	CryptDhaSize   = 16
)

var CryptPrime = []byte{
	0xF2, 0xBF, 0x52, 0xC5, 0x5F, 0x58, 0x7A, 0xDD, 0x53, 0x71, 0xA9, 0x36,
	0xE8, 0x86, 0xEB, 0x3C, 0x62, 0x17, 0xA3, 0x3E, 0xC3, 0x4C, 0xB4, 0x0D,
	0xC7, 0x3A, 0x41, 0xA6, 0x43, 0xAF, 0xFC, 0xE7, 0x21, 0xFC, 0x28, 0x63,
	0x66, 0x53, 0x5B, 0xDB, 0xCE, 0x25, 0x9F, 0x22, 0x86, 0xDA, 0x4A, 0x91,
	0xB2, 0x07, 0xCB, 0xAA, 0x52, 0x55, 0xD4, 0xF6, 0x1C, 0xCE, 0xAE, 0xD4,
	0x5A, 0xD5, 0xE0, 0x74, 0x7D, 0xF7, 0x78, 0x18, 0x28, 0x10, 0x5F, 0x34,
	0x0F, 0x76, 0x23, 0x87, 0xF8, 0x8B, 0x28, 0x91, 0x42, 0xFB, 0x42, 0x68,
	0x8F, 0x05, 0x15, 0x0F, 0x54, 0x8B, 0x5F, 0x43, 0x6A, 0xF7, 0x0D, 0xF3,
}

type RC4Key struct {
	State [256]byte
	X     byte
	Y     byte
}

func RC4CreateKey(keyphrase []byte, drop bool) *RC4Key {
	k := &RC4Key{}
	for i := 0; i < 256; i++ {
		k.State[i] = byte(i)
	}
	// An empty keyphrase would index keyphrase[0] and divide by len(keyphrase)==0
	// in the loop below and panic (JS produced NaN instead). Unreachable today, but
	// a hostile or buggy caller must get an identity-permuted key, not a crash.
	if len(keyphrase) == 0 {
		return k
	}
	index1 := 0
	index2 := 0
	for i := 0; i < 256; i++ {
		index2 = (int(keyphrase[index1]) + int(k.State[i]) + index2) % 256
		k.State[i], k.State[index2] = k.State[index2], k.State[i]
		index1 = (index1 + 1) % len(keyphrase)
	}
	if drop {
		_ = RC4Crypt(nil, 1024, k)
	}
	return k
}

func RC4Crypt(buffer []byte, length int, key *RC4Key) []byte {
	if key == nil {
		return nil
	}
	var out []byte
	if buffer != nil {
		out = make([]byte, length)
	}
	for i := 0; i < length; i++ {
		key.X = byte((int(key.X) + 1) % 256)
		key.Y = byte((int(key.State[key.X]) + int(key.Y)) % 256)
		key.State[key.X], key.State[key.Y] = key.State[key.Y], key.State[key.X]
		xorIndex := byte((int(key.State[key.X]) + int(key.State[key.Y])) % 256)
		if buffer != nil {
			out[i] = buffer[i] ^ key.State[xorIndex]
		}
	}
	return out
}

func MD5(buffer []byte) []byte {
	sum := md5.Sum(buffer)
	return sum[:]
}

func Rand(n int) int {
	if n <= 0 {
		return 0
	}
	return rand.Intn(n + 1)
}

// RandUint32 returns a random value across the full uint32 range. Used instead of
// uint32(Rand(0xffffffff)): the constant 0xffffffff does not fit a 32-bit int, so
// that expression fails to compile on GOARCH=386, and Rand's internal n+1 would
// overflow there anyway. rand.Uint32 sidesteps both.
func RandUint32() uint32 {
	return rand.Uint32()
}

func RandBuf(length int) ([]byte, error) {
	out := make([]byte, length)
	_, err := crand.Read(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// randClientSocketMarker is RandProtocol without the Kad markers 0xe4/0xe5 either.
// The marker byte is not part of the key, so any value outside the set decrypts.
func randClientSocketMarker() uint8 {
	for {
		p := uint8(Rand(0xff))
		if !IsProtocol(p) && p != PrKad && p != PrKadZlib {
			return p
		}
	}
}

func RandProtocol() uint8 {
	p := uint8(0xff)
	for i := 0; i < 5; i++ {
		p = uint8(Rand(0xff))
		if !IsProtocol(p) {
			break
		}
	}
	return p
}
