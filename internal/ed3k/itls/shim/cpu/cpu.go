// Package cpu stands in for internal/cpu with golang.org/x/sys/cpu.
package cpu

import xcpu "golang.org/x/sys/cpu"

// The feature sets crypto/tls reads to prefer AES-GCM.
var (
	X86   = &xcpu.X86
	ARM64 = &xcpu.ARM64
	S390X = &xcpu.S390X
)
