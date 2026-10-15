//go:build !unix

package handoff

// Handover needs descriptor passing between processes (SCM_RIGHTS), which this
// platform does not have. Everything here is inert: Listen and ListenUDP bind as
// usual, and nothing is ever inherited.

// Init does nothing on this platform.
func Init() error { return nil }

// Inherited is always false on this platform.
func Inherited() bool { return false }

// Supported reports whether this platform can hand over.
func Supported() bool { return false }
