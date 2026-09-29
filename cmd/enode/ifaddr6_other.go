//go:build !linux && !windows && !darwin

package main

// localIPv6Candidates has no flag source on this platform, so every address comes
// back with FlagsKnown=false and selection behaves as it did before flags existed.
func localIPv6Candidates() []ipv6Candidate {
	return fallbackIPv6Candidates()
}
