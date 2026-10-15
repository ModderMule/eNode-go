//go:build !unix

package main

import "context"

// Handover needs descriptor passing (SCM_RIGHTS), which this platform lacks: a
// restart drops the connections, as it always has.

func watchHandoff(context.Context, handoffDeps) {}

func takeOver(handoffDeps) error { return nil }
