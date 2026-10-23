//go:build !unix

package main

import "context"

// SIGHUP does not exist here: log files are reopened only by a restart.

func watchReopen(context.Context, ...func() error) {}
