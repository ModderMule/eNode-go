package serverlink

import "sync/atomic"

// ServiceStats counts what the service did for other servers.
type ServiceStats struct {
	InfoCalls    atomic.Int64
	Searches     atomic.Int64
	Browses      atomic.Int64
	FilesServed  atomic.Int64
	Resets       atomic.Int64
	RateLimited  atomic.Int64
	AuthFailures atomic.Int64
}
