package main

import (
	"net"

	"enode/spamfilter"
	"enode/storage"
)

// spamObserver adapts the spam detector to ed2k.SpamObserver, so neither package
// depends on the other.
type spamObserver struct {
	detector *spamfilter.Detector
}

func (o spamObserver) ObserveOffer(session any, userHash []byte, ip net.IP, files []storage.File) any {
	s, _ := session.(*spamfilter.Session)
	if s == nil {
		s = &spamfilter.Session{}
	}
	records := make([]spamfilter.Record, len(files))
	for i, f := range files {
		records[i] = spamfilter.Record{
			Hash: f.Hash, Name: f.Name, Size: f.Size, Type: f.Type,
			LengthSec: f.Runtime, BitrateKbps: f.Bitrate, Codec: f.Codec,
		}
	}
	pub := spamfilter.Publisher{UserHash: userHash}
	if ip != nil {
		pub.Address = ip.String()
	}
	o.detector.Observe(s, pub, records)
	return s
}
