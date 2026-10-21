package transport

import "google.golang.org/protobuf/proto"

func protoUnmarshal(b []byte, m proto.Message) error { return proto.Unmarshal(b, m) }
