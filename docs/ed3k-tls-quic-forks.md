# The vendored TLS and QUIC of the ed3k node

ed3k authenticates both sides of a QUIC connection with **RFC 7250 raw public keys**
(Ed25519, no X.509), as specified in §4.1 of the spec. Go's `crypto/tls` does not
negotiate `client_certificate_type` / `server_certificate_type`. It cannot carry a bare
SubjectPublicKeyInfo in the Certificate message. quic-go drives `crypto/tls` directly,
with no seam to plug in another TLS. eNode-go therefore carries two forks, both used
only by the ed3k node:

| Fork | Upstream | Where |
|---|---|---|
| `internal/ed3k/itls/tls` | `crypto/tls` of the Go toolchain (go1.27.0) | patched for RFC 7250 |
| `internal/ed3k/iquic` | `github.com/quic-go/quic-go` v0.64.1 | imports rewritten to `itls` |

The approach follows `github.com/tmc/go-iroh` (`internal/itls`, `internal/qng`, MIT),
which was read as a reference and not imported. The eD2K server does not use either
fork.

## itls

`internal/ed3k/itls/sync.sh` recreates the fork from the installed toolchain:
1. It copies `$GOROOT/src/crypto/tls/*.go`, leaving out tests, `defaults_boring.go` and
   `generate_cert.go`.
2. It points the standard-library-internal imports at small shims in
   `internal/ed3k/itls/shim/`:

| Import | Shim |
|---|---|
| `crypto/internal/boring` | `boring`: never enabled |
| `crypto/internal/fips140/aes/gcm` | `gcm`: plain `cipher.NewGCM`; the upstream TLS constructors only add FIPS-gated nonce checks |
| `crypto/internal/fips140/tls12`, `tls13` | `tls12`, `tls13`: the key schedules, `tls13` copied verbatim, `tls12` on `crypto/hmac` |
| `crypto/tls/internal/fips140tls` | `fips140tls`: FIPS never required |
| `internal/byteorder`, `internal/cpu`, `internal/godebug` | `byteorder`, `cpu` (golang.org/x/sys/cpu), `godebug` (every setting at its default) |

3. It drops the `//go:linkname` push directives.
4. It applies `internal/ed3k/itls/rpk.patch`, the RFC 7250 change.

The patch:
- `Config.RawPublicKeys` (TLS 1.3 only, mutual), and `RawPublicKeyCertificate(priv)`,
  whose one entry is the DER SPKI.
- ClientHello carries `client_certificate_type` (19) and `server_certificate_type` (20)
  with the value RawPublicKey (2). EncryptedExtensions confirms both. A peer that does
  not offer them fails with `unsupported_certificate`, and so does a server that does not
  confirm them.
- A Certificate message under raw keys is exactly one SPKI. It is parsed into a synthetic
  `*x509.Certificate` that carries only the key, so `CertificateVerify` works unchanged,
  and the application checks the key in `VerifyConnection`.
- A raw-key server always requests the client's key and fails a client without one with
  `certificate_required`.
- Unlike go-iroh, the patch puts no certificate-type extension into CertificateRequest.
  RFC 8446 does not allow it there, and rustls (packmule) works without it.

Session tickets and 0-RTT are not used by the node (`SessionTicketsDisabled`), so the
ticket path is not patched for raw keys.

## iquic

`internal/ed3k/iquic/sync.sh` copies the packages the `quic` package builds from out of
the module cache: `internal/ackhandler`, `congestion`, `handshake`, `monotime`,
`protocol`, `qerr`, `utils/...` and `wire`, plus `qlog`, `qlogwriter` and `quicvarint`.
It leaves out tests, mocks and http3. Then it:
- rewrites `crypto/tls` to `itls`;
- rewrites `github.com/quic-go/quic-go` to `enode/internal/ed3k/iquic`;
- applies `internal/ed3k/iquic/ed3k.patch`.

That patch replaces the `go:linkname` into `crypto/tls.aeadAESGCMTLS13`, which quic-go
uses only in FIPS 140 mode, with a function that refuses FIPS mode. The fork has no FIPS
mode.

### Hooks

The patch also adds four small hooks that the index node and its dialling tools need and
quic-go does not expose. Each is marked `ed3k` in the code:

| Hook | Where | Used for |
|---|---|---|
| `ConnectionState.IdleTimeout` | set in `applyTransportParameters` under `connStateMutex` | the relay's `ttl`, at most the negotiated idle timeout (§9.4) |
| `Config.OnPathSwitch func(c *Conn, addr net.Addr)` | called just before the server's `ChangeRemoteAddr`, after QUIC validated the new path | the obfuscation layer's amplification limit follows a migrated client (§4.4) |
| `SendStream.Acked()` / `Stream.Acked()` | a channel closed where the send stream becomes completed (FIN and all data acknowledged, or reset) | closing after a malformed `Hello` once its `Error` is acknowledged (§5.5) |
| `Conn.HandshakeConfirmed()` | a channel closed in `handleHandshakeConfirmed` (on the client: `HANDSHAKE_DONE` arrived) | a dialler closes with `WRONG_PEER` only then, so the close travels in 1-RTT packets with its code (§4.1, RFC 9000 §10.2.3) |

## Updating

After a Go or quic-go upgrade, from the repository root:

```bash
./internal/ed3k/itls/sync.sh                         # crypto/tls of the installed Go
QUIC_VERSION=v0.64.1 ./internal/ed3k/iquic/sync.sh   # quic-go from the module cache
go test ./internal/ed3k/... ./ed3k/...
ENODE_ED3K_PACKMULE=…/packmule-node go test ./ed3k/... -run Packmule
```

Each script records what it synced from in `UPSTREAM` beside the fork. When a patch no
longer applies:
1. Resolve it by hand in the fork.
2. Regenerate the patch from a pristine sync of the fork, e.g. `diff -ruN a b > rpk.patch`,
   where `a` is the pristine copy and `b` the patched one, each holding the fork's
   directory.

The handshake tests, against Go and against packmule's rustls, are the gate.

## When to drop the forks

The RPK fork can go when the standard `crypto/tls` negotiates RFC 7250 certificate types
and parses an SPKI Certificate entry. quic-go would then work unforked, and
`internal/ed3k/iquic` can go with it. `VerifyConnection` alone is not enough: without
the negotiation, a peer that sends a bare key fails before that callback runs.
