// Copyright 2026 The eNode-go Authors. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file of this directory.
//
// The design follows the RFC 7250 patch of github.com/tmc/go-iroh
// (internal/itls, MIT license).

package tls

// ed3k: RFC 7250 raw public keys. Added to this fork of crypto/tls; see docs/ed3k-tls-quic-forks.md.

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"time"
)

// certTypeRawPublicKey is the RFC 7250 certificate type RawPublicKey.
const certTypeRawPublicKey uint8 = 2

// RawPublicKeyCertificate returns a Certificate for a raw public key handshake:
// its one entry is the DER SubjectPublicKeyInfo of the key.
func RawPublicKeyCertificate(priv ed25519.PrivateKey) (Certificate, error) {
	spki, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return Certificate{}, err
	}
	return Certificate{Certificate: [][]byte{spki}, PrivateKey: priv}, nil
}

// verifyRawPublicKey takes the peer's Certificate entries under RFC 7250: exactly
// one bare SubjectPublicKeyInfo. It sets c.peerCertificates to a synthetic
// certificate that carries the key, so the CertificateVerify path reads
// PublicKey as it does for X.509, and runs VerifyPeerCertificate and, for the
// client side, VerifyConnection (the server side calls it after this).
func (c *Conn) verifyRawPublicKey(certificates [][]byte, fromClient bool) error {
	if len(certificates) != 1 {
		c.sendAlert(alertBadCertificate)
		return errors.New("tls: raw public key handshake needs exactly one certificate entry")
	}
	pub, err := x509.ParsePKIXPublicKey(certificates[0])
	if err != nil {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: failed to parse raw public key: " + err.Error())
	}
	cert := &x509.Certificate{
		Raw:                     certificates[0],
		RawSubjectPublicKeyInfo: certificates[0],
		PublicKey:               pub,
		PublicKeyAlgorithm:      publicKeyAlgorithmOf(pub),
		// A raw key has no validity period.
		NotBefore: time.Unix(0, 0),
		NotAfter:  time.Unix(1<<62, 0),
	}
	c.peerCertificates = []*x509.Certificate{cert}

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, nil); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}
	if !fromClient && c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}
	return nil
}

func publicKeyAlgorithmOf(pub any) x509.PublicKeyAlgorithm {
	if _, ok := pub.(ed25519.PublicKey); ok {
		return x509.Ed25519
	}
	return x509.UnknownPublicKeyAlgorithm
}
