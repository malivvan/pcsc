// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha1" //nolint:gosec
	"encoding/binary"
	"fmt"
	"io"
	"time"

	iso "github.com/malivvan/pcsc/iso7816"
	"github.com/malivvan/pcsc/iso7816/tlv"
)

var _ crypto.Signer = (*PrivateKeyEdDSA)(nil)

//nolint:unused
type PrivateKeyEdDSA struct {
	card   *TX
	attrs  AlgorithmAttributes
	key    KeyRef
	public ed25519.PublicKey
}

//nolint:unused
func (k PrivateKeyEdDSA) fingerprint(creationTime time.Time) []byte {
	buf := []byte{
		0x99, // Prefix
		0, 0, // Packet length
		0x04,       // Version
		0, 0, 0, 0, // Creation timestamp
		byte(AlgPubkeyEdDSA),
	}

	buf = append(buf, k.attrs.OID...)
	buf = append(buf, k.public...)

	binary.BigEndian.PutUint16(buf[1:], uint16(len(buf)-3))          // Fill in packet length
	binary.BigEndian.PutUint32(buf[4:], uint32(creationTime.Unix())) // Fill in generation timestamp

	digest := sha1.New() //nolint:gosec
	digest.Write(buf)

	return digest.Sum(nil)
}

func (k PrivateKeyEdDSA) Public() crypto.PublicKey {
	return k.public
}

// See: OpenPGP Smart Card Application - Section 7.2.10 PSO: COMPUTE DIGITAL SIGNATURE
func (k PrivateKeyEdDSA) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if l := len(digest); (opts != nil && l != opts.HashFunc().Size()) || (l != 32 && l != 48 && l != 64) {
		return nil, ErrInvalidLength
	}

	return send(k.card.tx, iso.InsPerformSecurityOperation, 0x9e, 0x9a, digest)
}

func decodePublicEdDSA(tvs tlv.TagValues) (ed25519.PublicKey, error) {
	_, tvs, ok := tvs.Get(tagPublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: public key", errMissingTag)
	}

	p, _, ok := tvs.Get(tagPublicKeyEC)
	if !ok {
		return nil, fmt.Errorf("%w: points", errMissingTag)
	}

	return p, nil
}
