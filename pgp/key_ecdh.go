// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp

import (
	"crypto"
	"crypto/ecdh"
	"crypto/sha1" //nolint:gosec
	"encoding/binary"
	"fmt"
	"time"

	iso "github.com/malivvan/pcsc/iso7816"
	"github.com/malivvan/pcsc/iso7816/tlv"
)

type PrivateKeyECDH struct {
	card   *TX
	curve  Curve
	key    KeyRef
	public *ecdh.PublicKey
}

func (k *PrivateKeyECDH) Public() crypto.PublicKey {
	return k.public
}

// ECDH performs a Diffie-Hellman key agreement with the peer
// to produce a shared secret key.
//
// See: OpenPGP Smart Card Application - Section 7.2.11 PSO: DECIPHER
func (k *PrivateKeyECDH) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	if peer.Curve() != k.curve.ECDH() {
		return nil, ErrMismatchingAlgorithms
	}

	data, err := tlv.EncodeBER(
		tlv.New(tagCipher,
			tlv.New(tagPublicKey,
				tlv.New(tagExternalPublicKey, peer.Bytes()),
			),
		),
	)
	if err != nil {
		return nil, err
	}

	return send(k.card.tx, iso.InsPerformSecurityOperation, 0x80, 0x86, data)
}

func (k PrivateKeyECDH) fingerprint(creationTime time.Time) []byte {
	buf := []byte{
		0x99, // Prefix
		0, 0, // Packet length
		0x04,       // Version
		0, 0, 0, 0, // Creation timestamp
		byte(AlgPubkeyECDH),
	}

	buf = append(buf, k.curve.OID()...)
	buf = appendBytesMPI(buf, k.public.Bytes())
	buf = appendKDF(buf, AlgHashSHA512, AlgSymAES256) // same default values as Sequoia

	binary.BigEndian.PutUint16(buf[1:], uint16(len(buf)-3))          // Fill in packet length
	binary.BigEndian.PutUint32(buf[4:], uint32(creationTime.Unix())) // Fill in generation timestamp

	digest := sha1.New() //nolint:gosec
	digest.Write(buf)

	return digest.Sum(nil)
}

func decodePublicECDH(tvs tlv.TagValues, curve Curve) (*ecdh.PublicKey, error) {
	_, tvs, ok := tvs.Get(tagPublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: public key", errMissingTag)
	}

	p, _, ok := tvs.Get(tagPublicKeyEC)
	if !ok {
		return nil, fmt.Errorf("%w: points", errMissingTag)
	}

	curveECDH := curve.ECDH()
	if curveECDH == nil {
		return nil, ErrUnsupportedCurve
	}

	return curveECDH.NewPublicKey(p)
}
