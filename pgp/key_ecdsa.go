// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1" //nolint:gosec
	"encoding/asn1"
	"encoding/binary"
	"io"
	"math/big"
	"time"

	iso "github.com/malivvan/pcsc/iso7816"
	"github.com/malivvan/pcsc/iso7816/tlv"
)

var (
	_ crypto.Signer    = (*PrivateKeyECDSA)(nil)
	_ crypto.Decrypter = (*PrivateKeyECDSA)(nil)
)

type PrivateKeyECDSA struct {
	card   *TX
	curve  Curve
	key    KeyRef
	public *ecdsa.PublicKey
}

func (k *PrivateKeyECDSA) Public() crypto.PublicKey {
	return k.public
}

// See: OpenPGP Smart Card Application - Section 7.2.10 PSO: COMPUTE DIGITAL SIGNATURE
func (k *PrivateKeyECDSA) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if l := len(digest); (opts != nil && l != opts.HashFunc().Size()) || (l != 32 && l != 48 && l != 64) {
		return nil, ErrInvalidLength
	}

	ds, err := send(k.card.tx, iso.InsPerformSecurityOperation, 0x9e, 0x9a, digest)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(struct {
		R, S *big.Int
	}{
		R: new(big.Int).SetBytes(ds[:len(ds)/2]),
		S: new(big.Int).SetBytes(ds[len(ds)/2:]),
	})
}

// See: OpenPGP Smart Card Application - Section 7.2.11 PSO: DECIPHER
func (k *PrivateKeyECDSA) Decrypt(_ io.Reader, _ /*msg*/ []byte, _ /*opts*/ crypto.DecrypterOpts) (plaintext []byte, err error) {
	return nil, ErrUnsupported
}

func (k PrivateKeyECDSA) fingerprint(creationTime time.Time) []byte {
	var alg AlgPubkey
	switch {
	case k.curve == CurveX25519:
		alg = AlgPubkeyEdDSA
	default:
		alg = AlgPubkeyECDSA
	}

	buf := []byte{
		0x99, // Prefix
		0, 0, // Packet length
		0x04,       // Version
		0, 0, 0, 0, // Creation timestamp
		byte(alg),
	}

	pk, err := k.public.ECDH()
	if err != nil {
		return nil
	}

	buf = append(buf, k.curve.OID()...)
	buf = appendBytesMPI(buf, pk.Bytes())
	buf = appendKDF(buf, AlgHashSHA512, AlgSymAES256) // same default values as Sequoia

	binary.BigEndian.PutUint16(buf[1:], uint16(len(buf)-3))          // Fill in packet length
	binary.BigEndian.PutUint32(buf[4:], uint32(creationTime.Unix())) // Fill in generation timestamp

	digest := sha1.New() //nolint:gosec
	digest.Write(buf)

	return digest.Sum(nil)
}

func decodePublicECDSA(tvs tlv.TagValues, curve Curve) (*ecdsa.PublicKey, error) {
	pkECDH, err := decodePublicECDH(tvs, curve)
	if err != nil {
		return nil, err
	}

	return ecdhToECDSAPublicKey(pkECDH)
}

func ecdhToECDSAPublicKey(key *ecdh.PublicKey) (*ecdsa.PublicKey, error) {
	rawKey := key.Bytes()
	switch key.Curve() {
	case ecdh.P256():
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(0).SetBytes(rawKey[1:33]),
			Y:     big.NewInt(0).SetBytes(rawKey[33:]),
		}, nil

	case ecdh.P384():
		return &ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     big.NewInt(0).SetBytes(rawKey[1:49]),
			Y:     big.NewInt(0).SetBytes(rawKey[49:]),
		}, nil

	case ecdh.P521():
		return &ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     big.NewInt(0).SetBytes(rawKey[1:67]),
			Y:     big.NewInt(0).SetBytes(rawKey[67:]),
		}, nil

	default:
		return nil, ErrUnsupportedCurve
	}
}
