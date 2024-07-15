// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/malivvan/pcsc/iso7816/tlv"
)

var (
	_ crypto.Signer    = (*PrivateKeyRSA)(nil)
	_ crypto.Decrypter = (*PrivateKeyRSA)(nil)
)

//nolint:unused
type rsaPublicKey struct {
	*rsa.PublicKey

	private *PrivateKeyRSA
}

type PrivateKeyRSA struct {
	card       *TX
	lenModulus int
	key        KeyRef
	public     *rsa.PublicKey
}

func (k *PrivateKeyRSA) Public() crypto.PublicKey {
	return k.public
}

func (k *PrivateKeyRSA) Bits() int {
	return k.lenModulus
}

// See: OpenPGP Smart Card Application - Section 7.2.10 PSO: COMPUTE DIGITAL SIGNATURE
func (k *PrivateKeyRSA) Sign(_ io.Reader, _ /*digest*/ []byte, _ /*opts*/ crypto.SignerOpts) (signature []byte, err error) {
	return nil, ErrUnsupported
}

// See: OpenPGP Smart Card Application - Section 7.2.11 PSO: DECIPHER
func (k *PrivateKeyRSA) Decrypt(_ io.Reader, _ /*msg*/ []byte, _ /*opts*/ crypto.DecrypterOpts) (plaintext []byte, err error) {
	return nil, ErrUnsupported
}

func (k PrivateKeyRSA) fingerprint(creationTime time.Time) []byte {
	buf := []byte{
		0x99, // Prefix
		0, 0, // Packet length
		0x04,       // Version
		0, 0, 0, 0, // Creation timestamp
		byte(AlgPubkeyRSA),
	}

	buf = appendMPI(buf, k.public.N)
	buf = appendMPI(buf, big.NewInt(int64(k.public.E)))

	binary.BigEndian.PutUint16(buf[1:], uint16(len(buf)-3))          // Fill in packet length
	binary.BigEndian.PutUint32(buf[4:], uint32(creationTime.Unix())) // Fill in creation timestamp

	digest := sha1.New() // nolint:gosec
	digest.Write(buf)

	return digest.Sum(nil)
}

func decodePublicRSA(tvs tlv.TagValues) (*rsa.PublicKey, error) {
	_, tvs, ok := tvs.Get(tagPublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: public key", errMissingTag)
	}

	mod, _, ok := tvs.Get(tagModulus)
	if !ok {
		return nil, fmt.Errorf("%w modulus", errUnmarshal)
	}

	exp, _, ok := tvs.Get(tagExponent)
	if !ok {
		return nil, fmt.Errorf("%w exponent", errUnmarshal)
	}

	var n, e big.Int
	n.SetBytes(mod)
	e.SetBytes(exp)

	if !e.IsInt64() {
		return nil, fmt.Errorf("%w: returned exponent too large: %s", ErrInvalidLength, e.String())
	}

	return &rsa.PublicKey{N: &n, E: int(e.Int64())}, nil
}
