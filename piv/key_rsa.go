// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"

	iso "github.com/malivvan/pcsc/iso7816"
	"github.com/malivvan/pcsc/iso7816/tlv"
)

type keyRSA struct {
	c    *TX
	slot Slot
	pub  *rsa.PublicKey
	auth KeyAuth
	pp   PINPolicy
}

func (k *keyRSA) Public() crypto.PublicKey {
	return k.pub
}

func (k *keyRSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.auth.do(k.c, k.pp, func(tx iso.TX) ([]byte, error) {
		return signRSA(tx, rand, k.slot, k.pub, digest, opts)
	})
}

func (k *keyRSA) Decrypt(_ io.Reader, msg []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	return k.auth.do(k.c, k.pp, func(tx iso.TX) ([]byte, error) {
		return decryptRSA(tx, k.slot, k.pub, msg)
	})
}

func decodeRSAPublic(tvs tlv.TagValues) (*rsa.PublicKey, error) {
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	mod, _, ok := tvs.Get(0x81)
	if !ok {
		return nil, fmt.Errorf("%w modulus", errUnmarshal)
	}

	exp, _, ok := tvs.Get(0x82)
	if !ok {
		return nil, fmt.Errorf("%w exponent", errUnmarshal)
	}

	var n, e big.Int
	n.SetBytes(mod)
	e.SetBytes(exp)

	if !e.IsInt64() {
		return nil, fmt.Errorf("%w: returned exponent too large: %s", errUnexpectedLength, e.String())
	}

	return &rsa.PublicKey{N: &n, E: int(e.Int64())}, nil
}

func decryptRSA(tx iso.TX, slot Slot, pub *rsa.PublicKey, data []byte) ([]byte, error) {
	alg, err := algRSA(pub)
	if err != nil {
		return nil, err
	}

	resp, err := sendTLV(tx, iso.InsGeneralAuthenticate, byte(alg), slot.Key,
		tlv.New(0x7c,
			tlv.New(0x82),
			tlv.New(0x81, data),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}

	decrypted, _, ok := resp.GetChild(0x7c, 0x82)
	if !ok {
		return nil, fmt.Errorf("%w response signature", errUnmarshal)
	}

	// Decrypted blob contains a bunch of random data. Look for a NULL byte which
	// indicates where the plain text starts.
	for i := 2; i+1 < len(decrypted); i++ {
		if decrypted[i] == 0x00 {
			return decrypted[i+1:], nil
		}
	}

	return nil, errInvalidPKCS1Padding
}

func signRSA(tx iso.TX, rand io.Reader, slot Slot, pub *rsa.PublicKey, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	if hash.Size() != len(digest) {
		return nil, fmt.Errorf("%w: input must be a hashed message", errUnexpectedLength)
	}

	alg, err := algRSA(pub)
	if err != nil {
		return nil, err
	}

	var data []byte
	if o, ok := opts.(*rsa.PSSOptions); ok {
		salt, err := _rsaNewSalt(rand, pub, hash, o)
		if err != nil {
			return nil, err
		}

		em, err := _rsaEMSAPSSEncode(digest, pub, salt, hash.New())
		if err != nil {
			return nil, err
		}

		data = em
	} else {
		prefix, ok := hashPrefixes[hash]
		if !ok {
			return nil, fmt.Errorf("%w: crypto.Hash(%d)", errUnsupportedHashAlgorithm, hash)
		}

		// https://tools.ietf.org/pdf/rfc2313.pdf#page=9
		d := make([]byte, len(prefix)+len(digest))
		copy(d[:len(prefix)], prefix)
		copy(d[len(prefix):], digest)

		paddingLen := pub.Size() - 3 - len(d)
		if paddingLen < 0 {
			return nil, rsa.ErrMessageTooLong
		}

		padding := make([]byte, paddingLen)
		for i := range padding {
			padding[i] = 0xff
		}

		// https://tools.ietf.org/pdf/rfc2313.pdf#page=9
		data = append([]byte{0x00, 0x01}, padding...)
		data = append(data, 0x00)
		data = append(data, d...)
	}

	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=117
	resp, err := sendTLV(tx, iso.InsGeneralAuthenticate, byte(alg), slot.Key,
		tlv.New(0x7c,
			tlv.New(0x82),
			tlv.New(0x81, data),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}

	pkcs1v15Sig, _, ok := resp.GetChild(0x7c, 0x82) // 0x82
	if !ok {
		return nil, fmt.Errorf("%w response signature", errUnmarshal)
	}

	return pkcs1v15Sig, nil
}

func algRSA(pub *rsa.PublicKey) (Algorithm, error) {
	size := pub.N.BitLen()
	switch size {
	case 1024:
		return AlgRSA1024, nil

	case 2048:
		return AlgRSA2048, nil

	default:
		return 0, fmt.Errorf("%w: %d", errUnsupportedKeySize, size)
	}
}

// PKCS#1 v15 is largely informed by the standard library
// https://github.com/golang/go/blob/go1.13.5/src/crypto/rsa/pkcs1v15.go

//nolint:gochecknoglobals
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

var (
	_rsaErrInvalidSaltLen = errors.New("invalid salt length")
	_rsaErrInvalidHashLen = errors.New("invalid hash length")
)

// Per RFC 8017, Section 9.1
//
//     EM = MGF1 xor DB || H( 8*0x00 || mHash || salt ) || 0xbc
//
// where
//
//     DB = PS || 0x01 || salt
//
// and PS can be empty so
//
//     emLen = dbLen + hLen + 1 = psLen + sLen + hLen + 2
//

// EMSAPSSEncode is extracted from SignPSS, and is used to generate a EM value
// for a PSS signature operation.
func _rsaEMSAPSSEncode(mHash []byte, pub *rsa.PublicKey, salt []byte, hash hash.Hash) ([]byte, error) {
	emBits := pub.N.BitLen() - 1

	// See RFC 8017, Section 9.1.1.

	hLen := hash.Size()
	sLen := len(salt)
	emLen := (emBits + 7) / 8

	// 1.  If the length of M is greater than the input limitation for the
	//     hash function (2^61 - 1 octets for SHA-1), output "message too
	//     long" and stop.
	//
	// 2.  Let mHash = Hash(M), an octet string of length hLen.

	if len(mHash) != hLen {
		return nil, _rsaErrInvalidHashLen
	}

	// 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.

	if emLen < hLen+sLen+2 {
		return nil, rsa.ErrMessageTooLong
	}

	em := make([]byte, emLen)
	psLen := emLen - sLen - hLen - 2
	db := em[:psLen+1+sLen]
	h := em[psLen+1+sLen : emLen-1]

	// 4.  Generate a random octet string salt of length sLen; if sLen = 0,
	//     then salt is the empty string.
	//
	// 5.  Let
	//       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
	//
	//     M' is an octet string of length 8 + hLen + sLen with eight
	//     initial zero octets.
	//
	// 6.  Let H = Hash(M'), an octet string of length hLen.

	var prefix [8]byte

	hash.Write(prefix[:])
	hash.Write(mHash)
	hash.Write(salt)

	h = hash.Sum(h[:0])
	hash.Reset()

	// 7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
	//     zero octets. The length of PS may be 0.
	//
	// 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
	//     emLen - hLen - 1.

	db[psLen] = 0x01
	copy(db[psLen+1:], salt)

	// 9.  Let dbMask = MGF(H, emLen - hLen - 1).
	//
	// 10. Let maskedDB = DB \xor dbMask.

	mgf1XOR(db, hash, h)

	// 11. Set the leftmost 8 * emLen - emBits bits of the leftmost octet in
	//     maskedDB to zero.

	db[0] &= 0xff >> (8*emLen - emBits)

	// 12. Let EM = maskedDB || H || 0xbc.
	em[emLen-1] = 0xbc

	// 13. Output EM.
	return em, nil
}

// mgf1XOR XORs the bytes in out with a mask generated using the MGF1 function
// specified in PKCS #1 v2.1.
func mgf1XOR(out []byte, hash hash.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(out) {
		hash.Write(seed)
		hash.Write(counter[0:4])
		digest = hash.Sum(digest[:0])
		hash.Reset()

		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		_rsaIncCounter(&counter)
	}
}

// incCounter increments a four byte, big-endian counter.
func _rsaIncCounter(c *[4]byte) {
	if c[3]++; c[3] != 0 {
		return
	}
	if c[2]++; c[2] != 0 {
		return
	}
	if c[1]++; c[1] != 0 {
		return
	}
	c[0]++
}

// NewSalt is extracted from SignPSS and is used to generate a salt value for a
// PSS signature.
func _rsaNewSalt(rand io.Reader, pub *rsa.PublicKey, hash crypto.Hash, opts *rsa.PSSOptions) ([]byte, error) {
	saltLength := opts.SaltLength

	switch saltLength {
	case rsa.PSSSaltLengthAuto:
		saltLength = (pub.N.BitLen()-1+7)/8 - 2 - hash.Size()
		if saltLength < 0 {
			return nil, rsa.ErrMessageTooLong
		}

	case rsa.PSSSaltLengthEqualsHash:
		saltLength = hash.Size()

	default:
		// If we get here saltLength is either > 0 or < -1, in the
		// latter case we fail out.
		if saltLength <= 0 {
			return nil, _rsaErrInvalidSaltLen
		}
	}

	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand, salt); err != nil {
		return nil, err
	}

	return salt, nil
}
