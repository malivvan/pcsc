// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"github.com/malivvan/pcsc/iso7816/tlv"
)

var ErrPubkeyRequired = fmt.Errorf("missing public key: not present on card")

type privateKey interface {
	fingerprint(creationTime time.Time) []byte
}

func cpktTag(tag tlv.Tag, sz int) []byte {
	b, _ := tag.MarshalBER()
	bl, _ := tlv.EncodeLengthBER(sz)
	return append(b, bl...)
}

func (tx *TX) ImportKey(key KeyRef, skImport crypto.PrivateKey) (crypto.PrivateKey, error) {
	if tx.Capabilities.Flags&CapKeyImport == 0 {
		return nil, ErrUnsupported
	}

	attrs, err := tx.algorithmAttributesFromPrivateKey(skImport)
	if err != nil {
		return nil, fmt.Errorf("failed to detect private key attributes: %w", err)
	}

	if attrs, err = tx.changeAlgorithmAttributes(key, attrs); err != nil {
		return nil, fmt.Errorf("failed to change algorithm attributes: %w", err)
	}

	cpkt := tlv.New(tagPrivateKeyTemplate)
	cpk := tlv.New(tagPrivateKey)

	// Some helpers
	appendBytes := func(t tlv.Tag, b []byte) {
		cpkt.Append(cpktTag(t, len(b)))
		cpk.Append(b)
	}

	appendBigInt := func(t tlv.Tag, l int, i *big.Int) {
		b := make([]byte, l)
		i.FillBytes(b)

		cpkt.Append(cpktTag(t, l))
		cpk.Append(b)
	}

	appendInt := func(t tlv.Tag, l int, i int) {
		appendBigInt(t, l, big.NewInt(int64(i)))
	}

	var sk privateKey
	switch skImport := skImport.(type) {
	case *rsa.PrivateKey:
		if attrs.ImportFormat == ImportFormatRSAStd || attrs.ImportFormat == ImportFormatRSACRT {
			appendInt(0x91, (attrs.LengthExponent+7)/8, skImport.PublicKey.E) // Public exponent: e
			appendBigInt(0x92, attrs.LengthModulus/(2*8), skImport.Primes[0]) // Prime1: p
			appendBigInt(0x93, attrs.LengthModulus/(2*8), skImport.Primes[1]) // Prime2: q
		}

		if attrs.ImportFormat == ImportFormatRSACRT {
			appendBigInt(0x94, attrs.LengthModulus/(2*8), skImport.Precomputed.Qinv) // PQ: 1/q mod p
			appendBigInt(0x95, attrs.LengthModulus/(2*8), skImport.Precomputed.Dp)   // DP1: d mod (p - 1)
			appendBigInt(0x96, attrs.LengthModulus/(2*8), skImport.Precomputed.Dq)   // // DQ1: d mod (q - 1)
		}

		if attrs.ImportFormat == ImportFormatRSAStdWithModulus || attrs.ImportFormat == ImportFormatRSACRTWithModulus {
			appendBigInt(0x97, attrs.LengthModulus, skImport.N) // Modulus: n
		}

		sk = &PrivateKeyRSA{
			card:       tx,
			lenModulus: skImport.Size() * 8,
			key:        key,
			public:     &skImport.PublicKey,
		}

	case *ecdsa.PrivateKey:
		skECDH, err := skImport.ECDH()
		if err != nil {
			return nil, fmt.Errorf("failed to convert private key: %w", err)
		}

		appendBytes(0x92, skECDH.Bytes())

		if attrs.ImportFormat == ImportFormatECDSAStdWithPublicKey {
			pkECDH, err := skImport.PublicKey.ECDH()
			if err != nil {
				return nil, fmt.Errorf("failed to get public key: %w", err)
			}

			appendBytes(0x99, pkECDH.Bytes())
		}

		sk = &PrivateKeyECDSA{
			card:   tx,
			curve:  attrs.Curve(),
			key:    key,
			public: &skImport.PublicKey,
		}

	case *ecdh.PrivateKey:
		appendBytes(0x92, skImport.Bytes())

		if attrs.ImportFormat == ImportFormatECDSAStdWithPublicKey {
			appendBytes(0x99, skImport.PublicKey().Bytes())
		}

		sk = &PrivateKeyECDH{
			card:   tx,
			curve:  attrs.Curve(),
			key:    key,
			public: skImport.PublicKey(),
		}

	case ed25519.PrivateKey:
		appendBytes(0x92, []byte(skImport[:32]))

		pk, ok := skImport.Public().(ed25519.PublicKey)
		if !ok {
			panic("broken key")
		}

		if attrs.ImportFormat == ImportFormatECDSAStdWithPublicKey {
			appendBytes(0x99, []byte(pk))
		}

		sk = &PrivateKeyEdDSA{
			card:   tx,
			key:    key,
			public: pk,
		}

	default:
		return nil, ErrUnsupportedKeyType
	}

	if err := tx.putDataTLV(tlv.New(tagExtendedHeaderList, key.crt(), cpkt, cpk)); err != nil {
		return nil, fmt.Errorf("failed to import key: %w", err)
	}

	if err := tx.updateKeyMetadata(key, sk); err != nil {
		return nil, fmt.Errorf("failed to update key metadata: %w", err)
	}

	return sk, nil
}

func (tx *TX) GenerateKey(key KeyRef, attrs AlgorithmAttributes) (crypto.PrivateKey, error) {
	if _, err := tx.changeAlgorithmAttributes(key, attrs); err != nil {
		return nil, fmt.Errorf("failed to change algorithm attributes: %w", err)
	}

	sk, err := tx.generateAsymmetricKeyPair(key, true)
	if err != nil {
		return nil, err
	}

	if err := tx.updateKeyMetadata(key, sk); err != nil {
		return nil, fmt.Errorf("failed to update key metadata: %w", err)
	}

	return sk, nil
}

func (tx *TX) updateKeyMetadata(key KeyRef, sk privateKey) error {
	generationTime := tx.Clock()

	ts := make([]byte, 4)
	binary.BigEndian.PutUint32(ts, uint32(generationTime.Unix()))

	if err := tx.putData(key.tagGenTime(), ts); err != nil {
		return fmt.Errorf("failed to store key generation time: %w", err)
	}

	if err := tx.putData(key.tagFpr(), sk.fingerprint(generationTime)); err != nil {
		return fmt.Errorf("failed to store key fingerprint: %w", err)
	}

	if _, err := tx.GetApplicationRelatedData(); err != nil {
		return fmt.Errorf("failed to get updated metadata: %w", err)
	}

	return nil
}

func (tx *TX) PrivateKey(key KeyRef, pkHint crypto.PublicKey) (crypto.PrivateKey, error) {
	attrs := tx.Keys[key].AlgAttrs

	if sk, err := tx.generateAsymmetricKeyPair(key, false); err == nil {
		return sk, nil
	} else if pkHint == nil {
		// We failed to retrieve a public key from the card.
		// Lets try to use the hint and fail if none has been provided.
		return nil, ErrPubkeyRequired
	}

	switch attrs.Algorithm {
	case AlgPubkeyRSA:
		pk, ok := pkHint.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: %T. Must be an *rsa.PublicKey", ErrUnsupportedKeyType, pkHint)
		}

		return &PrivateKeyRSA{
			card:       tx,
			lenModulus: attrs.LengthModulus,
			key:        key,
			public:     pk,
		}, nil

	case AlgPubkeyECDH:
		pk, ok := pkHint.(*ecdh.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: %T. Must be an *ecdh.PublicKey", ErrUnsupportedKeyType, pkHint)
		}

		curve := curveFromECDH(pk.Curve())
		if curve == CurveUnknown {
			return nil, ErrUnsupportedCurve
		}

		return &PrivateKeyECDH{
			card:   tx,
			curve:  curve,
			key:    key,
			public: pk,
		}, nil

	case AlgPubkeyECDSA:
		pk, ok := pkHint.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: %T. Must be an *ecdsa.PublicKey", ErrUnsupportedKeyType, pkHint)
		}

		curve := curveFromECDSA(pk.Curve)
		if curve == CurveUnknown {
			return nil, ErrUnsupportedCurve
		}

		return &PrivateKeyECDSA{
			card:   tx,
			curve:  curve,
			public: pk,
			key:    key,
		}, nil

	case AlgPubkeyEdDSA:
		pk, ok := pkHint.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: %T. Must be edd25519.PublicKey", ErrUnsupportedKeyType, pkHint)
		}

		return &PrivateKeyEdDSA{
			card:   tx,
			public: pk,
			key:    key,
		}, nil

	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKeyType, pkHint)
	}
}

// AlgorithmAttributes returns the currently configured
// algorithm attributes for the given key.
func (tx *TX) AlgorithmAttributes(key KeyRef) (attrs AlgorithmAttributes, err error) {
	if tx.ApplicationRelated, err = tx.GetApplicationRelatedData(); err != nil {
		return attrs, err
	}

	return tx.Keys[key].AlgAttrs, nil
}

// SupportedAlgorithms returns the list of supported algorithms
// by each key type.
func (tx *TX) SupportedAlgorithms() (map[KeyRef][]AlgorithmAttributes, error) {
	algs := map[KeyRef][]AlgorithmAttributes{}

	algInfo, err := tx.getData(tagAlgInfo)
	if err != nil {
		return nil, err
	}

	// TODO: Fix?
	if len(algInfo) >= 4 {
		algInfo[3] -= 2
	}

	tvs, err := tlv.DecodeBER(algInfo)
	if err != nil {
		return nil, errUnmarshal
	}

	_, tvs, ok := tvs.Get(tagAlgInfo)
	if !ok {
		return nil, errUnmarshal
	}

	for _, tv := range tvs {
		var key KeyRef
		switch tv.Tag {
		case tagAlgAttrsSign:
			key = KeySign
		case tagAlgAttrsDecrypt:
			key = KeyDecrypt
		case tagAlgAttrsAuthn:
			key = KeyAuthn
		case tagAlgAttrsAttest:
			key = KeyAttest
		}

		var algAttrs AlgorithmAttributes
		if err := algAttrs.Decode(tv.Value); err != nil {
			return nil, errUnmarshal
		}

		algs[key] = append(algs[key], algAttrs)
	}

	return algs, nil
}

// BlockCipher returns a block cipher object for symmetric AES de/encipherment.
func (tx *TX) BlockCipher() *BlockCipher {
	return &BlockCipher{tx}
}

// ImportKeyAES stores an AES key for symmetric encryption on the card.
// The Key length must be 16 or 32 Byte for AES128 and AES256 respectively.
// For encryption and decryption, use the block cipher object returned by [Card.BlockCipher].
func (tx *TX) ImportKeyAES(key []byte) error {
	if tx.Capabilities.Flags&CapAES == 0 {
		return fmt.Errorf("%w: AES en/decryption is not supported", ErrUnsupported)
	}

	if len(key) != 16 && len(key) != 32 {
		return fmt.Errorf("%w: AES key length must be either 16 or 32 Bytes", ErrInvalidLength)
	}

	return tx.putData(tagKeyAES, key)
}

func (tx *TX) algorithmAttributesFromPrivateKey(sk crypto.PrivateKey) (aa AlgorithmAttributes, err error) {
	switch sk := sk.(type) {
	case *rsa.PrivateKey:
		aa.LengthModulus = sk.N.BitLen()

	case *ecdsa.PrivateKey:
		aa.OID = curveFromECDSA(sk.Curve).OID()

	case *ecdh.PrivateKey:
		aa.OID = curveFromECDH(sk.Curve()).OID()

	case ed25519.PrivateKey:
		aa.OID = CurveEd25519.OID()

	default:
		return aa, ErrUnsupportedKeyType
	}

	return aa, nil
}

func (tx *TX) findCompatibleAlgorithmAttributes(key KeyRef, attrs AlgorithmAttributes) (aa AlgorithmAttributes, err error) {
	asByKey, err := tx.SupportedAlgorithms()
	if err != nil {
		return aa, fmt.Errorf("failed to get supported algorithm attributes: %w", err)
	}

	as, ok := asByKey[key]
	if !ok {
		return aa, ErrUnsupportedKeyType
	}

	for _, a := range as {
		if a.Compatible(attrs) {
			return a, nil
		}
	}

	return aa, ErrUnsupportedKeyType
}

func (tx *TX) changeAlgorithmAttributes(key KeyRef, attrsRequested AlgorithmAttributes) (a AlgorithmAttributes, err error) {
	attrsNew, err := tx.findCompatibleAlgorithmAttributes(key, attrsRequested)
	if err != nil {
		return a, err
	}

	if attrsCurrent := tx.Keys[key].AlgAttrs; attrsCurrent.Equal(attrsNew) {
		return attrsCurrent, nil
	} else if tx.Capabilities.Flags&CapAlgAttrsChangeable == 0 {
		return attrsCurrent, fmt.Errorf("%w: %s key is fixed to %s", ErrAlgAttrsNotChangeable, key, attrsCurrent)
	}

	if err := tx.putData(key.tagAlgAttrs(), attrsNew.Encode()); err != nil {
		return a, err
	}

	// Update attributes
	keyInfo := tx.Keys[key]
	keyInfo.AlgAttrs = attrsNew
	tx.Keys[key] = keyInfo

	return attrsNew, nil
}

// See: OpenPGP Smart Card Application - Section 7.2.14 GENERATE ASYMMETRIC KEY PAIR
func (tx *TX) generateAsymmetricKeyPair(key KeyRef, generate bool) (privateKey, error) {
	attrs := tx.Keys[key].AlgAttrs

	if !generate && tx.Keys[key].Status == KeyNotPresent {
		return nil, errKeyNotPresent
	}

	p1 := byte(0x81)
	if generate {
		p1 = 0x80
	}

	data, err := tlv.EncodeBER(key.crt())
	if err != nil {
		return nil, fmt.Errorf("failed to encode CRT: %w", err)
	}

	resp, err := send(tx.tx, insGenerateAsymmetricKeyPair, p1, 0, data)
	if err != nil {
		return nil, err
	}

	tvs, err := tlv.DecodeBER(resp)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnmarshal, err)
	}

	switch {
	case attrs.Algorithm == AlgPubkeyRSA:
		pk, err := decodePublicRSA(tvs)
		if err != nil {
			return nil, err
		}

		return &PrivateKeyRSA{
			card:       tx,
			lenModulus: attrs.LengthModulus,
			key:        key,
			public:     pk,
		}, nil

	case attrs.Algorithm == AlgPubkeyECDSA:
		pk, err := decodePublicECDSA(tvs, attrs.Curve())
		if err != nil {
			return nil, err
		}

		return &PrivateKeyECDSA{
			card:   tx,
			curve:  attrs.Curve(),
			public: pk,
			key:    key,
		}, nil

	case attrs.Algorithm == AlgPubkeyEdDSA && attrs.Curve() == CurveX25519:
		fallthrough // Special-case

	case attrs.Algorithm == AlgPubkeyECDH:
		pk, err := decodePublicECDH(tvs, attrs.Curve())
		if err != nil {
			return nil, err
		}

		return &PrivateKeyECDH{
			card:   tx,
			curve:  attrs.Curve(),
			public: pk,
			key:    key,
		}, nil

	case attrs.Algorithm == AlgPubkeyEdDSA:
		pk, err := decodePublicEdDSA(tvs)
		if err != nil {
			return nil, err
		}

		return &PrivateKeyEdDSA{
			card:   tx,
			public: pk,
			key:    key,
		}, nil

	default:
		return nil, ErrUnsupported
	}
}

func appendKDF(b []byte, h AlgHash, c AlgSymmetric) []byte {
	return append(b, 3, 0x01, byte(h), byte(c))
}
