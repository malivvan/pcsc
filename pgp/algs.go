// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
)

type AlgorithmAttributes struct {
	Algorithm    AlgPubkey
	ImportFormat ImportFormat

	// Relevant for RSA
	LengthModulus  int
	LengthExponent int

	// Relevant for ECDSA/ECDH/EdDSA
	OID []byte
}

func (a AlgorithmAttributes) Compatible(b AlgorithmAttributes) bool {
	if b.OID != nil { // EC
		return bytes.Equal(a.OID, b.OID)
	}

	return a.LengthModulus == b.LengthModulus // RSA
}

func (a AlgorithmAttributes) Equal(b AlgorithmAttributes) bool {
	return reflect.DeepEqual(a, b)
}

func (a *AlgorithmAttributes) Decode(b []byte) error {
	if len(b) < 1 {
		return ErrInvalidLength
	}

	a.Algorithm = AlgPubkey(b[0])

	switch a.Algorithm {
	case AlgPubkeyRSA:
		if len(b) < 6 {
			return ErrInvalidLength
		}

		a.LengthModulus = int(binary.BigEndian.Uint16(b[1:]))
		a.LengthExponent = int(binary.BigEndian.Uint16(b[3:]))
		a.ImportFormat = ImportFormat(b[5])

	case AlgPubkeyECDH, AlgPubkeyECDSA, AlgPubkeyEdDSA:
		a.OID = b[1:]

		// Strip trailing import format byte if present
		l := len(a.OID)
		if ImportFormat(a.OID[l-1]) == ImportFormatECDSAStdWithPublicKey {
			a.ImportFormat = ImportFormatECDSAStdWithPublicKey
			a.OID = a.OID[:l-1]
		}

	default:
		return errUnmarshal
	}

	return nil
}

func (a AlgorithmAttributes) Encode() (b []byte) {
	b = []byte{byte(a.Algorithm)}

	switch a.Algorithm {
	case AlgPubkeyRSA:
		b = binary.BigEndian.AppendUint16(b, uint16(a.LengthModulus))
		b = binary.BigEndian.AppendUint16(b, uint16(a.LengthExponent))
		b = append(b, byte(a.ImportFormat))

	case AlgPubkeyECDH, AlgPubkeyECDSA, AlgPubkeyEdDSA:
		b = append(b, a.OID...)
		if a.ImportFormat == ImportFormatECDSAStdWithPublicKey {
			b = append(b, byte(ImportFormatECDSAStdWithPublicKey))
		}

	default:
	}

	return b
}

func (a AlgorithmAttributes) String() string {
	switch a.Algorithm {
	case AlgPubkeyRSAEncOnly, AlgPubkeyRSASignOnly, AlgPubkeyRSA:
		return fmt.Sprintf("RSA-%d", a.LengthModulus)

	case AlgPubkeyECDH, AlgPubkeyECDSA, AlgPubkeyEdDSA:
		return fmt.Sprintf("%s (%s)", a.Curve(), a.Algorithm)

	default:
		return "<unknown>"
	}
}

func (a AlgorithmAttributes) Curve() Curve {
	switch {
	case bytes.Equal(a.OID, oidANSIx9p256r1):
		return CurveANSIx9p256r1
	case bytes.Equal(a.OID, oidANSIx9p384r1):
		return CurveANSIx9p384r1
	case bytes.Equal(a.OID, oidANSIx9p521r1):
		return CurveANSIx9p521r1

	case bytes.Equal(a.OID, oidBrainpoolP256r1):
		return CurveBrainpoolP256r1
	case bytes.Equal(a.OID, oidBrainpoolP384r1):
		return CurveBrainpoolP384r1
	case bytes.Equal(a.OID, oidBrainpoolP512r1):
		return CurveBrainpoolP512r1

	case bytes.Equal(a.OID, oidSecp256k1):
		return CurveSecp256k1

	case bytes.Equal(a.OID, oidEd448):
		return CurveEd448
	case bytes.Equal(a.OID, oidEd25519):
		return CurveEd25519

	case bytes.Equal(a.OID, oidX448):
		return CurveX448
	case bytes.Equal(a.OID, oidX25519):
		return CurveX25519
	}

	return CurveUnknown
}

func EC(curve Curve) AlgorithmAttributes {
	return curve.AlgAttrs()
}

func RSA(bits int) AlgorithmAttributes {
	return AlgorithmAttributes{
		LengthModulus: bits,
	}
}
