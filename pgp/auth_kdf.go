// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"

	iso "github.com/malivvan/pcsc/iso7816"
)

var (
	errIterationsTooSmall                       = errors.New("iterations too small")
	errUnsupportedKDFAlg                        = fmt.Errorf("%w algorithm", ErrUnsupported)
	errUnsupportedKDFHashAlg                    = fmt.Errorf("%w hash algorithm", ErrUnsupported)
	errUnsupportedPasswordLengthsTooShortForKDF = fmt.Errorf("%w: password lengths are too small for KDF", ErrUnsupported)
	errMissingKDFSalt                           = errors.New("missing salt")
)

func (tx *TX) GetKDF() (k *KDF, err error) {
	resp, err := tx.getData(tagKDF)
	if err != nil {
		return nil, err
	}

	k = &KDF{}
	if err := k.Decode(resp); err != nil {
		return nil, err
	}

	tx.kdf = k

	return k, nil
}

// SetupKDF initialize the KDF data object and updates passwords to work with it.
//
// Resetting code must be set again. User/PW1 and Admin/PW3 are unchanged.
//
// Access condition: Admin/PW3 (User/PW1 and AdminPW3 must be passed as arguments)
// See: OpenPGP Smart Card Application - Section 4.3.2 Key derived format
func (tx *TX) SetupKDF(alg AlgKDF, iterations int, pw1, pw3 string) (err error) {
	// Check if KDF is supported
	if tx.Capabilities.Flags&CapKDF == 0 {
		return fmt.Errorf("key derived passwords are %w", ErrUnsupported)
	}

	if min(tx.PasswordStatus.LengthPW1, tx.PasswordStatus.LengthRC, tx.PasswordStatus.LengthPW3) < 64 {
		return errUnsupportedPasswordLengthsTooShortForKDF
	}

	if alg == AlgKDFIterSaltedS2K && iterations < 1000 {
		return errIterationsTooSmall
	}

	// Prepare new KDF parameters
	// Put KDF parameters to card
	kdf := &KDF{
		Algorithm: alg,
	}

	switch alg {
	case AlgKDFNone:
	case AlgKDFIterSaltedS2K:
		kdf.HashAlgorithm = AlgHashSHA512
		kdf.Iterations = iterations

		if _, err := tx.Rand.Read(kdf.SaltPW1[:]); err != nil {
			return fmt.Errorf("failed to generate random salt: %w", err)
		}

		if _, err := tx.Rand.Read(kdf.SaltRC[:]); err != nil {
			return fmt.Errorf("failed to generate random salt: %w", err)
		}

		if _, err := tx.Rand.Read(kdf.SaltPW3[:]); err != nil {
			return fmt.Errorf("failed to generate random salt: %w", err)
		}

	default:
		return ErrUnsupported
	}

	if kdf.InitialHashPW1, err = kdf.DerivePassword(PW1, DefaultPW1); err != nil {
		return fmt.Errorf("failed to derive password: %w", err)
	}

	if kdf.InitialHashPW3, err = kdf.DerivePassword(PW3, DefaultPW3); err != nil {
		return fmt.Errorf("failed to derive password: %w", err)
	}

	// Verify for KDF-DO update
	if err := tx.VerifyPassword(PW3, pw3); err != nil {
		return err
	}

	// Update passwords according to new KDF
	pws := map[byte]string{
		PW1: pw1,
		PW3: pw3,
	}

	for pwType, pwCurrent := range pws {
		pwOld, err := tx.kdf.DerivePassword(pwType, pwCurrent)
		if err != nil {
			return fmt.Errorf("failed to derive password: %w", err)
		}

		pwNew, err := kdf.DerivePassword(pwType, pwCurrent)
		if err != nil {
			return fmt.Errorf("failed to derive password: %w", err)
		}

		data := []byte{}
		data = append(data, pwOld...)
		data = append(data, pwNew...)

		if _, err = send(tx.tx, iso.InsChangeReferenceData, 0x00, pwType, data); err != nil {
			return fmt.Errorf("failed to change password: %w", err)
		}
	}

	// Update KDF-DO
	b, err := kdf.Encode()
	if err != nil {
		return err
	}

	if err := tx.putData(tagKDF, b); err != nil {
		return err
	}

	tx.kdf = kdf

	return nil
}

func (k *KDF) DerivePassword(pwType byte, pw string) ([]byte, error) {
	switch k.Algorithm {
	case AlgKDFNone:
		return []byte(pw), nil

	case AlgKDFIterSaltedS2K:
		var hash hash.Hash
		switch k.HashAlgorithm {
		case AlgHashSHA256:
			hash = sha256.New()
		case AlgHashSHA512:
			hash = sha512.New()
		default:
			return nil, errUnsupportedKDFHashAlg
		}

		var salt [8]byte
		switch pwType {
		case PW1:
			salt = k.SaltPW1
		case RC:
			salt = k.SaltRC
		case PW3:
			salt = k.SaltPW3
		default:
			return nil, errMissingKDFSalt
		}

		out := make([]byte, hash.Size())
		s2kIterated(out, hash, []byte(pw), salt, k.Iterations)

		return out, nil

	default:
		return nil, errUnsupportedKDFAlg
	}
}
