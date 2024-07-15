// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp

import (
	"crypto/aes"

	"github.com/malivvan/pcsc/iso7816"
)

// ICV is the Initial Chaining Value used by OpenPGP cards for symmetric encryption using AES-CBC
//
//nolint:gochecknoglobals
var ICV = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

type BlockCipher struct {
	card *TX
}

// BlockSize returns the cipher's block size.
func (k BlockCipher) BlockSize() int {
	return aes.BlockSize
}

// Encrypt encrypts the provided plaintext using AES in Cipher Block Chaining (CBC) mode
// using an Initial Chaining Value (ICV) of zero bytes ([IV]).
//
// See: OpenPGP Smart Card Application - Section 7.2.12 PSO: ENCIPHER
func (k *BlockCipher) Encrypt(pt []byte) ([]byte, error) {
	if len(pt)%aes.BlockSize != 0 {
		return nil, ErrInvalidLength
	}

	resp, err := send(k.card.tx, iso7816.InsPerformSecurityOperation, 0x86, 0x80, pt)
	if err != nil {
		return nil, err
	}

	return resp[1:], err
}

// Decrypt decrypts the provided ciphertext using AES in Cipher Block Chaining (CBC) mode
// using an Initial Chaining Value (ICV) of zero bytes.
//
// See: OpenPGP Smart Card Application - Section 7.2.11 PSO: DECIPHER
func (k *BlockCipher) Decrypt(ct []byte) ([]byte, error) {
	if len(ct)%aes.BlockSize != 0 {
		return nil, ErrInvalidLength
	}

	return send(k.card.tx, iso7816.InsPerformSecurityOperation, 0x80, 0x86, append([]byte{0x02}, ct...))
}
