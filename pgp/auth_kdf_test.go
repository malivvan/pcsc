// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	pgp "github.com/malivvan/pcsc/pgp"
)

//
//func TestSetupKDF(t *testing.T) {
//	withCard(t, true, func(t *testing.T, c *pgp.Card) {
//		require := require.New(t)
//
//		if c.Capabilities.Flags&pgp.CapKDF == 0 {
//			t.Skip("Card does not support key derivation")
//		}
//
//		err := c.SetupKDF(pgp.AlgKDFIterSaltedS2K, 100000, pgp.DefaultPW1, pgp.DefaultPW3)
//		require.NoError(err)
//
//		err = c.VerifyPassword(pgp.PW1, pgp.DefaultPW1)
//		require.NoError(err)
//
//		err = c.VerifyPassword(pgp.PW3, pgp.DefaultPW3)
//		require.NoError(err)
//
//		// Remove KDF again
//		err = c.SetupKDF(pgp.AlgKDFNone, 0, pgp.DefaultPW1, pgp.DefaultPW3)
//		require.NoError(err)
//
//		err = c.VerifyPassword(pgp.PW1, pgp.DefaultPW1)
//		require.NoError(err)
//
//		err = c.VerifyPassword(pgp.PW3, pgp.DefaultPW3)
//		require.NoError(err)
//	})
//}

func TestKDF(t *testing.T) {
	require := require.New(t)

	k := &pgp.KDF{
		Algorithm:     pgp.AlgKDFIterSaltedS2K,
		HashAlgorithm: pgp.AlgHashSHA256,
		Iterations:    100000,
		SaltPW1:       [8]byte{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37},
		SaltRC:        [8]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
		SaltPW3:       [8]byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48},
	}

	// Test vectors from OpenPGP Smart Card Application spec
	// See: OpenPGP Smart Card Application - Section 4.3.2 Key derived format
	expectedHashDefaultPW1 := []byte{0x77, 0x37, 0x84, 0xA6, 0x02, 0xB6, 0xC8, 0x1E, 0x3F, 0x09, 0x2F, 0x4D, 0x7D, 0x00, 0xE1, 0x7C, 0xC8, 0x22, 0xD8, 0x8F, 0x73, 0x60, 0xFC, 0xF2, 0xD2, 0xEF, 0x2D, 0x9D, 0x90, 0x1F, 0x44, 0xB6}
	expectedHashDefaultPW3 := []byte{0x26, 0x75, 0xD6, 0x16, 0x4A, 0x0D, 0x48, 0x27, 0xD1, 0xD0, 0x0C, 0x7E, 0xEA, 0x62, 0x0D, 0x01, 0x5C, 0x00, 0x03, 0x0A, 0x1C, 0xAB, 0x38, 0xB4, 0xD0, 0xDD, 0x60, 0x0B, 0x27, 0xDC, 0x96, 0x30}

	hashDefaultPW1, err := k.DerivePassword(pgp.PW1, pgp.DefaultPW1)
	require.NoError(err)
	require.Equal(expectedHashDefaultPW1, hashDefaultPW1)

	hashDefaultPW3, err := k.DerivePassword(pgp.PW3, pgp.DefaultPW3)
	require.NoError(err)
	require.Equal(expectedHashDefaultPW3, hashDefaultPW3)
}
