// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp_test

import (
	"bytes"
)

//nolint:gochecknoglobals
var (
	plainText          = []byte("Lorem ipsum dolor sit amet, consetetur sadipscing elitr...")
	cipherTextExpected = []byte{0x20, 0xd6, 0x82, 0xa1, 0x15, 0xe7, 0x29, 0x33, 0x02, 0xbd, 0x3e, 0x52, 0x93, 0x8e, 0x63, 0xc3, 0x14, 0xfd, 0x9d, 0x43, 0x57, 0x97, 0x6c, 0xdc, 0x57, 0x17, 0x7f, 0xe3, 0x05, 0x8c, 0x58, 0x82, 0x2a, 0xc9, 0x48, 0x23, 0x3b, 0xf7, 0x97, 0x38, 0x04, 0x2a, 0xba, 0x67, 0x0c, 0x45, 0x5f, 0x36, 0xa6, 0x73, 0x8a, 0xd7, 0x55, 0x07, 0xc2, 0x67, 0x13, 0x0a, 0xc5, 0x17, 0x2a, 0x0f, 0x41, 0xa7}
	key                = []byte{0x8f, 0x6a, 0xc9, 0xd3, 0x7f, 0x40, 0xde, 0x14, 0x4e, 0x23, 0x4b, 0x04, 0x6f, 0xea, 0x1a, 0x72}
)

//
//func TestBlockCipher(t *testing.T) {
//	withCard(t, true, func(t *testing.T, c *pgp.Card) {
//		require := require.New(t)
//
//		if c.Capabilities.Flags&pgp.CapAES == 0 {
//			t.Skip("Card does not support AES")
//		}
//
//		err := c.ImportKeyAES(key)
//		require.NoError(err)
//
//		bc := c.BlockCipher()
//
//		// Encrypt
//		plainTextPadded := PadPKCS(plainText, bc.BlockSize())
//
//		cipherText, err := bc.Encrypt(plainTextPadded)
//		require.NoError(err)
//		require.Equal(cipherTextExpected, cipherText)
//
//		// Decrypt
//		plainTextPadded2, err := bc.Decrypt(plainTextPadded)
//		require.NoError(err)
//		require.Equal(plainTextPadded, plainTextPadded2)
//
//		plainText2 := TrimPKCS(plainTextPadded2)
//		require.Equal(plainText, plainText2)
//	})
//}

func PadPKCS(pt []byte, bs int) []byte {
	padding := bs - len(pt)%bs
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(pt, padtext...)
}

func TrimPKCS(pt []byte) []byte {
	padding := pt[len(pt)-1]
	return pt[:len(pt)-int(padding)]
}
