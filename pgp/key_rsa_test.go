// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp_test

//
////nolint:gochecknoglobals
//var rsaBits = []int{1024, 2048, 3072, 4096}
//
//func testGenerateKeyRSA(t *testing.T) {
//	for _, bits := range rsaBits {
//		t.Run(fmt.Sprintf("%d", bits), func(t *testing.T) {
//			withCard(t, true, func(t *testing.T, c *pgp.Card) {
//				require := require.New(t)
//
//				sk, err := c.GenerateKey(pgp.KeySign, pgp.RSA(bits))
//				if errors.Is(err, pgp.ErrUnsupportedKeyType) {
//					t.Skip(err)
//				}
//
//				require.NoError(err)
//
//				skRSA, ok := sk.(*pgp.PrivateKeyRSA)
//				require.True(ok)
//				require.Equal(bits, skRSA.Bits())
//
//				ki := c.Keys[pgp.KeySign]
//				require.Equal(pgp.KeySign, ki.Reference)
//				require.Equal(pgp.KeyGenerated, ki.Status)
//				require.Equal(pgp.AlgPubkeyRSA, ki.AlgAttrs.Algorithm)
//				require.Equal(bits, ki.AlgAttrs.LengthModulus)
//			})
//		})
//	}
//}

//func testImportKeyRSA(t *testing.T) {
//	for _, bits := range rsaBits {
//		t.Run(fmt.Sprint(bits), func(t *testing.T) {
//			withCard(t, true, func(t *testing.T, c *pgp.Card) {
//				require := require.New(t)
//
//				if test.PCSCCard(c.Card) == nil {
//					t.Skip("RSA key generation is not deterministic. Mocked tests are broken")
//				}
//
//				skImport, err := rsa.GenerateKey(rand.Reader, bits)
//				require.NoError(err)
//
//				sk, err := c.ImportKey(pgp.KeySign, skImport)
//				if errors.Is(err, pgp.ErrUnsupportedKeyType) {
//					t.Skip(err)
//				}
//
//				require.NoError(err)
//
//				skRSA, ok := sk.(*pgp.PrivateKeyRSA)
//				require.True(ok)
//				require.Equal(bits, skRSA.Bits())
//
//				ki := c.Keys[pgp.KeySign]
//				require.Equal(pgp.KeySign, ki.Reference)
//				require.Equal(pgp.KeyImported, ki.Status)
//				require.Equal(pgp.AlgPubkeyRSA, ki.AlgAttrs.Algorithm)
//				require.Equal(bits, ki.AlgAttrs.LengthModulus)
//			})
//		})
//	}
//}
//
//func testSignRSA(*testing.T) {
//}
