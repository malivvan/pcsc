// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0
package pgp_test

//func TestGenerateKey(t *testing.T) {
//	t.Run("RSA", testGenerateKeyRSA)
//	t.Run("ECDSA", testGenerateKeyECDSA)
//	t.Run("ECDH", testGenerateKeyECDH)
//	t.Run("EdDSA", testGenerateKeyEdDSA)
//}
//
//func TestImportKey(t *testing.T) {
//	t.Run("RSA", testImportKeyRSA)
//	t.Run("ECDSA", testImportKeyECDSA)
//	t.Run("ECDH", testImportKeyECDH)
//	t.Run("EdDSA", testImportKeyEdDSA)
//}
//
//func TestSign(t *testing.T) {
//	t.Run("RSA", testSignRSA)
//	t.Run("ECDSA", testSignECDSA)
//	t.Run("EdDSA", testSignEdDSA)
//}
//
//func TestSupportedAlgorithms(t *testing.T) {
//	withCard(t, false, func(t *testing.T, c *pgp.Card) {
//		require := require.New(t)
//
//		asByKey, err := c.SupportedAlgorithms()
//		require.NoError(err)
//
//		for key, as := range asByKey {
//			for _, a := range as {
//				t.Logf("%s %s %#x", key, a, a.ImportFormat)
//			}
//		}
//	})
//}
//
//func TestAlgorithmAttributes(t *testing.T) {
//	withCard(t, false, func(t *testing.T, c *pgp.Card) {
//		require := require.New(t)
//
//		attrs, err := c.AlgorithmAttributes(pgp.KeySign)
//		require.NoError(err)
//
//		t.Log(attrs)
//	})
//}
