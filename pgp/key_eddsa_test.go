// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp_test

//
////nolint:gochecknoglobals
//var eddsaCurves = []pgp.Curve{pgp.CurveEd25519}
//
//func testGenerateKeyEdDSA(t *testing.T) {
//	for _, curve := range eddsaCurves {
//		t.Run(curve.String(), func(t *testing.T) {
//			withCard(t, true, func(t *testing.T, c *pgp.Card) {
//				require := require.New(t)
//
//				sk, err := c.GenerateKey(pgp.KeySign, pgp.EC(curve))
//				if errors.Is(err, pgp.ErrUnsupportedKeyType) {
//					t.Skip(err)
//				}
//
//				require.NoError((err))
//
//				skEdDSA, ok := sk.(*pgp.PrivateKeyEdDSA)
//				require.True(ok)
//
//				_, ok = skEdDSA.Public().(ed25519.PublicKey)
//				require.True(ok)
//
//				ki := c.Keys[pgp.KeySign]
//				require.Equal(pgp.KeySign, ki.Reference)
//				require.Equal(pgp.KeyGenerated, ki.Status)
//				require.Equal(pgp.AlgPubkeyEdDSA, ki.AlgAttrs.Algorithm)
//				require.Equal(curve.OID(), ki.AlgAttrs.OID)
//			})
//		})
//	}
//}
//
//func testImportKeyEdDSA(t *testing.T) {
//	for _, curve := range eddsaCurves {
//		t.Run(curve.String(), func(t *testing.T) {
//			withCard(t, true, func(t *testing.T, c *pgp.Card) {
//				require := require.New(t)
//
//				_, skImport, err := ed25519.GenerateKey(c.Rand)
//				require.NoError(err)
//
//				sk, err := c.ImportKey(pgp.KeySign, skImport)
//				if errors.Is(err, pgp.ErrUnsupportedKeyType) {
//					t.Skip(err)
//				}
//
//				require.NoError(err)
//
//				skEdDSA, ok := sk.(*pgp.PrivateKeyEdDSA)
//				require.True(ok)
//
//				_, ok = skEdDSA.Public().(ed25519.PublicKey)
//				require.True(ok)
//
//				ki := c.Keys[pgp.KeySign]
//				require.Equal(pgp.KeySign, ki.Reference)
//				require.Equal(pgp.KeyImported, ki.Status)
//				require.Equal(pgp.AlgPubkeyEdDSA, ki.AlgAttrs.Algorithm)
//				require.Equal(curve.OID(), ki.AlgAttrs.OID)
//			})
//		})
//	}
//}
//
//func testSignEdDSA(t *testing.T) {
//	withCard(t, true, func(t *testing.T, c *pgp.Card) {
//		require := require.New(t)
//
//		sk, err := c.GenerateKey(pgp.KeySign, pgp.EC(pgp.CurveEd25519))
//		require.NoError(err)
//
//		skEdDSA, ok := sk.(*pgp.PrivateKeyEdDSA)
//		require.True(ok)
//
//		pk := skEdDSA.Public()
//
//		pkEdDSA, ok := pk.(ed25519.PublicKey)
//		require.True(ok)
//
//		data := make([]byte, 21422)
//		_, err = c.Rand.Read(data)
//		require.NoError(err)
//
//		err = c.VerifyPassword(pgp.PW1, pgp.DefaultPW1)
//		require.NoError(err)
//
//		for _, ht := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
//			h := ht.New()
//			_, err := h.Write(data)
//			require.NoError(err)
//
//			digest := h.Sum(nil)
//
//			_, err = skEdDSA.Sign(nil, digest[:len(digest)-1], nil)
//			require.ErrorIs(err, pgp.ErrInvalidLength)
//
//			ds, err := skEdDSA.Sign(nil, digest, nil)
//			require.NoError(err)
//
//			ok = ed25519.Verify(pkEdDSA, digest, ds)
//			require.True(ok)
//		}
//	})
//}
