// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp_test

import (
	pgp "github.com/malivvan/pcsc/pgp"
)

//nolint:gochecknoglobals
var ecdsaCurves = []pgp.Curve{
	pgp.CurveANSIx9p256r1,
	pgp.CurveANSIx9p384r1,
	pgp.CurveANSIx9p521r1,
}

//
//func testGenerateKeyECDSA(t *testing.T) {
//	for _, curve := range ecdsaCurves {
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
//				skECDSA, ok := sk.(*pgp.PrivateKeyECDSA)
//				require.True(ok)
//
//				pkECDSA, ok := skECDSA.Public().(*ecdsa.PublicKey)
//				require.True(ok)
//
//				require.Equal(curve.ECDSA(), pkECDSA.Curve)
//
//				ki := c.Keys[pgp.KeySign]
//				require.Equal(pgp.KeySign, ki.Reference)
//				require.Equal(pgp.KeyGenerated, ki.Status)
//				require.Equal(pgp.AlgPubkeyECDSA, ki.AlgAttrs.Algorithm)
//				require.Equal(curve.OID(), ki.AlgAttrs.OID)
//			})
//		})
//	}
//}
//
//func testImportKeyECDSA(t *testing.T) {
//	for _, curve := range ecdsaCurves {
//		t.Run(curve.String(), func(t *testing.T) {
//			withCard(t, true, func(t *testing.T, c *pgp.Card) {
//				require := require.New(t)
//
//				skImport, err := ecdsa.GenerateKey(curve.ECDSA(), c.Rand)
//				require.NoError(err)
//
//				sk, err := c.ImportKey(pgp.KeySign, skImport)
//				if errors.Is(err, pgp.ErrUnsupportedKeyType) {
//					t.Skip(err)
//				}
//
//				require.NoError(err)
//
//				skECDSA, ok := sk.(*pgp.PrivateKeyECDSA)
//				require.True(ok)
//
//				pkECDSA, ok := skECDSA.Public().(*ecdsa.PublicKey)
//				require.True(ok)
//
//				require.Equal(curve.ECDSA(), pkECDSA.Curve)
//
//				ki := c.Keys[pgp.KeySign]
//				require.Equal(pgp.KeySign, ki.Reference)
//				require.Equal(pgp.KeyImported, ki.Status)
//				require.Equal(pgp.AlgPubkeyECDSA, ki.AlgAttrs.Algorithm)
//				require.Equal(curve.OID(), ki.AlgAttrs.OID)
//			})
//		})
//	}
//}
//
//func testSignECDSA(t *testing.T) {
//	for _, curve := range ecdsaCurves {
//		t.Run(curve.String(), func(t *testing.T) {
//			withCard(t, true, func(t *testing.T, c *pgp.Card) {
//				require := require.New(t)
//
//				skAlice, err := c.GenerateKey(pgp.KeySign, pgp.EC(curve))
//				require.NoError(err)
//
//				skECDSA, ok := skAlice.(*pgp.PrivateKeyECDSA)
//				require.True(ok)
//
//				pk := skECDSA.Public()
//
//				pkECDSA, ok := pk.(*ecdsa.PublicKey)
//				require.True(ok)
//
//				data := make([]byte, 21422)
//				_, err = c.Rand.Read(data)
//				require.NoError(err)
//
//				err = c.VerifyPassword(pgp.PW1, pgp.DefaultPW1)
//				require.NoError(err)
//
//				for _, ht := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
//					h := ht.New()
//					_, err := h.Write(data)
//					require.NoError(err)
//
//					digest := h.Sum(nil)
//
//					_, err = skECDSA.Sign(nil, digest[:len(digest)-1], nil)
//					require.ErrorIs(err, pgp.ErrInvalidLength)
//
//					ds, err := skECDSA.Sign(nil, digest, nil)
//					require.NoError(err)
//
//					ok = ecdsa.VerifyASN1(pkECDSA, digest, ds)
//					require.True(ok)
//				}
//			})
//		})
//	}
//}
