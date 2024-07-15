// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp_test

import (
	pgp "github.com/malivvan/pcsc/pgp"
)

//nolint:gochecknoglobals
var ecdhCurves = []pgp.Curve{
	pgp.CurveANSIx9p256r1,
	pgp.CurveANSIx9p384r1,
	pgp.CurveANSIx9p521r1,
	pgp.CurveX25519,
}

//
//func testGenerateKeyECDH(t *testing.T) {
//	for _, curve := range ecdhCurves {
//		t.Run(curve.String(), func(t *testing.T) {
//			withCard(t, true, func(t *testing.T, c *pgp.Card) {
//				require := require.New(t)
//
//				sk, err := c.GenerateKey(pgp.KeyDecrypt, pgp.EC(curve))
//				if errors.Is(err, pgp.ErrUnsupportedKeyType) {
//					t.Skip(err)
//				}
//
//				require.NoError((err))
//
//				skECDH, ok := sk.(*pgp.PrivateKeyECDH)
//				require.True(ok)
//
//				pkECDH, ok := skECDH.Public().(*ecdh.PublicKey)
//				require.True(ok)
//
//				require.Equal(curve.ECDH(), pkECDH.Curve())
//
//				ki := c.Keys[pgp.KeyDecrypt]
//				require.Equal(pgp.KeyDecrypt, ki.Reference)
//				require.Equal(pgp.KeyGenerated, ki.Status)
//				require.Equal(curve.OID(), ki.AlgAttrs.OID)
//				if curve == pgp.CurveX25519 {
//					require.Equal(pgp.AlgPubkeyEdDSA, ki.AlgAttrs.Algorithm)
//				} else {
//					require.Equal(pgp.AlgPubkeyECDH, ki.AlgAttrs.Algorithm)
//				}
//			})
//		})
//	}
//}
//
//func testImportKeyECDH(t *testing.T) {
//	for _, curve := range ecdhCurves {
//		t.Run(curve.String(), func(t *testing.T) {
//			withCard(t, true, func(t *testing.T, c *pgp.Card) {
//				require := require.New(t)
//
//				skImport, err := curve.ECDH().GenerateKey(c.Rand)
//				require.NoError(err)
//
//				sk, err := c.ImportKey(pgp.KeyDecrypt, skImport)
//				if errors.Is(err, pgp.ErrUnsupportedKeyType) {
//					t.Skip(err)
//				}
//
//				require.NoError(err)
//
//				skECDH, ok := sk.(*pgp.PrivateKeyECDH)
//				require.True(ok)
//
//				pkECDH, ok := skECDH.Public().(*ecdh.PublicKey)
//				require.True(ok)
//
//				require.Equal(curve.ECDH(), pkECDH.Curve())
//
//				ki := c.Keys[pgp.KeyDecrypt]
//				require.Equal(pgp.KeyDecrypt, ki.Reference)
//				require.Equal(pgp.KeyImported, ki.Status)
//				require.Equal(curve.OID(), ki.AlgAttrs.OID)
//				if curve == pgp.CurveX25519 {
//					require.Equal(pgp.AlgPubkeyEdDSA, ki.AlgAttrs.Algorithm)
//				} else {
//					require.Equal(pgp.AlgPubkeyECDH, ki.AlgAttrs.Algorithm)
//				}
//			})
//		})
//	}
//}
//
//func TestSharedKeyECDH(t *testing.T) {
//	for _, curve := range ecdhCurves {
//		t.Run(curve.String(), func(t *testing.T) {
//			withCard(t, true, func(t *testing.T, c *pgp.Card) {
//				require := require.New(t)
//
//				skAlice, err := c.GenerateKey(pgp.KeyDecrypt, pgp.EC(curve))
//				require.NoError(err)
//
//				skAliceECDH, ok := skAlice.(*pgp.PrivateKeyECDH)
//				require.True(ok)
//
//				pkAlice := skAliceECDH.Public()
//				pkAliceECDH, ok := pkAlice.(*ecdh.PublicKey)
//				require.True(ok)
//
//				skBobECDH, err := curve.ECDH().GenerateKey(c.Rand)
//				require.NoError(err)
//
//				pkBob := skBobECDH.Public()
//				pkBobECDH, ok := pkBob.(*ecdh.PublicKey)
//				require.True(ok)
//
//				ss1, err := skBobECDH.ECDH(pkAliceECDH)
//				require.NoError(err)
//
//				err = c.VerifyPassword(pgp.PW1forPSO, pgp.DefaultPW1)
//				require.NoError(err)
//
//				ss2, err := skAliceECDH.ECDH(pkBobECDH)
//				require.NoError(err)
//
//				require.Equal(ss1, ss2)
//			})
//		})
//	}
//}
