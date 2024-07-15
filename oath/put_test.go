// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package oath_test

//func TestPut(t *testing.T) {
//	withCard(t, nil, func(t *testing.T, card *ykoath.Card) {
//		require := require.New(t)
//
//		err := card.Put("test", ykoath.HmacSha1, ykoath.Hotp, 6, []byte{1, 2, 3}, false, 0)
//		require.NoError(err)
//	})
//}
//
//func TestPutNameTooLong(t *testing.T) {
//	withCard(t, nil, func(t *testing.T, card *ykoath.Card) {
//		require := require.New(t)
//
//		err := card.Put("0123456789012345678901234567890123456789012345678901234567890123456789", ykoath.HmacSha1, ykoath.Hotp, 6, []byte{1, 2, 3}, false, 0)
//		require.ErrorIs(err, ykoath.ErrNameTooLong)
//	})
//}
