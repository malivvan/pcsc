// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp_test

//
//func TestVerifyPassword(t *testing.T) {
//	for pwType, pw := range map[byte]string{
//		pgp.PW1: pgp.DefaultPW1,
//		pgp.PW3: pgp.DefaultPW3,
//	} {
//		testName := fmt.Sprintf("pw%d", pwType-0x80)
//		t.Run(testName, func(t *testing.T) {
//			withCard(t, true, func(t *testing.T, c *pgp.Card) {
//				require := require.New(t)
//
//				err := c.VerifyPassword(pwType, "wrong")
//				require.ErrorIs(err, iso.ErrIncorrectData)
//
//				err = c.VerifyPassword(pwType, pw)
//				require.NoError(err)
//
//				err = c.VerifyPassword(pwType, pw)
//				require.NoError(err)
//			})
//		})
//	}
//}
//
//func TestChangePassword(t *testing.T) {
//	withCard(t, true, func(t *testing.T, c *pgp.Card) {
//		require := require.New(t)
//
//		err := c.ChangePassword(pgp.PW1, pgp.DefaultPW1, "hallo")
//		require.ErrorIs(err, pgp.ErrInvalidLength)
//
//		err = c.ChangePassword(pgp.PW1, "wrong", "hallohallo")
//		require.ErrorIs(err, iso.ErrSecurityStatusNotSatisfied)
//
//		err = c.ChangePassword(pgp.PW1, pgp.DefaultPW1, "hallohallo")
//		require.NoError(err)
//
//		err = c.VerifyPassword(pgp.PW1, "hallohallo")
//		require.NoError(err)
//	})
//}
//
//func TestResetRetryCounter(t *testing.T) {
//	withCard(t, true, func(t *testing.T, c *pgp.Card) {
//		require := require.New(t)
//
//		require.Equal(byte(3), c.PasswordStatus.AttemptsPW1, "Initial attempts are not as expected")
//
//		err := c.VerifyPassword(pgp.PW1, "some wrong password")
//		require.ErrorIs(err, iso.ErrSecurityStatusNotSatisfied)
//
//		sts, err := c.GetPasswordStatus()
//		require.NoError(err)
//		require.Equal(byte(2), sts.AttemptsPW1)
//
//		err = c.VerifyPassword(pgp.PW3, pgp.DefaultPW3)
//		require.NoError(err)
//
//		err = c.ResetRetryCounter(pgp.DefaultPW1)
//		require.NoError(err)
//
//		sts, err = c.GetPasswordStatus()
//		require.NoError(err)
//		require.Equal(byte(3), sts.AttemptsPW1)
//	})
//}
//
//func TestResetRetryCounterWithResettingCode(t *testing.T) {
//	withCard(t, true, func(t *testing.T, c *pgp.Card) {
//		require := require.New(t)
//
//		err := c.ChangeResettingCode("my reset code")
//		require.NoError(err, "Failed to setup resetting code")
//
//		require.Equal(byte(3), c.PasswordStatus.AttemptsPW1, "Initial attempts are not as expected")
//
//		err = c.VerifyPassword(pgp.PW1, "some wrong password")
//		require.ErrorIs(err, iso.ErrSecurityStatusNotSatisfied)
//
//		sts, err := c.GetPasswordStatus()
//		require.NoError(err)
//		require.Equal(byte(2), sts.AttemptsPW1)
//
//		err = c.ResetRetryCounterWithResettingCode("my reset code", pgp.DefaultPW1)
//		require.NoError(err)
//
//		sts, err = c.GetPasswordStatus()
//		require.NoError(err)
//		require.Equal(byte(3), sts.AttemptsPW1)
//	})
//}
//
//func TestSetRetryCounters(t *testing.T) {
//	withCard(t, true, func(t *testing.T, c *pgp.Card) {
//		require := require.New(t)
//
//		require.Equal(byte(3), c.PasswordStatus.AttemptsPW1, "Initial attempts are not as expected")
//
//		err := c.VerifyPassword(pgp.PW3, pgp.DefaultPW3)
//		require.NoError(err)
//
//		err = c.SetRetryCounters(11, 12, 13)
//		require.NoError(err)
//
//		// Check that resetting code attempts are zero when not resetting code is set
//		sts, err := c.GetPasswordStatus()
//		require.NoError(err)
//		require.Equal(byte(0), sts.AttemptsRC)
//
//		err = c.ChangeResettingCode("my reset code")
//		require.NoError(err, "Failed to setup resetting code")
//
//		// Once set, we get the correct number
//		sts, err = c.GetPasswordStatus()
//		require.NoError(err)
//		require.Equal(byte(11), sts.AttemptsPW1)
//		require.Equal(byte(12), sts.AttemptsRC)
//		require.Equal(byte(13), sts.AttemptsPW3)
//
//		// Try if the new counters are in effect
//		for i := 0; i < 5; i++ {
//			err = c.VerifyPassword(pgp.PW1, "some wrong password")
//			require.ErrorIs(err, iso.ErrSecurityStatusNotSatisfied)
//		}
//
//		sts, err = c.GetPasswordStatus()
//		require.NoError(err)
//		require.Equal(byte(11-5), sts.AttemptsPW1)
//		require.Equal(byte(12), sts.AttemptsRC)
//		require.Equal(byte(13), sts.AttemptsPW3)
//	})
//}
