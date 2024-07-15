// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package oath_test

import (
	"github.com/malivvan/pcsc/oath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOTP(t *testing.T) {
	require := require.New(t)
	for _, v := range vectors["HOTP"] {
		c := oath.Code{
			Hash:   v.Hash,
			Digits: v.Digits,
		}

		require.Equal(v.Code, c.OTP())
	}
}
