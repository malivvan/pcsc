// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp

import (
	"math/big"
	"math/bits"
)

func appendMPI(b []byte, i *big.Int) []byte {
	b = append(b, byte(i.BitLen()>>8), byte(i.BitLen()))
	b = append(b, i.Bytes()...)
	return b
}

func appendBytesMPI(b, o []byte) []byte {
	for len(o) != 0 && o[0] == 0 {
		o = o[1:] // Strip leading zero bytes
	}

	var l uint16
	if len(o) > 0 {
		l = 8*uint16(len(o)-1) + uint16(bits.Len8(o[0]))
	}

	b = append(b, byte(l>>8), byte(l))
	b = append(b, o...)
	return b
}
