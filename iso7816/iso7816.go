// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package iso7816

func DecodeResponse(resp []byte) (data []byte, sw1 byte, sw2 byte) {
	lenResp := len(resp)

	sw1 = resp[lenResp-2]
	sw2 = resp[lenResp-1]
	data = resp[:lenResp-2]

	return data, sw1, sw2
}

type TX interface {
	Transmit([]byte) ([]byte, uint64, error)
	SendAPDU(*CAPDU) ([]byte, error)
	Select(aid []byte) error
	SetGRIns(ins Instruction)
}
