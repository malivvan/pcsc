// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package oath

import (
	"github.com/malivvan/pcsc/iso7816/tlv"
)

// Delete sends a "DELETE" instruction, removing one named OATH credential
func (c *Card) Delete(name string) error {
	_, err := c.send(insDelete, 0x00, 0x00,
		tlv.New(tagName, []byte(name)),
	)
	return err
}
