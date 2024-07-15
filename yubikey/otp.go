// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package yubikey

import (
	"encoding/binary"
	"errors"

	iso "github.com/malivvan/pcsc/iso7816"
)

type Status struct {
	Version    iso.Version
	Sequence   uint8
	TouchLevel uint16
}

func (s *Status) Unmarshal(b []byte) error {
	if len(b) != 6 {
		return ErrInvalidResponseLength
	}

	s.Version = iso.Version{
		Major: int(b[0]),
		Minor: int(b[1]),
		Patch: int(b[2]),
	}
	s.Sequence = b[3]
	s.TouchLevel = binary.BigEndian.Uint16(b[4:])

	return nil
}

// GetStatus returns the status of the YubiKey token.
func GetStatus(tx iso.TX) (*Status, error) {
	resp, err := tx.SendAPDU(&iso.CAPDU{
		Ins: InsReadStatus,
		P1:  0x00,
		P2:  0x00,
	})
	if err != nil {
		return nil, err
	}

	sts := &Status{}
	if err := sts.Unmarshal(resp); err != nil {
		return nil, err
	}

	return sts, nil
}

// GetSerialNumber returns the serial number of the YubiKey token.
func GetSerialNumber(tx iso.TX) (uint32, error) {
	resp, err := tx.SendAPDU(&iso.CAPDU{
		Ins: InsOTP,
		P1:  0x10,
		P2:  0x00,
	})
	if err != nil {
		return 0, err
	}

	if len(resp) != 4 {
		return 0, ErrInvalidResponseLength
	}

	return binary.BigEndian.Uint32(resp), nil
}

// GetFIPSMode returns returns the FIPS compliancy state of the YubiKey token.
func GetFIPSMode(tx iso.TX) (bool, error) {
	resp, err := tx.SendAPDU(&iso.CAPDU{
		Ins: InsOTP,
		P1:  0x14,
		P2:  0x00,
	})
	if err != nil {
		if errors.Is(err, iso.ErrIncorrectParams) || errors.Is(err, iso.ErrWrongParams) {
			return false, nil
		}

		return false, err
	}

	return resp[0] != 0, nil
}

func Metadata(tx iso.TX) (meta map[string]any) {
	if err := tx.Select(iso.AidYubicoOTP); err != nil {
		return nil
	}

	meta = map[string]any{}

	if sts, err := GetStatus(tx); err == nil {
		meta["version"] = sts.Version
	}

	if sno, err := GetSerialNumber(tx); err == nil {
		meta["serial"] = sno
	}

	return meta
}
