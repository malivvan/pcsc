// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp

import (
	"errors"
	"fmt"

	iso "github.com/malivvan/pcsc/iso7816"
	"github.com/malivvan/pcsc/iso7816/tlv"
)

// VerifyPassword attempts to unlock a given password.
//
// Access condition: Always
// See: OpenPGP Smart Card Application - Section 7.2.2 VERIFY
func (tx *TX) VerifyPassword(pwType byte, pw string) (err error) {
	var pwBuf []byte
	if tx.kdf == nil {
		pwBuf = []byte(pw)
	} else {
		if pwBuf, err = tx.kdf.DerivePassword(pwType, pw); err != nil {
			return fmt.Errorf("failed to derive password: %w", err)
		}
	}

	_, err = send(tx.tx, iso.InsVerify, 0x00, pwType, pwBuf)
	return err
}

// ClearPasswordState clears the passwort unlock state from the card.
//
// Access condition: Always
// Note: Appears to be broken on YubiKey 5
// See: OpenPGP Smart Card Application - Section 7.2.2 VERIFY
func (tx *TX) ClearPasswordState(pwType byte) error {
	_, err := send(tx.tx, iso.InsVerify, 0xff, pwType, nil)
	return err
}

// PasswordState returns true if the given password is unlocked.
//
// Access condition: Always
// Note: Appears to be broken on YubiKey 5
// See: OpenPGP Smart Card Application - Section 7.2.2 VERIFY
func (tx *TX) PasswordState(pwType byte) (bool, error) {
	_, err := send(tx.tx, iso.InsVerify, 0x00, pwType, nil)
	var aErr *AuthError
	if errors.Is(err, iso.ErrSuccess) {
		return true, nil
	} else if errors.As(err, &aErr) {
		return false, nil
	}
	return false, err
}

// ChangePassword changes the user or admin password.
//
// Access condition: Always
// Access level: None (current password must be provided)
// See: OpenPGP Smart Card Application - Section 7.2.3 CHANGE REFERENCE DATA
func (tx *TX) ChangePassword(pwType byte, pwCurrent, pwNew string) error {
	switch pwType {
	case PW1:
		if len(pwNew) < 6 || len(pwNew) > int(tx.PasswordStatus.LengthPW1) {
			return ErrInvalidLength
		}

	case PW3:
		if len(pwNew) < 8 || len(pwNew) > int(tx.PasswordStatus.LengthPW3) {
			return ErrInvalidLength
		}

	default:
		return ErrUnsupported
	}

	_, err := send(tx.tx, iso.InsChangeReferenceData, 0x00, pwType, []byte(pwCurrent+pwNew))
	return err
}

// ChangeResettingCode sets the resetting code of the cards.
//
// Access condition: Admin/PW3
// See: OpenPGP Smart Card Application - Section 4.3.4 Resetting Code
func (tx *TX) ChangeResettingCode(rc string) error {
	if len(rc) < 8 || len(rc) > int(tx.PasswordStatus.LengthRC) {
		return ErrInvalidLength
	}

	return tx.putData(tagResettingCode, []byte(rc))
}

func (tx *TX) ClearResettingCode() error {
	return tx.putData(tagResettingCode, nil)
}

// ResetRetryCounter reset the PIN retry counter and a new password.
//
// Access condition: Admin/PW3
// See: OpenPGP Smart Card Application - Section 7.2.4 RESET RETRY COUNTER
func (tx *TX) ResetRetryCounter(newPw string) error {
	if len(newPw) < 6 {
		return ErrInvalidLength
	}

	_, err := send(tx.tx, iso.InsResetRetryCounter, 0x02, PW1, []byte(newPw))
	return err
}

// ResetRetryCounterWithResettingCode resets the PIN retry counter using a reset code.
//
// Access condition: None (reset code is required)
// See: OpenPGP Smart Card Application - Section 7.2.4 RESET RETRY COUNTER
func (tx *TX) ResetRetryCounterWithResettingCode(rc, newPw string) error {
	if len(newPw) < 6 {
		return ErrInvalidLength
	}

	_, err := send(tx.tx, iso.InsResetRetryCounter, 0x00, PW1, []byte(rc+newPw))
	return err
}

// SetRetryCounters sets the number of PIN attempts to allow before blocking.
//
// Access condition: Admin/PW3
// Note: This is a YubiKey extensions
// Warning: On YubiKey NEO this will reset the PINs to their default values.
func (tx *TX) SetRetryCounters(pw1, rc, pw3 byte) error {
	_, err := send(tx.tx, insSetPINRetries, 0, 0, []byte{pw1, rc, pw3})
	return err
}

func (tx *TX) SetUserInteractionMode(op SecurityOperation, mode UserInteractionMode, feat GeneralFeatures) error {
	uif := UIF{mode, feat}
	return tx.putData(tagUIFSign+tlv.Tag(op), uif.Encode())
}

type PasswordMode struct {
	RequirePW1ForEachSignature bool
	UsePINBlockFormat2ForPW1   bool
}

func (tx *TX) SetPasswordMode(mode PasswordMode) error {
	sts, err := tx.getData(tagPasswordStatus)
	if err != nil {
		return err
	}

	if mode.RequirePW1ForEachSignature {
		sts[0] = 0
	} else {
		sts[0] = 1
	}

	if mode.UsePINBlockFormat2ForPW1 {
		if tx.Capabilities.Pin2BlockFormat == 0 {
			return fmt.Errorf("PIN block 2 format is %w", ErrUnsupported)
		}

		sts[1] |= 0b1
	} else {
		sts[1] &= 0b1
	}

	return tx.putData(tagPasswordStatus, sts)
}
