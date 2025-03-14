// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"bytes"
	"crypto/des" //nolint:gosec
	"errors"
	"fmt"
	"io"

	iso "github.com/malivvan/pcsc/iso7816"
	"github.com/malivvan/pcsc/iso7816/tlv"
)

var errFailedToGenerateKey = errors.New("failed to generate random key")

// authenticate attempts to authenticate against the card with the provided
// management key. The management key is required to generate new keys or add
// certificates to slots.
//
// Use DefaultManagementKey if the management key hasn't been set.
func (tx *TX) authenticate(key ManagementKey) error {
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=92
	// https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=918402#page=114

	// Request a witness
	resp, err := sendTLV(tx.tx, iso.InsGeneralAuthenticate, byte(Alg3DES), keyCardManagement,
		tlv.New(0x7c,
			tlv.New(0x80),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	cardChallenge, _, ok := resp.GetChild(0x7c, 0x80)
	if !ok {
		return errUnmarshal
	} else if len(cardChallenge) != 8 {
		return errUnexpectedLength
	}

	block, err := des.NewTripleDESCipher(key[:]) //nolint:gosec
	if err != nil {
		return fmt.Errorf("failed to create triple des block cipher: %w", err)
	}

	cardResponse := make([]byte, 8)
	block.Decrypt(cardResponse, cardChallenge)

	challenge := make([]byte, 8)
	if _, err := io.ReadFull(tx.Rand, challenge); err != nil {
		return fmt.Errorf("failed to read random data: %w", err)
	}

	response := make([]byte, 8)
	block.Encrypt(response, challenge)

	if resp, err = sendTLV(tx.tx, iso.InsGeneralAuthenticate, byte(Alg3DES), keyCardManagement,
		tlv.New(0x7c,
			tlv.New(0x80, cardResponse),
			tlv.New(0x81, challenge),
		),
	); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	if cardResponse, _, ok = resp.GetChild(0x7c, 0x82); !ok {
		return errUnmarshal
	} else if len(cardResponse) != 8 {
		return errUnexpectedLength
	} else if !bytes.Equal(cardResponse, response) {
		return errChallengeFailed
	}

	return nil
}

// authenticateWithPIN uses a PIN protected management key to authenticate
// https://docs.yubico.com/yesdk/users-manual/application-piv/pin-only.html
// https://docs.yubico.com/yesdk/users-manual/application-piv/piv-objects.html#pinprotecteddata
//
//nolint:unused
func (tx *TX) authenticateWithPIN(pin string) error {
	ppd, err := tx.PinProtectedData(pin)
	if err != nil {
		return err
	}

	key, err := ppd.ManagementKey()
	if err != nil {
		return err
	}

	return tx.authenticate(key)
}

// SetManagementKey updates the management key to a new key. Management keys
// are triple-des keys, however padding isn't verified. To generate a new key,
// generate 24 random bytes.
//
//	var newKey ManagementKey
//	if _, err := io.ReadFull(rand.Reader, newKey[:]); err != nil {
//		// ...
//	}
//	if err := c.SetManagementKey(piv.DefaultManagementKey, newKey); err != nil {
//		// ...
//	}
func (tx *TX) SetManagementKey(oldKey, newKey ManagementKey) error {
	if err := tx.authenticate(oldKey); err != nil {
		return fmt.Errorf("failed to authenticate with old key: %w", err)
	}

	p2 := byte(0xff)
	touch := false // TODO
	if touch {
		p2 = 0xfe
	}

	if _, err := send(tx.tx, insSetManagementKey, 0xff, p2, append([]byte{
		byte(Alg3DES), keyCardManagement, 24,
	}, newKey[:]...)); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	return nil
}

// https://docs.yubico.com/yesdk/users-manual/application-piv/pin-only.html
// https://docs.yubico.com/yesdk/users-manual/application-piv/piv-objects.html#pinprotecteddata
func (tx *TX) SetManagementKeyPinProtected(oldKey ManagementKey, pin string) error {
	var newKey ManagementKey

	if n, err := tx.Rand.Read(newKey[:]); err != nil {
		return fmt.Errorf("failed to generate random key: %w", err)
	} else if n != len(DefaultManagementKey) {
		return errFailedToGenerateKey
	}

	ppd, err := tx.PinProtectedData(pin)
	if err != nil {
		return err
	}

	if err := ppd.SetManagementKey(newKey); err != nil {
		return err
	}

	if err := tx.SetPinProtectedData(oldKey, ppd); err != nil {
		return err
	}

	return tx.SetManagementKey(oldKey, newKey)
}

// SetPIN updates the PIN to a new value. For compatibility, PINs should be 1-8
// numeric characters.
//
// To generate a new PIN, use the crypto/rand package.
//
//	// Generate a 6 character PIN.
//	newPINInt, err := rand.Int(rand.Reader, bit.NewInt(1_000_000))
//	if err != nil {
//		// ...
//	}
//	// Format with leading zeros.
//	newPIN := fmt.Sprintf("%06d", newPINInt)
//	if err := c.SetPIN(piv.DefaultPIN, newPIN); err != nil {
//		// ...
//	}
func (tx *TX) SetPIN(oldPIN, newPIN string) error {
	oldPINData, err := encodePIN(oldPIN)
	if err != nil {
		return fmt.Errorf("failed to encode old PIN: %w", err)
	}

	newPINData, err := encodePIN(newPIN)
	if err != nil {
		return fmt.Errorf("failed to encode new PIN: %w", err)
	}

	if _, err = send(tx.tx, iso.InsChangeReferenceData, 0, 0x80, append(oldPINData, newPINData...)); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	return nil
}

// Unblock unblocks the PIN, setting it to a new value.
func (tx *TX) Unblock(puk, newPIN string) error {
	pukData, err := encodePIN(puk)
	if err != nil {
		return fmt.Errorf("failed to encode PUK: %w", err)
	}

	newPINData, err := encodePIN(newPIN)
	if err != nil {
		return fmt.Errorf("failed to encode new PIN: %w", err)
	}

	if _, err = send(tx.tx, iso.InsResetRetryCounter, 0, 0x80, append(pukData, newPINData...)); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	return nil
}

// SetPUK updates the PUK to a new value. For compatibility, PUKs should be 1-8
// numeric characters.
//
// To generate a new PUK, use the crypto/rand package.
//
//	// Generate a 8 character PUK.
//	newPUKInt, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
//	if err != nil {
//		// ...
//	}
//	// Format with leading zeros.
//	newPUK := fmt.Sprintf("%08d", newPUKInt)
//	if err := c.SetPUK(piv.DefaultPUK, newPUK); err != nil {
//		// ...
//	}
func (tx *TX) SetPUK(oldPUK, newPUK string) error {
	oldPUKData, err := encodePIN(oldPUK)
	if err != nil {
		return fmt.Errorf("failed to encode old PUK: %w", err)
	}

	newPUKData, err := encodePIN(newPUK)
	if err != nil {
		return fmt.Errorf("failed to encode new PUK: %w", err)
	}

	if _, err = send(tx.tx, iso.InsChangeReferenceData, 0, 0x81, append(oldPUKData, newPUKData...)); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	return nil
}

func encodePIN(pin string) ([]byte, error) {
	data := []byte(pin)
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: cannot be empty", errInvalidPinLength)
	}

	if len(data) > 8 {
		return nil, fmt.Errorf("%w: longer than 8 bytes", errInvalidPinLength)
	}

	// Apply padding
	for i := len(data); i < 8; i++ {
		data = append(data, 0xff)
	}

	return data, nil
}

// VerifyPIN attempts to authenticate against the card with the provided PIN.
//
// PIN authentication for other operations are handled separately, and VerifyPIN
// does not need to be called before those methods.
//
// After a specific number of authentication attempts with an invalid PIN,
// usually 3, the PIN will become block and refuse further attempts. At that
// point the PUK must be used to unblock the PIN.
//
// Use DefaultPIN if the PIN hasn't been set.
func (tx *TX) VerifyPIN(pin string) error {
	return login(tx.tx, pin)
}

func login(tx iso.TX, pin string) error {
	data, err := encodePIN(pin)
	if err != nil {
		return err
	}

	// https://csrc.nist.gov/CSRC/media/Publications/sp/800-73/4/archive/2015-05-29/documents/sp800_73-4_pt2_draft.pdf#page=20
	if _, err = send(tx, iso.InsVerify, 0, 0x80, data); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	return err
}

func loginNeeded(tx iso.TX) bool {
	_, err := send(tx, iso.InsVerify, 0, 0x80, nil)
	return err != nil
}

// Retries returns the number of attempts remaining to enter the correct PIN.
func (tx *TX) Retries() (int, error) {
	_, err := send(tx.tx, iso.InsVerify, 0, 0x80, nil)
	if err == nil {
		return 0, fmt.Errorf("%w from empty pin", errExpectedError)
	}

	var aErr AuthError
	if errors.As(err, &aErr) {
		return aErr.Retries, nil
	}

	return 0, fmt.Errorf("invalid response: %w", err)
}
