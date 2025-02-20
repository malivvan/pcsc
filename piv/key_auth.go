// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"fmt"

	iso "github.com/malivvan/pcsc/iso7816"
)

// KeyAuth is used to authenticate against the card on each signing  and
// decryption request.
type KeyAuth struct {
	// PIN, if provided, is a static PIN used to authenticate against the key.
	// If provided, PINPrompt is ignored.
	PIN string

	// PINPrompt can be used to interactively request the PIN from the user. The
	// method is only called when needed. For example, if a key specifies
	// PINPolicyOnce, PINPrompt will only be called once per card struct.
	PINPrompt func() (pin string, err error)

	// PINPolicy can be used to specify the PIN caching strategy for the slot. If
	// not provided, this will be inferred from the attestation certificate.
	//
	// This field is required on older (<4.3.0) YubiKeys when using PINPrompt,
	// as well as for keys imported to the card.
	PINPolicy PINPolicy
}

func (k KeyAuth) authTx(c *TX, pp PINPolicy) error {
	// PINPolicyNever shouldn't require a PIN.
	if pp == PINPolicyNever {
		return nil
	}

	// PINPolicyAlways should always prompt a PIN even if the key says that
	// login isn't needed.
	// https://cunicu.li/go-piv/issues/49
	if pp != PINPolicyAlways && !loginNeeded(c.tx) {
		return nil
	}

	pin := k.PIN
	if pin == "" && k.PINPrompt != nil {
		p, err := k.PINPrompt()
		if err != nil {
			return fmt.Errorf("failed to get PIN from prompt: %w", err)
		}
		pin = p
	}
	if pin == "" {
		return errMissingPIN
	}

	return login(c.tx, pin)
}

func (k KeyAuth) do(c *TX, pp PINPolicy, f func(tx iso.TX) ([]byte, error)) ([]byte, error) {
	if err := k.authTx(c, pp); err != nil {
		return nil, err
	}

	return f(c.tx)
}
