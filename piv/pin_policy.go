// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"errors"
	"fmt"

	iso "github.com/malivvan/pcsc/iso7816"
)

//nolint:gochecknoglobals
var (
	pinPolicyMap = map[PINPolicy]byte{
		PINPolicyNever:  0x01,
		PINPolicyOnce:   0x02,
		PINPolicyAlways: 0x03,
	}

	pinPolicyMapInv = map[byte]PINPolicy{
		0x01: PINPolicyNever,
		0x02: PINPolicyOnce,
		0x03: PINPolicyAlways,
	}
)

// PINPolicy represents PIN requirements when signing or decrypting with an
// asymmetric key in a given slot.
type PINPolicy int

// PIN policies supported by this package.
//
// BUG(ericchiang): Caching for PINPolicyOnce isn't supported on YubiKey
// versions older than 4.3.0 due to issues with verifying if a PIN is needed.
// If specified, a PIN will be required for every operation.
const (
	PINPolicyNever PINPolicy = iota + 1
	PINPolicyOnce
	PINPolicyAlways
)

func pinPolicy(c *TX, slot Slot) (PINPolicy, error) {
	v, _ := iso.ParseVersion("4.3.0")
	if !v.Less(c.Version()) {
		md, err := c.Metadata(slot)
		if err != nil {
			return 0, fmt.Errorf("failed to get key info: %w", err)
		}

		return md.PINPolicy, nil
	}

	cert, err := c.Attest(slot)
	if err != nil {
		var e *iso.Code
		if errors.As(err, &e) && *e == iso.ErrUnsupportedInstruction {
			// Attestation cert command not supported, probably an older YubiKey.
			// Guess PINPolicyAlways.
			//
			// See https://cunicu.li/go-piv/issues/55
			return PINPolicyAlways, nil
		}

		return 0, fmt.Errorf("failed to get attestation cert: %w", err)
	}

	a, err := parseAttestation(cert)
	if err != nil {
		return 0, fmt.Errorf("failed to parse attestation cert: %w", err)
	}

	if _, ok := pinPolicyMap[a.PINPolicy]; ok {
		return a.PINPolicy, nil
	}

	return PINPolicyOnce, nil
}
