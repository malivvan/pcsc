// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"io"

	iso "github.com/malivvan/pcsc/iso7816"
	"github.com/malivvan/pcsc/iso7816/tlv"
)

type keyEd25519 struct {
	c    *TX
	slot Slot
	pub  ed25519.PublicKey
	auth KeyAuth
	pp   PINPolicy
}

func (k *keyEd25519) Public() crypto.PublicKey {
	return k.pub
}

// This function only works on SoloKeys prototypes and other PIV devices that choose
// to implement Ed25519 signatures under alg 0x22.
func (k *keyEd25519) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return k.auth.do(k.c, k.pp, func(tx iso.TX) ([]byte, error) {
		return signEd25519(tx, k.slot, digest)
	})
}

func decodeEd25519Public(tvs tlv.TagValues) (ed25519.PublicKey, error) {
	// Adaptation of
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	p, _, ok := tvs.Get(0x86)
	if !ok {
		return nil, fmt.Errorf("%w points", errUnmarshal)
	}

	if len(p) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w of points: %d", errUnexpectedLength, len(p))
	}

	return ed25519.PublicKey(p), nil
}

func signEd25519(tx iso.TX, slot Slot, data []byte) ([]byte, error) {
	// Adaptation of
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=118
	resp, err := sendTLV(tx, iso.InsGeneralAuthenticate, byte(AlgEd25519), slot.Key,
		tlv.New(0x7c,
			tlv.New(0x82),
			tlv.New(0x81, data),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}

	rs, _, ok := resp.GetChild(0x7c, 0x82)
	if !ok {
		return nil, fmt.Errorf("%w response signature: missing tag", errUnmarshal)
	}

	return rs, nil
}
