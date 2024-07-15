// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package filter

import (
	"errors"
	iso "github.com/malivvan/pcsc/iso7816"
)

// ErrOpen is a sentinel error returned by a Filter indicating
// that the filter requires a connection to the card for checking
// its predicate.
// This is usually the case if the predicate needs to exchange
// APDUs with the card rather than simply checking the readers
// name
var ErrOpen = errors.New("open card for detailed filtering")

// Filter is a predicate which evaluates
// whether a given reader/card matches
// a given condition.
type Filter func(reader string, card iso.TX) (bool, error)

// Any matches any card
//
//nolint:gochecknoglobals
var Any Filter = func(string, iso.TX) (bool, error) {
	return true, nil
}

// None matches no card
//
//nolint:gochecknoglobals
var None Filter = func(string, iso.TX) (bool, error) {
	return false, nil
}

// HasApplet matches card which can select an applet
// with the given application identifier (AID).
func HasApplet(aid []byte) Filter {
	return func(reader string, tx iso.TX) (bool, error) {
		if tx == nil {
			return false, ErrOpen
		}

		if err := tx.Select(aid); err != nil {
			return false, nil //nolint:nilerr
		}

		return true, nil
	}
}
