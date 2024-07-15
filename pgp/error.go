// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp

import (
	"errors"
	"fmt"

	iso "github.com/malivvan/pcsc/iso7816"
)

var (

	// ErrMismatchingAlgorithms is returned when a cryptographic operation
	// is given keys using different algorithms.
	ErrMismatchingAlgorithms = errors.New("mismatching key algorithms")
	ErrInvalidLength         = errors.New("invalid length")
	errMissingTag            = errors.New("missing tag")
	errOutOfMemory           = errors.New("out of memory (basic card)")
	errSecurity              = errors.New("security related issue")
	ErrUnsupported           = errors.New("unsupported")
	ErrUnsupportedKeyType    = fmt.Errorf("%w key attributes", ErrUnsupported)
	ErrUnsupportedCurve      = fmt.Errorf("%w curve", ErrUnsupported)
	errUnmarshal             = errors.New("failed to unmarshal")
	errKeyNotPresent         = errors.New("key not present")
	ErrAlgAttrsNotChangeable = errors.New("algorithm attributes are not changeable")
	errChallengeTooLong      = fmt.Errorf("%w: challenge too long", ErrInvalidLength)
)

// AuthError is an error indicating an authentication error occurred (wrong PIN or blocked).
type AuthError struct {
	// Retries is the number of retries remaining if this error resulted from a retry-able
	// authentication attempt.  If the authentication method is blocked or does not support
	// retries, this will be 0.
	Retries int
}

func (v AuthError) Error() string {
	r := "retries"
	if v.Retries == 1 {
		r = "retry"
	}
	return fmt.Sprintf("verification failed (%d %s remaining)", v.Retries, r)
}

func wrapCode(err error) error {
	c, ok := err.(iso.Code) //nolint:errorlint
	if !ok {
		return err
	}

	switch {
	case c == iso.Code{0x64, 0x0E}:
		return errOutOfMemory

	case c == iso.Code{0x66, 0x00}:
		return errSecurity

	case c[0] == 0x63 && c[1]&0xf0 == 0xc0:
		return AuthError{int(c[1] & 0xf)}
	}

	return err
}
