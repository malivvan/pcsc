// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package filter

import (
	"regexp"

	iso "github.com/malivvan/pcsc/iso7816"
)

// HasName compares the name of the smart card reader
// with the provided name.
func HasName(nameExpected string) Filter {
	return func(reader string, tx iso.TX) (bool, error) {
		return reader == nameExpected, nil
	}
}

// HasName matches the name of the smart card reader
// against the provided regular expression.
func HasNameRegex(regex string) Filter {
	re := regexp.MustCompile(regex)
	return func(reader string, tx iso.TX) (bool, error) {
		return re.MatchString(reader), nil
	}
}

// IsYubikey checks if the smart card is a YubiKey
// based on the name of the smart card reader.
func IsYubiKey(reader string, tx iso.TX) (bool, error) {
	return HasNameRegex("(?i)YubiKey")(reader, tx)
}

// IsNikrokey checks if the smart card is a Nitrokey
// based on the name of the smart card reader.
func IsNitrokey(reader string, tx iso.TX) (bool, error) {
	return HasNameRegex("(?i)Nitrokey")(reader, tx)
}

// IsNikrokey3 checks if the smart card is a Nitrokey 3
// based on the name of the smart card reader.
func IsNitrokey3(reader string, tx iso.TX) (bool, error) {
	return HasNameRegex("Nitrokey 3")(reader, tx)
}
