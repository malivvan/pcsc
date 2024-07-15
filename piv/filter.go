// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"github.com/malivvan/pcsc/yubikey"
)

//nolint:gochecknoglobals
var (
	SupportsAttestation    = yubikey.HasVersionStr("4.3.0")
	SupportsMetadata       = yubikey.HasVersionStr("5.3.0")
	SupportsAlgorithmEC384 = yubikey.HasVersionStr("4.3.0")
)
