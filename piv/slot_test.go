// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

//
////nolint:gocognit
//func TestSlots(t *testing.T) {
//	tests := []struct {
//		name string
//		slot Slot
//	}{
//		{"Authentication", SlotAuthentication},
//		{"CardAuthentication", SlotCardAuthentication},
//		{"KeyManagement", SlotKeyManagement},
//		{"Signature", SlotSignature},
//	}
//
//	for _, test := range tests {
//		t.Run(test.name, func(t *testing.T) {
//			withCard(t, true, false, nil, func(t *testing.T, c *TX) {
//				if c.SupportsAttestation() {
//					_, err := c.Attest(test.slot)
//					assert.ErrorIs(t, err, ErrNotFound)
//				}
//				k := Key{
//					Algorithm:   AlgECCP256,
//					PINPolicy:   PINPolicyNever,
//					TouchPolicy: TouchPolicyNever,
//				}
//				pub, err := c.GenerateKey(DefaultManagementKey, test.slot, k)
//				require.NoError(t, err, "Failed to generate key on slot")
//
//				if c.SupportsAttestation() {
//					_, err := c.Attest(test.slot)
//					assert.NoError(t, err, "Failed to attest")
//				}
//
//				priv, err := c.PrivateKey(test.slot, pub, KeyAuth{PIN: DefaultPIN})
//				require.NoError(t, err, "Failed to get private key")
//
//				tmpl := &x509.Certificate{
//					Subject:      pkix.Name{CommonName: "my-client"},
//					SerialNumber: big.NewInt(1),
//					KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
//					ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
//				}
//
//				// Certificate must be deterministic for
//				// reproducible tests
//				tmpl.NotBefore, _ = time.Parse(time.DateOnly, "2020-01-01")
//				tmpl.NotAfter, _ = time.Parse(time.DateOnly, "2030-01-01")
//
//				raw, err := x509.CreateCertificate(c.Rand, tmpl, tmpl, pub, priv)
//				require.NoError(t, err, "Failed to sign self-signed certificate")
//
//				cert, err := x509.ParseCertificate(raw)
//				require.NoError(t, err, "Failed to parse certificate")
//
//				_, err = c.Certificate(test.slot)
//				assert.ErrorIs(t, err, ErrNotFound)
//
//				err = c.SetCertificate(DefaultManagementKey, test.slot, cert)
//				require.NoError(t, err, "Failed to set certificate")
//
//				got, err := c.Certificate(test.slot)
//				require.NoError(t, err, "Failed to get certificate")
//
//				assert.Equal(t, raw, got.Raw, "Certificate from slot didn't match the certificate written")
//			})
//		})
//	}
//}
//
//func TestParseSlot(t *testing.T) {
//	retiredSlot89, _ := SlotRetiredKeyManagement(0x89)
//
//	tests := []struct {
//		name string
//		cn   string
//		ok   bool
//		slot Slot
//	}{
//		{
//			name: "Invalid/Missing Yubico PIV Prefix",
//			cn:   "invalid",
//			ok:   false,
//			slot: Slot{},
//		},
//		{
//			name: "Invalid/Slot Name",
//			cn:   yubikeySubjectCNPrefix + "xy",
//			ok:   false,
//			slot: Slot{},
//		},
//		{
//			name: "Valid/SlotAuthentication",
//			cn:   yubikeySubjectCNPrefix + "9a",
//			ok:   true,
//			slot: SlotAuthentication,
//		},
//		{
//			name: "Valid/Retired Management Key",
//			cn:   yubikeySubjectCNPrefix + "89",
//			ok:   true,
//			slot: retiredSlot89,
//		},
//	}
//
//	for _, test := range tests {
//		t.Run(test.name, func(t *testing.T) {
//			gotSlot, gotOk := parseSlot(test.cn)
//			assert.Equal(t, test.ok, gotOk)
//			assert.Equal(t, test.slot, gotSlot, "Returned slot %+v did not match expected %+v", gotSlot, test.slot)
//		})
//	}
//}
//
//func TestRetiredKeyManagementSlot(t *testing.T) {
//	firstRetiredSlot, _ := SlotRetiredKeyManagement(0x82)
//	lastRetiredSlot, _ := SlotRetiredKeyManagement(0x95)
//
//	tests := []struct {
//		name     string
//		key      byte
//		wantSlot Slot
//		wantOk   bool
//	}{
//		{
//			name:     "Non-existent slot, before range",
//			key:      0x0,
//			wantSlot: Slot{},
//			wantOk:   false,
//		},
//		{
//			name:     "Non-existent slot, after range",
//			key:      0x96,
//			wantSlot: Slot{},
//			wantOk:   false,
//		},
//		{
//			name:     "First retired slot key",
//			key:      0x82,
//			wantSlot: firstRetiredSlot,
//			wantOk:   true,
//		},
//		{
//			name:     "Last retired slot key",
//			key:      0x95,
//			wantSlot: lastRetiredSlot,
//			wantOk:   true,
//		},
//	}
//	for _, test := range tests {
//		t.Run(test.name, func(t *testing.T) {
//			gotSlot, gotOk := SlotRetiredKeyManagement(test.key)
//			assert.Equal(t, test.wantSlot, gotSlot)
//			assert.Equal(t, test.wantOk, gotOk)
//		})
//	}
//}
