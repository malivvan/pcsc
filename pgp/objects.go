// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"time"

	iso "github.com/malivvan/pcsc/iso7816"
	"github.com/malivvan/pcsc/iso7816/tlv"
)

// KDF contains the Parameters for the Key Derivation Function (KDF).
type KDF struct {
	Algorithm      AlgKDF
	HashAlgorithm  AlgHash
	Iterations     int
	SaltPW1        [8]byte
	SaltPW3        [8]byte
	SaltRC         [8]byte
	InitialHashPW1 []byte
	InitialHashPW3 []byte
}

func (k *KDF) Decode(b []byte) (err error) {
	tvs, err := tlv.DecodeBER(b)
	if err != nil {
		return err
	}

	for _, tv := range tvs {
		switch tv.Tag {
		case 0x81:
			if len(tv.Value) != 1 {
				return ErrInvalidLength
			}

			k.Algorithm = AlgKDF(tv.Value[0])

		case 0x82:
			if len(tv.Value) != 1 {
				return ErrInvalidLength
			}

			k.HashAlgorithm = AlgHash(tv.Value[0])

		case 0x83:
			if len(tv.Value) != 4 {
				return ErrInvalidLength
			}

			k.Iterations = int(binary.BigEndian.Uint32(tv.Value))

		case 0x84:
			if len(tv.Value) != 8 {
				return ErrInvalidLength
			}

			k.SaltPW1 = [8]byte(tv.Value)

		case 0x85:
			if len(tv.Value) != 8 {
				return ErrInvalidLength
			}

			k.SaltRC = [8]byte(tv.Value)

		case 0x86:
			if len(tv.Value) != 8 {
				return ErrInvalidLength
			}

			k.SaltPW3 = [8]byte(tv.Value)

		case 0x87:
			k.InitialHashPW1 = tv.Value

		case 0x88:
			k.InitialHashPW3 = tv.Value

		default:
			slog.Warn("Received unknown tag",
				slog.String("do", "kdf"),
				slog.Any("tag", tv.Tag),
				slog.String("value", hex.EncodeToString(tv.Value)))
		}
	}

	return nil
}

func (k *KDF) Encode() ([]byte, error) {
	parts := []tlv.TagValue{
		tlv.New(0x81, byte(k.Algorithm)),
	}

	switch k.Algorithm {
	case AlgKDFNone:

	case AlgKDFIterSaltedS2K:
		parts = append(parts,
			tlv.New(0x82, byte(k.HashAlgorithm)),
			tlv.New(0x83, uint32(k.Iterations)),
			tlv.New(0x84, k.SaltPW1[:]),
			tlv.New(0x85, k.SaltRC[:]),
			tlv.New(0x86, k.SaltPW3[:]),
			tlv.New(0x87, k.InitialHashPW1),
			tlv.New(0x88, k.InitialHashPW3),
		)

	default:
		return nil, ErrUnsupported
	}

	return tlv.EncodeBER(parts...)
}

// UIF configures the required user interaction for certain security operations.
type UIF struct {
	Mode    UserInteractionMode
	Feature GeneralFeatures
}

func (uif *UIF) Decode(b []byte) error {
	if len(b) != 2 {
		return ErrInvalidLength
	}

	uif.Mode = UserInteractionMode(b[0])
	uif.Feature = GeneralFeatures(b[1])

	return nil
}

func (uif UIF) Encode() []byte {
	return []byte{byte(uif.Mode), byte(uif.Feature)}
}

type ImportFormat byte

const (
	ImportFormatRSAStd ImportFormat = iota
	ImportFormatRSAStdWithModulus
	ImportFormatRSACRT
	ImportFormatRSACRTWithModulus

	ImportFormatECDSAStdWithPublicKey ImportFormat = 0xff
)

type Fingerprint [20]byte

type KeyStatus byte

const (
	KeyNotPresent KeyStatus = iota // Not generated or imported
	KeyGenerated                   // On the the card
	KeyImported                    // Into the card (insecure)
)

type KeyInfo struct {
	Reference      KeyRef
	Status         KeyStatus
	AlgAttrs       AlgorithmAttributes
	Fingerprint    []byte
	FingerprintCA  []byte
	GenerationTime time.Time
	UIF            UIF
}

type ApplicationRelated struct {
	AID             AID
	HistoricalBytes iso.HistoricalBytes

	LengthInfo     ExtendedLengthInfo
	Capabilities   ExtendedCapabilities
	Features       GeneralFeatures
	PasswordStatus PasswordStatus

	Keys map[KeyRef]KeyInfo
}

//nolint:gocognit
func (ar *ApplicationRelated) Decode(b []byte) (err error) {
	tvs, err := tlv.DecodeBER(b)
	if err != nil {
		return err
	}

	_, tvs, ok := tvs.Get(tagApplicationRelated)
	if !ok {
		return errMissingTag
	}

	for _, tv := range tvs {
		switch tv.Tag {
		case tagAID:
			if err := ar.AID.Decode(tv.Value); err != nil {
				return fmt.Errorf("failed to decode application identifier: %w", err)
			}

		case tagHistoricalBytes:
			if err := ar.HistoricalBytes.Decode(tv.Value); err != nil {
				return fmt.Errorf("failed to decode historical bytes: %w", err)
			}

		case tagGeneralFeatureManagement:
			if err := ar.Features.Decode(tv.Value); err != nil {
				return fmt.Errorf("failed to decode general features: %w", err)
			}

		case tagDiscretionaryDOs:
			var keySign, keyDecrypt, keyAuthn, keyAttest KeyInfo

			for _, tv := range tv.Children {
				switch tv.Tag {
				case tagExtendedLengthInfo:
					if err := ar.LengthInfo.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode extended length information: %w", err)
					}

				case tagExtendedCapabilities:
					if err := ar.Capabilities.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode extended capabilities: %w", err)
					}

				case tagAlgAttrsSign:
					if err := keySign.AlgAttrs.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode sign key attrs: %w", err)
					}

				case tagAlgAttrsDecrypt:
					if err := keyDecrypt.AlgAttrs.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode decrypt key attrs: %w", err)
					}

				case tagAlgAttrsAuthn:
					if err := keyAuthn.AlgAttrs.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode authentication key attrs: %w", err)
					}

				case tagAlgAttrsAttest:
					if err := keyAttest.AlgAttrs.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode attestation key attrs: %w", err)
					}

				case tagUIFSign:
					if err := keySign.UIF.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode user interaction flag: %w", err)
					}

				case tagUIFAuthn:
					if err := keyAuthn.UIF.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode user interaction flag: %w", err)
					}

				case tagUIFDecrypt:
					if err := keyDecrypt.UIF.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode user interaction flag: %w", err)
					}

				case tagUIFAttest:
					if err := keyAttest.UIF.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode user interaction flag: %w", err)
					}

				case tagPasswordStatus:
					if err := ar.PasswordStatus.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode password status: %w", err)
					}

				case tagFpr:
					if len(tv.Value) < 60 {
						return ErrInvalidLength
					}

					keySign.Fingerprint = tv.Value[0:20]
					keyDecrypt.Fingerprint = tv.Value[20:40]
					keyAuthn.Fingerprint = tv.Value[40:60]

				case tagFprAttest:
					if len(tv.Value) < 20 {
						return ErrInvalidLength
					}

					keyAttest.Fingerprint = tv.Value[0:20]

				case tagFprCA:
					if len(tv.Value) < 60 {
						return ErrInvalidLength
					}

					keySign.FingerprintCA = tv.Value[0:20]
					keyDecrypt.FingerprintCA = tv.Value[20:40]
					keyAuthn.FingerprintCA = tv.Value[40:60]

				case tagFprCAAttest:
					if len(tv.Value) < 20 {
						return ErrInvalidLength
					}

					keyAttest.FingerprintCA = tv.Value[0:20]

				case tagGenTime:
					if len(tv.Value) < 12 {
						return ErrInvalidLength
					}

					keySign.GenerationTime = decodeTime(tv.Value[0:])
					keyDecrypt.GenerationTime = decodeTime(tv.Value[4:])
					keyAuthn.GenerationTime = decodeTime(tv.Value[8:])

				case tagGenTimeAttest:
					if len(tv.Value) < 4 {
						return ErrInvalidLength
					}

					keyAttest.GenerationTime = decodeTime(tv.Value[0:])

				case tagKeyInfo:
					keySign.Reference = KeyRef(tv.Value[0])
					keySign.Status = KeyStatus(tv.Value[1])
					keyDecrypt.Reference = KeyRef(tv.Value[2])
					keyDecrypt.Status = KeyStatus(tv.Value[3])
					keyAuthn.Reference = KeyRef(tv.Value[4])
					keyAuthn.Status = KeyStatus(tv.Value[5])

					if len(tv.Value) >= 8 {
						keyAttest.Reference = KeyRef(tv.Value[6])
						keyAttest.Status = KeyStatus(tv.Value[7])
					}

				default:
					slog.Warn("Received unknown tag",
						slog.String("do", "discretionary objects"),
						slog.Any("tag", tv.Tag),
						slog.String("value", hex.EncodeToString(tv.Value)))
				}
			}

			ar.Keys = map[KeyRef]KeyInfo{
				KeySign:    keySign,
				KeyDecrypt: keyDecrypt,
				KeyAuthn:   keyAuthn,
			}

		default:
			slog.Warn("Received unknown tag",
				slog.String("do", "application related"),
				slog.Any("tag", tv.Tag),
				slog.String("value", hex.EncodeToString(tv.Value)))
		}
	}

	return nil
}

type PasswordStatus struct {
	ValidityPW1 uint8

	LengthPW1 uint8
	LengthRC  uint8
	LengthPW3 uint8

	AttemptsPW1 uint8
	AttemptsRC  uint8
	AttemptsPW3 uint8
}

func (ps *PasswordStatus) Decode(b []byte) error {
	if len(b) != 7 {
		return ErrInvalidLength
	}

	ps.ValidityPW1 = b[0]
	ps.LengthPW1 = b[1]
	ps.LengthRC = b[2]
	ps.LengthPW3 = b[3]
	ps.AttemptsPW1 = b[4]
	ps.AttemptsRC = b[5]
	ps.AttemptsPW3 = b[6]

	return nil
}

type ExtendedCapabilities struct {
	Flags                ExtendedCapabilitiesFlag
	AlgSM                byte
	MaxLenChallenge      uint16
	MaxLenCardholderCert uint16
	MaxLenSpecialDO      uint16
	Pin2BlockFormat      byte
	CommandMSE           byte
}

type ExtendedCapabilitiesFlag byte

const (
	CapKDF ExtendedCapabilitiesFlag = (1 << iota)
	CapAES
	CapAlgAttrsChangeable
	CapPrivateDO
	CapPasswordStatusChangeable
	CapKeyImport
	CapGetChallenge
	CapSecureMessaging
)

func (ec *ExtendedCapabilities) Decode(b []byte) error {
	if len(b) != 10 {
		return ErrInvalidLength
	}

	ec.Flags = ExtendedCapabilitiesFlag(b[0])
	ec.AlgSM = b[1]
	ec.MaxLenChallenge = binary.BigEndian.Uint16(b[2:])
	ec.MaxLenCardholderCert = binary.BigEndian.Uint16(b[4:])
	ec.MaxLenSpecialDO = binary.BigEndian.Uint16(b[6:])
	ec.Pin2BlockFormat = b[8]
	ec.CommandMSE = b[9]

	return nil
}

type Cardholder struct {
	Name     string
	Language string
	Sex      Sex
}

func (ch *Cardholder) Decode(b []byte) (err error) {
	tvs, err := tlv.DecodeBER(b)
	if err != nil {
		return err
	}

	_, tvs, ok := tvs.Get(tagCardholderRelated)
	if !ok {
		return errMissingTag
	}

	for _, tv := range tvs {
		switch tv.Tag {
		case tagName:
			ch.Name = string(tv.Value)
		case tagSex:
			if len(tv.Value) < 1 {
				return ErrInvalidLength
			}
			ch.Sex = Sex(tv.Value[0])
		case tagLanguage:
			ch.Language = string(tv.Value)
		default:
			slog.Warn("Received unknown tag",
				slog.String("do", "cardholder related"),
				slog.Any("tag", tv.Tag),
				slog.String("value", hex.EncodeToString(tv.Value)))
		}
	}

	return nil
}

type SecuritySupportTemplate struct {
	SignatureCounter int
	CardHolderCerts  [3][]byte
}

func (sst *SecuritySupportTemplate) Decode(b []byte) (err error) {
	tvs, err := tlv.DecodeBER(b)
	if err != nil {
		return err
	}

	_, tvs, ok := tvs.Get(tagSecuritySupportTemplate)
	if !ok {
		return errMissingTag
	}

	for _, tv := range tvs {
		switch tv.Tag {
		case tagDSCounter:
			buf := append([]byte{0}, tv.Value...)
			sst.SignatureCounter = int(binary.BigEndian.Uint32(buf))

		case tagCerts:
			log.Println(hex.EncodeToString(tv.Value))

		default:
			slog.Warn("Received unknown tag",
				slog.String("do", "security support template"),
				slog.Any("tag", tv.Tag),
				slog.String("value", hex.EncodeToString(tv.Value)))
		}
	}

	return nil
}

type GeneralFeatures byte

const (
	GeneralFeatureTouchscreen byte = (1 << iota)
	GeneralFeatureMicrophone
	GeneralFeatureSpeaker
	GeneralFeatureLED
	GeneralFeatureKeyPad
	GeneralFeatureButton
	GeneralFeatureBiometric
	GeneralFeatureDisplay
)

func (gf *GeneralFeatures) Decode(b []byte) error {
	if len(b) < 1 {
		return ErrInvalidLength
	}

	*gf = GeneralFeatures(b[0])

	return nil
}

type AID struct {
	RID          iso.RID
	Application  byte
	Version      iso.Version
	Serial       [4]byte
	Manufacturer Manufacturer
}

func (aid *AID) Decode(b []byte) error {
	if len(b) != 16 {
		return ErrInvalidLength
	}

	aid.RID = [5]byte(b[0:5])
	aid.Application = b[5]
	aid.Version = iso.Version{
		Major: int(b[6]),
		Minor: int(b[7]),
	}
	aid.Manufacturer = Manufacturer(binary.BigEndian.Uint16(b[8:10]))
	aid.Serial = [4]byte(b[10:14])

	return nil
}

type ExtendedLengthInfo struct {
	MaxCommandLength  uint16
	MaxResponseLength uint16
}

func (li *ExtendedLengthInfo) Decode(b []byte) error {
	if len(b) != 8 {
		return ErrInvalidLength
	}

	li.MaxCommandLength = binary.BigEndian.Uint16(b[2:4])
	li.MaxResponseLength = binary.BigEndian.Uint16(b[6:8])

	return nil
}

func decodeTime(b []byte) time.Time {
	tsc := binary.BigEndian.Uint32(b)
	return time.Unix(int64(tsc), 0)
}
