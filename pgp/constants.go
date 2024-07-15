// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//nolint:unused,gochecknoglobals
package pgp

import (
	"crypto/ecdh"
	"crypto/elliptic"

	iso "github.com/malivvan/pcsc/iso7816"
	"github.com/malivvan/pcsc/iso7816/tlv"
)

const unknown = "<unknown>"

type AlgPubkey byte

const (
	AlgPubkeyRSA                AlgPubkey = 1  // RSA (Encrypt or Sign)
	AlgPubkeyRSAEncOnly         AlgPubkey = 2  // RSA Encrypt-Only (legacy)
	AlgPubkeyRSASignOnly        AlgPubkey = 3  // RSA Sign-Only (legacy)
	AlgPubkeyElgamalEncOnly     AlgPubkey = 16 // Elgamal (Encrypt-Only)
	AlgPubkeyDSA                AlgPubkey = 17 // DSA (Digital Signature Algorithm)
	AlgPubkeyECDH               AlgPubkey = 18 // RFC-6637
	AlgPubkeyECDSA              AlgPubkey = 19 // RFC-6637
	AlgPubkeyElgamalEncSignOnly AlgPubkey = 20 // Elgamal encrypt+sign, reserved by OpenPGP (legacy)
	AlgPubkeyEdDSA              AlgPubkey = 22 // EdDSA
	AlgPubkeyKy768_25519        AlgPubkey = 29 // Kyber768 + X25519
	AlgPubkeyKy1024_448         AlgPubkey = 30 // Kyber1024 + X448
	AlgPubkeyDil3_25519         AlgPubkey = 35 // Dilithium3 + Ed25519
	AlgPubkeyDil5_448           AlgPubkey = 36 // Dilithium5 + Ed448
	AlgPubkeySPHINXSHA2         AlgPubkey = 41 // SPHINX+-simple-SHA2
)

func (a AlgPubkey) String() string {
	switch a {
	case AlgPubkeyRSA:
		return "RSA"
	case AlgPubkeyRSAEncOnly:
		return "RSA (encrypt)"
	case AlgPubkeyRSASignOnly:
		return "RSA (sign)"
	case AlgPubkeyElgamalEncSignOnly:
		return "Elgamal"
	case AlgPubkeyElgamalEncOnly:
		return "Elgamal (encrypt)"
	case AlgPubkeyDSA:
		return "DSA"
	case AlgPubkeyECDH:
		return "ECDH"
	case AlgPubkeyECDSA:
		return "ECDSA"
	case AlgPubkeyEdDSA:
		return "EdDSA"
	case AlgPubkeyKy768_25519:
		return "Kyber 768+X25519"
	case AlgPubkeyKy1024_448:
		return "Kyber 1024+X448"
	case AlgPubkeyDil3_25519:
		return "Dilithium3+X25519"
	case AlgPubkeyDil5_448:
		return "Dilithium5+448"
	case AlgPubkeySPHINXSHA2:
		return "SPHINX+-simple-SHA2"
	}

	return "Unknown"
}

type AlgKDF byte

const (
	AlgKDFNone          AlgKDF = 0
	AlgKDFIterSaltedS2K AlgKDF = 3
)

type AlgHash byte

const (
	AlgHashMD5       AlgHash = iota + 1 // Message Digest 5
	AlgHashSHA1                         // SHA-1
	AlgHashRIPEMD160                    // RIPE-MD/160
	_                                   // Reserved
	_                                   // Reserved
	_                                   // Reserved
	_                                   // Reserved
	AlgHashSHA256                       // SHA-256
	AlgHashSHA384                       // SHA-384
	AlgHashSHA512                       // SHA-512
	AlgHashSHA224                       // SHA-224
)

type AlgSymmetric byte

const (
	AlgSymPlaintext AlgSymmetric = iota // Plaintext or unencrypted data
	AlgSymIDEA                          // IDEA
	AlgSymTripleDES                     // TripleDES (DES-EDE, - 168 bit key derived from 192)
	AlgSymCAST5                         // CAST5 (128 bit key, as per RFC2144)
	AlgSymBlowfish                      // Blowfish (128 bit key, 16 rounds)
	_                                   // Reserved
	_                                   // Reserved
	AlgSymAES128                        // AES with 128-bit key
	AlgSymAES192                        // AES with 192-bit key
	AlgSymAES256                        // AES with 256-bit key
	AlgSymTwofish                       // Twofish with 256-bit key
)

type Sex byte

const (
	SexUnknown       Sex = '0'
	SexMale          Sex = '1'
	SexFemale        Sex = '2'
	SexNotApplicable Sex = '9'
)

func (s Sex) String() string {
	switch s {
	case SexMale:
		return "Male"
	case SexFemale:
		return "Female"
	case SexNotApplicable:
		return "Not Applicable"
	case SexUnknown:
		return "Unknown"
	}

	return ""
}

type KeyRef byte

const (
	KeySign    KeyRef = 0x01
	KeyDecrypt KeyRef = 0x02
	KeyAuthn   KeyRef = 0x03
	KeyAttest  KeyRef = 0x81
)

func (r KeyRef) String() string {
	switch r {
	case KeySign:
		return "sign"
	case KeyDecrypt:
		return "decrypt"
	case KeyAuthn:
		return "authenticate"
	case KeyAttest:
		return "attest"
	default:
		return unknown
	}
}

func (r KeyRef) tagAlgAttrs() tlv.Tag {
	switch r {
	case KeySign:
		return tagAlgAttrsSign
	case KeyDecrypt:
		return tagAlgAttrsDecrypt
	case KeyAuthn:
		return tagAlgAttrsAuthn
	case KeyAttest:
		return tagAlgAttrsAttest
	default:
		return 0
	}
}

func (r KeyRef) tagGenTime() tlv.Tag {
	switch r {
	case KeySign:
		return tagGenTimeSign
	case KeyDecrypt:
		return tagGenTimeDecrypt
	case KeyAuthn:
		return tagGenTimeAuthn
	case KeyAttest:
		return tagGenTimeAttest
	default:
		return 0
	}
}

func (r KeyRef) tagFpr() tlv.Tag {
	switch r {
	case KeySign:
		return tagFprSign
	case KeyDecrypt:
		return tagFprDecrypt
	case KeyAuthn:
		return tagFprAuthn
	case KeyAttest:
		return tagFprAttest
	default:
		return 0
	}
}

// crt returns the control reference template
// See: OpenPGP Smart Card Application - Section 7.2.14 GENERATE ASYMMETRIC KEY PAIR
func (r KeyRef) crt() tlv.TagValue {
	return tlv.TagValue{
		Tag:   r.tag(),
		Value: []byte{0x84, 0x01, byte(r)},
	}
}

func (r KeyRef) tag() tlv.Tag {
	switch r {
	case KeySign, KeyAttest:
		return tlv.Tag(0xB6)
	case KeyDecrypt:
		return tlv.Tag(0xB8)
	case KeyAuthn:
		return tlv.Tag(0xA4)
	default:
		return 0
	}
}

type UserInteractionMode byte

const (
	UserInteractionDisabled     UserInteractionMode = 0x00
	UserInteractionEnabled      UserInteractionMode = 0x01
	UserInteractionEnabledFixed UserInteractionMode = 0x02
	UserInteractionCached       UserInteractionMode = 0x03
	UserInteractionCachedFixed  UserInteractionMode = 0x04
)

// See: OpenPGP Smart Card Application - Section 6 Historical Bytes
type LifeCycleStatus byte

const (
	LifeCycleStatusNoInfo      LifeCycleStatus = 0x00
	LifeCycleStatusInitialized LifeCycleStatus = 0x03
	LifeCycleStatusOperational LifeCycleStatus = 0x05
)

type SecurityOperation byte

const (
	SecurityOperationSign         SecurityOperation = iota
	SecurityOperationAuthenticate                   // Authentication
	SecurityOperationDecrypt                        // Confidentiality
	SecurityOperationAttest
)

type Curve byte

const (
	CurveUnknown Curve = iota

	CurveANSIx9p256r1
	CurveANSIx9p384r1
	CurveANSIx9p521r1

	CurveBrainpoolP256r1
	CurveBrainpoolP384r1
	CurveBrainpoolP512r1

	CurveX25519
	CurveX448

	CurveEd25519
	CurveEd448

	CurveSecp256k1
)

func (c Curve) String() string {
	switch c {
	case CurveANSIx9p256r1:
		return "ANSIx9p256r1"
	case CurveANSIx9p384r1:
		return "ANSIx9p384r1"
	case CurveANSIx9p521r1:
		return "ANSIx9p521r1"
	case CurveBrainpoolP256r1:
		return "BrainpoolP256r1"
	case CurveBrainpoolP384r1:
		return "BrainpoolP384r1"
	case CurveBrainpoolP512r1:
		return "BrainpoolP512r1"
	case CurveX25519:
		return "X25519"
	case CurveX448:
		return "X448"
	case CurveEd25519:
		return "Ed25519"
	case CurveEd448:
		return "Ed448"
	case CurveSecp256k1:
		return "Secp256k1"
	default:
		return unknown
	}
}

func (c Curve) ECDH() ecdh.Curve {
	switch c {
	case CurveANSIx9p256r1:
		return ecdh.P256()
	case CurveANSIx9p384r1:
		return ecdh.P384()
	case CurveANSIx9p521r1:
		return ecdh.P521()
	case CurveX25519:
		return ecdh.X25519()
	default:
		return nil // TODO: panic here?
	}
}

func (c Curve) ECDSA() elliptic.Curve {
	switch c {
	case CurveANSIx9p256r1:
		return elliptic.P256()
	case CurveANSIx9p384r1:
		return elliptic.P384()
	case CurveANSIx9p521r1:
		return elliptic.P521()
	default:
		return nil // TODO: panic here?
	}
}

func (c Curve) OID() []byte {
	switch c {
	case CurveANSIx9p256r1:
		return oidANSIx9p256r1
	case CurveANSIx9p384r1:
		return oidANSIx9p384r1
	case CurveANSIx9p521r1:
		return oidANSIx9p521r1

	case CurveBrainpoolP256r1:
		return oidBrainpoolP256r1
	case CurveBrainpoolP384r1:
		return oidBrainpoolP384r1
	case CurveBrainpoolP512r1:
		return oidBrainpoolP512r1

	case CurveSecp256k1:
		return oidSecp256k1

	case CurveX448:
		return oidX448
	case CurveX25519:
		return oidX25519

	case CurveEd448:
		return oidEd448
	case CurveEd25519:
		return oidEd25519

	case CurveUnknown:
		return nil // TODO: panic here?
	}

	return nil
}

func (c Curve) AlgAttrs() AlgorithmAttributes {
	return AlgorithmAttributes{
		OID: c.OID(),
	}
}

func curveFromECDSA(c elliptic.Curve) Curve {
	switch c {
	case elliptic.P256():
		return CurveANSIx9p256r1
	case elliptic.P384():
		return CurveANSIx9p384r1
	case elliptic.P521():
		return CurveANSIx9p521r1
	}

	return CurveUnknown
}

func curveFromECDH(c ecdh.Curve) Curve {
	switch c {
	case ecdh.P256():
		return CurveANSIx9p256r1
	case ecdh.P384():
		return CurveANSIx9p384r1
	case ecdh.P521():
		return CurveANSIx9p521r1
	case ecdh.X25519():
		return CurveX25519
	}

	return CurveUnknown
}

type oid []byte

var (
	oidANSIx9p256r1 = []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	oidANSIx9p384r1 = []byte{0x2B, 0x81, 0x04, 0x00, 0x22}
	oidANSIx9p521r1 = []byte{0x2B, 0x81, 0x04, 0x00, 0x23}

	oidBrainpoolP256r1 = []byte{0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07}
	oidBrainpoolP384r1 = []byte{0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B}
	oidBrainpoolP512r1 = []byte{0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D}

	oidSecp256k1 = []byte{0x2B, 0x81, 0x04, 0x00, 0x0A}

	oidX25519 = []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}
	oidX448   = []byte{0x2B, 0x65, 0x6F}

	oidEd25519 = []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}
	oidEd448   = []byte{0x2B, 0x65, 0x71}
)

const (
	PW1       byte = 0x81 // User PIN (PSO:CDS command only)
	PW1forPSO byte = 0x82 // User PIN for PSO: DECIPHER
	RC        byte = 0x82 // Resetting code
	PW3       byte = 0x83 // Admin PIN
)

var (
	DefaultPW = map[byte]string{
		RC:  DefaultPW1,
		PW3: DefaultPW3,
	}

	DefaultPW1 = "123456"
	DefaultPW3 = "12345678"
)

const (
	insGenerateAsymmetricKeyPair iso.Instruction = 0x47
	insSelectData                iso.Instruction = 0xa5
	insGetNextData               iso.Instruction = 0xcc

	// Yubico extension
	insSetPINRetries iso.Instruction = 0xf2
)

// Tags reference file objects
const (
	tagPrivateUse1 tlv.Tag = 0x0101 // Optional DO for private use (binary)
	tagPrivateUse2 tlv.Tag = 0x0102 // Optional DO for private use (binary)
	tagPrivateUse3 tlv.Tag = 0x0103 // Optional DO for private use (binary)
	tagPrivateUse4 tlv.Tag = 0x0104 // Optional DO for private use (binary)

	tagAID tlv.Tag = 0x4f // Application identifier (AID), ISO 7816-4

	// Cardholder

	tagName      tlv.Tag = 0x5b   // Name (according to ISO/IEC 7501-1)
	tagLoginData tlv.Tag = 0x5e   // Login data
	tagLanguage  tlv.Tag = 0x5f2d // Language preferences (according to ISO 639)
	tagSex       tlv.Tag = 0x5f35 // Sex (according to ISO 5218)

	tagPublicKeyURL tlv.Tag = 0x5f50 // Uniform resource locator (URL)

	// Historical bytes, Card service data and Card capabilities shall
	// be included, mandatory for the OpenPGP application.
	tagHistoricalBytes tlv.Tag = 0x5f52

	tagExternalPublicKey tlv.Tag = 0x86
	tagCipher            tlv.Tag = 0xa6

	tagDiscretionaryDOs tlv.Tag = 0x73 // Discretionary data objects

	tagExtendedCapabilities tlv.Tag = 0xc0 // Extended Capabilities, Flag list

	// Algorithm attributes
	// 1 Byte Algorithm ID, according to RFC 4880/6637
	// further bytes depending on algorithm (e.g. length modulus and length exponent).

	tagAlgAttrsSign    tlv.Tag = 0xc1 // Algorithm attributes signature
	tagAlgAttrsDecrypt tlv.Tag = 0xc2 // Algorithm attributes decryption
	tagAlgAttrsAuthn   tlv.Tag = 0xc3 // Algorithm attributes authentication

	// PW Status Bytes (binary)
	// 1st byte: 00 = PW1 (no. 81) only valid for one
	// PSO:CDS command
	//  01 = PW1 valid for several PSO:CDS commands
	//
	// 2nd byte: max. length and format of PW1 (user)
	// Bit 1-7 = max. length
	// Bit 8 = 0 for UTF-8 or derived password
	//         1 for PIN block format 2
	///
	// 3rd byte: max. length of Resetting Code (RC) for PW1
	//
	// 4th byte: max. length and format of PW3 (admin), see 2nd byte for PW1
	//
	// Byte 5, 6, 7 (first byte for PW1, second byte for Resetting Code, third byte for PW3):
	// 		Error counter of PW1, RC and PW3.
	//		If 00, then the corresponding PW/RC is blocked.
	//		Incorrect usage decrements the counter, correct verification sets to default value = 03.
	tagPasswordStatus tlv.Tag = 0xc4

	// Fingerprints (binary, 20 bytes (dec.)
	// each for Sig, Dec, Aut in that order),
	// zero bytes indicate a not defined private key.
	tagFpr tlv.Tag = 0xc5

	// List of CA-Fingerprints (binary, 20 bytes (dec.) each) of “Ultimately Trusted Keys”.
	// Zero bytes indicate a free entry.
	// May be used to verify Public Keys from servers.
	tagFprCA tlv.Tag = 0xc6

	// Fingerprints for signature, decryption and authentication key
	// Format according to RFC 4880
	tagFprSign    tlv.Tag = 0xc7
	tagFprDecrypt tlv.Tag = 0xc8
	tagFprAuthn   tlv.Tag = 0xc9

	// List of CA fingerprints
	tagFprCA1 tlv.Tag = 0xca
	tagFprCA2 tlv.Tag = 0xcb
	tagFprCA3 tlv.Tag = 0xcc

	// List of generation dates/times of key pairs, binary.
	// 4 bytes, Big Endian each for Sig, Dec and Aut.
	// Each value shall be seconds since Jan 1, 1970.
	// Default value is 00000000 (not specified).
	tagGenTime tlv.Tag = 0xcd

	// Generation date/time of signature, decryption and authentication key
	// Big Endian, format according to RFC 4880
	tagGenTimeSign    tlv.Tag = 0xce
	tagGenTimeDecrypt tlv.Tag = 0xcf
	tagGenTimeAuthn   tlv.Tag = 0xd0

	// Optional DOs (announced in Extended Capabilities) for Secure Messaging.
	// SM-Key-ENC for cryptogram (16 or 32 bytes in case of AES128/256).
	// The stored Secure Messaging key shall match the announced algorithm in Extended Capabilities.
	tagKeySMENC tlv.Tag = 0xd1
	// SM-Key-MAC for cryptographic checksum (16 or 32 bytes in case of AES128/256).
	// The stored Secure Messaging key shall match the announced algorithm in Extended Capabilities.
	tagKeySMMAC tlv.Tag = 0xd2

	tagResettingCode tlv.Tag = 0xd3 // Resetting Code, 0 or 8 to xx bytes (dec.), binary

	// Optional DO (announced in Extended Capabilities) for PSO:ENC/DEC with AES (32 bytes dec. in case of AES256, 16 bytes dec. in case of AES128).
	tagKeyAES tlv.Tag = 0xd5

	// User Interaction Flag (UIF)
	// If not supported, DO is not available.
	// First byte =
	//   00: UIF disabled (default)
	//   01: UIF enabled
	//   02: UIF permanently enabled (not changeable with PUT DATA, optional)
	//   03/04: Reserved for caching modes (Yubico)
	// Second byte = Content from General feature management ('20' for button/keypad)

	tagUIFSign    tlv.Tag = 0xd6 // UIF for PSO:CDS (optional)
	tagUIFDecrypt tlv.Tag = 0xd7 // UIF for PSO:DEC (optional)
	tagUIFAuthn   tlv.Tag = 0xd8 // UIF for PSO:AUT (optional)
	tagUIFAttest  tlv.Tag = 0xd9 // Reserved for UIF for Attestation key and Generate Attestation command (Yubico)

	// Reserved for Yubico attestation key
	tagAlgAttrsAttest tlv.Tag = 0xda // Algorithm attributes
	tagFprAttest      tlv.Tag = 0xdb // Fingerprint
	tagFprCAAttest    tlv.Tag = 0xdc // CA fingerprint
	tagGenTimeAttest  tlv.Tag = 0xdd // Generation date/time

	// Key Information
	// Every key is presented with its Key-Reference number
	// first (1 byte) and a second status byte.
	//  Byte 1-2: Key-Ref. and Status of the signature key
	//  Byte 3-4: Key-Ref. and Status of the decryption key
	//  Byte 5-6: Key-Ref. and Status of the authentication key
	//  Further bytes: Key-Ref. and Status of additional keys (optional)
	//
	// Values for the Status byte:
	//   00 = Key not present (not generated or imported)
	//   01 = Key generated by the card
	//   02 = Key imported into the card
	tagKeyInfo tlv.Tag = 0xde

	// Digital signature counter (counts usage of Compute Digital Signature command), binary, ISO 7816-4.
	tagDSCounter tlv.Tag = 0x93

	// Optional DO (announced in Extended Capabilities) for Secure Messaging .
	// Container for both Secure Messaging keys (ENC and MAC) with Tags D1 and D2. Useful for updating or deleting both keys simultaneous.
	tagKeyContainerSM tlv.Tag = 0xf4

	tagKDF        tlv.Tag = 0xf9 // KDF-DO, announced in Extended Capabilities (optional)
	tagAlgInfo    tlv.Tag = 0xfa // Algorithm Information, List of supported Algorithm attributes
	tagCertSM     tlv.Tag = 0xfb // Reserved for a certificate used with secure messaging (e. g. SCP11b), optional
	tagCertAttest tlv.Tag = 0xfc // Reserved for an Attestation Certificate (Yubico), optional

	// Cardholder certificate (each for AUT, DEC and SIG)
	// These DOs are designed to store a certificate (e.g. X.509) for the keys in the card.
	// They can be used to identify the card in a client-server authentication,
	// where specific non-OpenPGP-certificates are needed, for S-MIME and other x.509 related functions.
	// The maximum length of the DOs is announced in Extended Capabilities.
	// The content should be TLV-constructed, but is out of scope of this specification.
	// The DOs are stored in the order AUT (1st occurrence), DEC (2nd occurrence) and SIG (3rd occurrence).
	// Storing the AUT certificate at first occurrence is for downward compatibility with older versions of this specification.
	tagCerts tlv.Tag = 0x7f21

	tagPublicKey tlv.Tag = 0x7f49

	// Extended length information (ISO 7816-4)
	// with maximum number of bytes for command and response.
	tagExtendedLengthInfo tlv.Tag = 0x7f66

	tagGeneralFeatureManagement tlv.Tag = 0x7f74 // (optional)

	tagExtendedHeaderList tlv.Tag = 0x4d // For key import including the following sub-tags
	tagPrivateKeyTemplate tlv.Tag = 0x7f48
	tagPrivateKey         tlv.Tag = 0x5f48

	// Constructed DOs

	tagApplicationRelated      tlv.Tag = 0x6e // Application related data
	tagCardholderRelated       tlv.Tag = 0x65 // Cardholder related data
	tagSecuritySupportTemplate tlv.Tag = 0x7a // Security support template

	tagModulus     tlv.Tag = 0x81
	tagExponent    tlv.Tag = 0x82
	tagPublicKeyEC tlv.Tag = 0x86
)

type permission struct {
	read  byte
	write byte
}

var (
	always = byte(0)
	never  = byte(1)

	accessConditionsDO = map[tlv.Tag]permission{
		tagPrivateUse1:              {always, RC}, // With PW no. 82
		tagPrivateUse2:              {always, PW3},
		tagPrivateUse3:              {RC, RC}, // With PW no. 82
		tagPrivateUse4:              {PW3, PW3},
		tagAID:                      {always, never}, // Writing possible only during personalisation (manufacturer)
		tagName:                     {always, PW3},
		tagLoginData:                {always, PW3},
		tagLanguage:                 {always, PW3},
		tagSex:                      {always, PW3},
		tagPrivateKey:               {never, PW3}, // Relevant for all private keys in the application (signature, decryption, authentication)
		tagPublicKeyURL:             {always, PW3},
		tagHistoricalBytes:          {always, never}, // Writing possible only during personalisation
		tagCardholderRelated:        {always, PW3},   // Relevant for all sub-tags
		tagSecuritySupportTemplate:  {always, never}, // Internally set by related commands
		tagCerts:                    {always, PW3},
		tagExtendedLengthInfo:       {always, never},
		tagGeneralFeatureManagement: {always, never},
		tagDSCounter:                {always, never}, // Internal Reset during key generation
		tagExtendedCapabilities:     {always, never}, // Writing possible only during personalisation
		tagAlgAttrsSign:             {always, PW3},
		tagAlgAttrsDecrypt:          {always, PW3},
		tagAlgAttrsAuthn:            {always, PW3},
		tagPasswordStatus:           {always, PW3}, // Only 1st byte can be changed, other bytes only during personalisation
		tagFprCA:                    {always, PW3},
		tagGenTime:                  {always, PW3},
		tagKeySMENC:                 {never, PW3},
		tagKeySMMAC:                 {never, PW3},
		tagResettingCode:            {never, PW3},
		tagKeyAES:                   {never, PW3},
		tagUIFSign:                  {always, PW3},
		tagUIFDecrypt:               {always, PW3},
		tagUIFAuthn:                 {always, PW3},
		tagUIFAttest:                {always, PW3},
		tagKeyContainerSM:           {never, PW3},
		tagKeyInfo:                  {always, never}, // Internally set by related commands
		tagKDF:                      {always, PW3},
		tagAlgInfo:                  {always, never}, // Writing possible only during personalisation (manufacturer)
		tagCertSM:                   {always, PW3},
		tagCertAttest:               {always, never}, // Writing possible only during personalisation (manufacturer)
	}
)

const (
	apduShort = 256
	apduLong  = 65536
)

type Manufacturer uint16

// From: https://github.com/gpg/gnupg/blob/9e4d52223945d677c1ffcb0e20dae48299e9aae1/scd/app-openpgp.c#L293
const (
	ManufacturerYubico Manufacturer = 0x0006
)

func (m Manufacturer) String() string {
	switch m {
	case 0x0001:
		return "PPC Card Systems"
	case 0x0002:
		return "Prism"
	case 0x0003:
		return "OpenFortress"
	case 0x0004:
		return "Wewid"
	case 0x0005:
		return "ZeitControl"
	case 0x0006:
		return "Yubico"
	case 0x0007:
		return "OpenKMS"
	case 0x0008:
		return "LogoEmail"
	case 0x0009:
		return "Fidesmo"
	case 0x000A:
		return "VivoKey"
	case 0x000B:
		return "Feitian Technologies"
	case 0x000D:
		return "Dangerous Things"
	case 0x000E:
		return "Excelsecu"
	case 0x000F:
		return "Nitrokey"
	case 0x002A:
		return "Magrathea"
	case 0x0042:
		return "GnuPG e.V."
	case 0x1337:
		return "Warsaw Hackerspace"
	case 0x2342:
		return "warpzone" // hackerspace Muenster
	case 0x4354:
		return "Confidential Technologies" // cotech.de
	case 0x5343:
		return "SSE Carte à puce"
	case 0x5443:
		return "TIF-IT e.V."
	case 0x63AF:
		return "Trustica"
	case 0xBA53:
		return "c-base e.V."
	case 0xBD0E:
		return "Paranoidlabs"
	case 0xCA05:
		return "Atos CardOS"
	case 0xF1D0:
		return "CanoKeys"
	case 0xF517:
		return "FSIJ"
	case 0xF5EC:
		return "F-Secure"
	case 0x2C97:
		return "Ledger"
	case 0xAFAF:
		return "ANSSI"
	default:
		return unknown
	}
}
