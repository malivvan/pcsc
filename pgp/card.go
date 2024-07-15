// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package pgp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/malivvan/pcsc/yubikey"
	"io"
	"net/url"
	"slices"
	"time"

	iso "github.com/malivvan/pcsc/iso7816"
	"github.com/malivvan/pcsc/iso7816/tlv"
)

type TX struct {
	tx    iso.TX
	Rand  io.Reader
	Clock func() time.Time

	*ApplicationRelated
	*Cardholder
	*SecuritySupportTemplate

	kdf       *KDF
	fwVersion iso.Version
}

var (
	errAlreadyInitialized = errors.New("already initialized")
	errInvalidIndex       = errors.New("invalid index")
)

// NewCard creates a new OpenPGP card handle.
func New(tx iso.TX) (c *TX, err error) {
	c = &TX{
		tx: tx,

		Rand:  rand.Reader,
		Clock: time.Now,
	}

	if err = c.Select(); err != nil {
		return nil, fmt.Errorf("failed to select applet: %w", err)
	}

	if err := c.getAll(); err != nil {
		return nil, err
	}

	//// Manufacturer specific quirks
	if c.AID.Manufacturer == ManufacturerYubico {
		if err := tx.Select(iso.AidYubicoOTP); err != nil {
			return nil, fmt.Errorf("failed to select applet: %w", err)
		}

		sts, err := yubikey.GetStatus(tx)
		if err != nil {
			return nil, fmt.Errorf("failed to get YubiKey status: %w", err)
		}

		c.fwVersion = sts.Version

		if err := c.Select(); err != nil {
			return nil, fmt.Errorf("failed to select applet: %w", err)
		}
	}

	return c, nil
}

func (tx *TX) getAll() error {
	if _, err := tx.GetApplicationRelatedData(); err != nil {
		return err
	}

	if _, err := tx.GetCardholder(); err != nil {
		return err
	}

	if _, err := tx.GetSecuritySupportTemplate(); err != nil {
		return err
	}

	if tx.Capabilities.Flags&CapKDF != 0 {
		var err error
		if tx.kdf, err = tx.GetKDF(); err != nil {
			return err
		}
	}

	return nil
}

// Select selects the OpenPGP applet.
//
// See: OpenPGP Smart Card Application - Section 7.2.1 SELECT
func (tx *TX) Select() error {
	return tx.tx.Select(iso.AidOpenPGP)
}

// GetApplicationRelatedData fetches the application related data from the card.
func (tx *TX) GetApplicationRelatedData() (ar *ApplicationRelated, err error) {
	resp, err := tx.getData(tagApplicationRelated)
	if err != nil {
		return ar, err
	}

	ar = &ApplicationRelated{}
	if err := ar.Decode(resp); err != nil {
		return nil, err
	}

	tx.ApplicationRelated = ar

	return ar, nil
}

// GetSecuritySupportTemplate fetches the the security template from the card.
func (tx *TX) GetSecuritySupportTemplate() (sst *SecuritySupportTemplate, err error) {
	resp, err := tx.getData(tagSecuritySupportTemplate)
	if err != nil {
		return sst, err
	}

	sst = &SecuritySupportTemplate{}
	if err := sst.Decode(resp); err != nil {
		return nil, err
	}

	tx.SecuritySupportTemplate = sst

	return sst, nil
}

// GetCardholder fetches the card holder information from the card.
func (tx *TX) GetCardholder() (ch *Cardholder, err error) {
	resp, err := tx.getData(tagCardholderRelated)
	if err != nil {
		return ch, err
	}

	ch = &Cardholder{}
	if err := ch.Decode(resp); err != nil {
		return nil, err
	}

	tx.Cardholder = ch

	return ch, nil
}

func (tx *TX) GetPasswordStatus() (*PasswordStatus, error) {
	resp, err := tx.getData(tagPasswordStatus)
	if err != nil {
		return nil, err
	}

	s := &PasswordStatus{}
	if err := s.Decode(resp); err != nil {
		return nil, err
	}

	tx.PasswordStatus = *s

	return s, nil
}

func (tx *TX) SetCardholder(ch Cardholder) error {
	if err := tx.SetName(ch.Name); err != nil {
		return fmt.Errorf("failed to set name: %w", err)
	}

	if err := tx.SetLanguage(ch.Language); err != nil {
		return fmt.Errorf("failed to set language: %w", err)
	}

	if err := tx.SetSex(ch.Sex); err != nil {
		return fmt.Errorf("failed to set sex: %w", err)
	}

	return nil
}

func (tx *TX) GetLoginData() (string, error) {
	b, err := tx.getData(tagLoginData)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (tx *TX) GetPublicKeyURL() (*url.URL, error) {
	b, err := tx.getData(tagPublicKeyURL)
	if err != nil {
		return nil, err
	}

	if len(b) == 0 {
		return nil, nil //nolint
	}

	return url.Parse(string(b))
}

func (tx *TX) GetCardholderCertificates() ([][]byte, error) {
	return tx.getAllData(tagCerts)
}

func (tx *TX) GetCardholderCertificate(key KeyRef) ([]byte, error) {
	order := []KeyRef{KeyAuthn, KeyDecrypt, KeySign}
	index := slices.Index(order, key)
	if index < 0 {
		return nil, ErrUnsupported
	}

	return tx.getDataIndex(tagCerts, index)
}

func (tx *TX) GetSignatureCounter() (int, error) {
	if _, err := tx.GetSecuritySupportTemplate(); err != nil {
		return 0, err
	}

	return tx.SecuritySupportTemplate.SignatureCounter, nil
}

func (tx *TX) PrivateData(index int) ([]byte, error) {
	if tx.Capabilities.Flags&CapPrivateDO == 0 {
		return nil, ErrUnsupported
	} else if index < 0 || index > 3 {
		return nil, errInvalidIndex
	}

	t := tagPrivateUse1 + tlv.Tag(index)
	return tx.getData(t)
}

func (tx *TX) SetName(name string) error {
	if len(name) >= 40 {
		return ErrInvalidLength
	}

	return tx.putData(tagName, []byte(name))
}

func (tx *TX) SetLoginData(login string) error {
	b := []byte(login)
	if maxObjLen := int(tx.Capabilities.MaxLenSpecialDO); len(b) > maxObjLen {
		return fmt.Errorf("%w: max length is %d Bytes", ErrInvalidLength, maxObjLen)
	}

	return tx.putData(tagLoginData, b)
}

func (tx *TX) SetLanguage(lang string) error {
	if len(lang) < 2 || len(lang) > 8 {
		return ErrInvalidLength
	}

	return tx.putData(tagLanguage, []byte(lang))
}

func (tx *TX) SetSex(sex Sex) error {
	return tx.putData(tagSex, []byte{byte(sex)})
}

func (tx *TX) SetPublicKeyURL(url *url.URL) error {
	b := []byte(url.String())

	if maxObjLen := int(tx.Capabilities.MaxLenSpecialDO); len(b) > maxObjLen {
		return fmt.Errorf("%w: max length is %d Bytes", ErrInvalidLength, maxObjLen)
	}

	return tx.putData(tagPublicKeyURL, b)
}

func (tx *TX) SetPrivateData(index int, b []byte) error {
	if tx.Capabilities.Flags&CapPrivateDO == 0 {
		return ErrUnsupported
	} else if maxObjLen := int(tx.Capabilities.MaxLenSpecialDO); len(b) > maxObjLen {
		return fmt.Errorf("%w: max length is %d Bytes", ErrInvalidLength, maxObjLen)
	} else if index < 0 || index > 3 {
		return errInvalidIndex
	}

	t := tagPrivateUse1 + tlv.Tag(index)
	return tx.putData(t, b)
}

// Challenge generates a random number of cnt bytes.
//
// See: OpenPGP Smart Card Application - Section 7.2.15 GET CHALLENGE
func (tx *TX) Challenge(cnt int) ([]byte, error) {
	if tx.Capabilities.Flags&CapGetChallenge == 0 {
		return nil, ErrUnsupported
	} else if cnt > int(tx.Capabilities.MaxLenChallenge) {
		return nil, errChallengeTooLong
	}

	return sendNe(tx.tx, iso.InsGetChallenge, 0x00, 0x00, nil, cnt)
}

// FactoryReset resets the applet to its original state
//
// Access condition: Admin/PW3
//
//	Alternatively, we will try to block the Admin PIN by repeatedly calling VerifyPassword()
//	with a wrong password to enable TERMINATE DF without Admin PIN.
//
// See: OpenPGP Smart Card Application - Section 7.2.16 TERMINATE DF & 7.2.17 ACTIVATE FILE
func (tx *TX) FactoryReset() error {
	switch LifeCycleStatus(tx.HistoricalBytes.LifeCycleStatus) {
	case LifeCycleStatusNoInfo:
		return ErrUnsupported

	case LifeCycleStatusInitialized:

	case LifeCycleStatusOperational:
		if err := tx.terminate(); err != nil {
			return fmt.Errorf("failed to terminate applet: %w", err)
		}
	}

	tx.HistoricalBytes.LifeCycleStatus = byte(LifeCycleStatusInitialized)

	if err := tx.activate(); err != nil {
		return fmt.Errorf("failed to activate applet: %w", err)
	}

	// Fetch application related data again after reset
	if err := tx.getAll(); err != nil {
		return err
	}

	return nil
}

// See: OpenPGP Smart Card Application - Section 7.2.18 MANAGE SECURITY ENVIRONMENT
func (tx *TX) ManageSecurityEnvironment(op SecurityOperation, key KeyRef) error {
	if tx.Capabilities.CommandMSE == 0 {
		return ErrUnsupported
	}

	var opRef KeyRef
	switch op {
	case SecurityOperationDecrypt:
		opRef = KeyDecrypt
	case SecurityOperationAuthenticate:
		opRef = KeyAuthn
	default:
		return fmt.Errorf("%w: security operation", ErrUnsupported)
	}

	_, err := sendTLV(tx.tx, iso.InsManageSecurityEnvironment, 0x41, byte(opRef.tag()), key.crt())
	return err
}

// See: OpenPGP Smart Card Application - Section 7.2.5 SELECT DATA
func (tx *TX) selectData(t tlv.Tag, skip byte) error {
	tagBuf, err := t.MarshalBER()
	if err != nil {
		return err
	}

	data, err := tlv.EncodeBER(
		tlv.New(0x60,
			tlv.New(0x5c, tagBuf),
		))
	if err != nil {
		return err
	}

	// These use a non-standard byte in the command.
	if tx.AID.Manufacturer == ManufacturerYubico {
		fwVersionNonStandardData := iso.Version{Major: 5, Minor: 4, Patch: 4}
		if fwVersionNonStandardData.Less(tx.fwVersion) {
			data = append([]byte{0x06}, data...)
		}
	}

	_, err = sendNe(tx.tx, insSelectData, skip, 0x04, data, iso.MaxLenRespDataStandard)
	return err
}

// See: OpenPGP Smart Card Application - Section 7.2.6 GET DATA
func (tx *TX) getData(t tlv.Tag) ([]byte, error) {
	p1 := byte(t >> 8)
	p2 := byte(t)

	ne := iso.MaxLenRespDataStandard
	if ar := tx.ApplicationRelated; ar != nil {
		ne = int(ar.LengthInfo.MaxResponseLength)
	}

	return sendNe(tx.tx, iso.InsGetData, p1, p2, nil, ne)
}

// See: OpenPGP Smart Card Application - Section 7.2.7 GET NEXT DATA
func (tx *TX) getNextData(t tlv.Tag) ([]byte, error) {
	p1 := byte(t >> 8)
	p2 := byte(t)

	ne := iso.MaxLenRespDataStandard
	if ar := tx.ApplicationRelated; ar != nil {
		ne = int(ar.LengthInfo.MaxResponseLength)
	}

	return sendNe(tx.tx, insGetNextData, p1, p2, nil, ne)
}

func (tx *TX) getDataIndex(t tlv.Tag, i int) ([]byte, error) {
	if err := tx.selectData(t, byte(i)); err != nil {
		return nil, err
	}

	return tx.getData(t)
}

func (tx *TX) getAllData(t tlv.Tag) (datas [][]byte, err error) {
	var data []byte

	for getNextData := tx.getData; ; getNextData = tx.getNextData {
		if data, err = getNextData(t); err != nil {
			if errors.Is(err, iso.ErrIncorrectData) {
				break
			}
			return nil, err
		}
		datas = append(datas, data)
	}

	return datas, nil
}

// See: OpenPGP Smart Card Application - Section 7.2.8 PUT DATA
func (tx *TX) putData(t tlv.Tag, data []byte) error {
	p1 := byte(t >> 8)
	p2 := byte(t)

	_, err := send(tx.tx, iso.InsPutData, p1, p2, data)
	return err
}

// See: OpenPGP Smart Card Application - Section 7.2.8 PUT DATA
func (tx *TX) putDataTLV(tv tlv.TagValue) error {
	_, err := sendTLV(tx.tx, iso.InsPutDataOdd, 0x3f, 0xff, tv)
	return err
}

// See: OpenPGP Smart Card Application - Section 7.2.17 ACTIVATE FILE
func (tx *TX) activate() error {
	switch LifeCycleStatus(tx.HistoricalBytes.LifeCycleStatus) {
	case LifeCycleStatusNoInfo:
		return ErrUnsupported

	case LifeCycleStatusOperational:
		return errAlreadyInitialized

	case LifeCycleStatusInitialized:
	}

	_, err := send(tx.tx, iso.InsActivateFile, 0x00, 0x00, nil)
	return err
}

// See: OpenPGP Smart Card Application - Section 7.2.16 TERMINATE DF
func (tx *TX) terminate() error {
	if tx.HistoricalBytes.LifeCycleStatus == byte(LifeCycleStatusNoInfo) {
		return ErrUnsupported
	}

	for {
		// First try to terminate in case we already have PW3 unlocked
		if _, err := send(tx.tx, iso.InsTerminateDF, 0x00, 0x00, nil); err == nil {
			break
		}

		// Get number of remaining PW3 attempts before blocking
		pwSts, err := tx.GetPasswordStatus()
		if err != nil {
			return fmt.Errorf("failed to get password status: %w", err)
		}

		remainingAttempts := int(pwSts.AttemptsPW3)
		if remainingAttempts == 0 {
			remainingAttempts = 3
		}

		// We purposefully block PW3 here
		for i := 0; i < remainingAttempts; i++ {
			if err := tx.VerifyPassword(PW3, DefaultPW3); err == nil {
				break
			}
		}
	}

	return nil
}

func sendNe(tx iso.TX, ins iso.Instruction, p1, p2 byte, data []byte, ne int) ([]byte, error) {
	resp, err := tx.SendAPDU(&iso.CAPDU{
		Ins:  ins,
		P1:   p1,
		P2:   p2,
		Data: data,
		Ne:   ne,
	})
	if err != nil {
		return nil, wrapCode(err)
	}

	return resp, nil
}

func send(tx iso.TX, ins iso.Instruction, p1, p2 byte, data []byte) ([]byte, error) {
	return sendNe(tx, ins, p1, p2, data, 0)
}

//nolint:unparam
func sendTLV(tx iso.TX, ins iso.Instruction, p1, p2 byte, value tlv.TagValue) ([]byte, error) {
	data, err := tlv.EncodeBER(value)
	if err != nil {
		return nil, err
	}

	return send(tx, ins, p1, p2, data)
}
