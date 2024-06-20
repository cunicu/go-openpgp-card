// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"time"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/devices/yubikey"
	"cunicu.li/go-iso7816/encoding/tlv"
)

type Card struct {
	*iso.Card

	Rand  io.Reader
	Clock func() time.Time

	*ApplicationRelated
	*Cardholder
	*SecuritySupportTemplate

	kdf       *KDF
	tx        *iso.Transaction
	fwVersion iso.Version
}

var (
	errAlreadyInitialized = errors.New("already initialized")
	errInvalidIndex       = errors.New("invalid index")
)

// NewCard creates a new OpenPGP card handle.
func NewCard(sc *iso.Card) (c *Card, err error) {
	c = &Card{
		Card: sc,

		Rand:  rand.Reader,
		Clock: time.Now,
	}

	if c.tx, err = sc.NewTransaction(); err != nil {
		return nil, err
	}

	if err = c.Select(); err != nil {
		return nil, fmt.Errorf("failed to select applet: %w", err)
	}

	if err := c.getAll(); err != nil {
		return nil, err
	}

	// Manufacturer specific quirks
	if c.AID.Manufacturer == ManufacturerYubico {
		if _, err := c.Card.Select(iso.AidYubicoOTP); err != nil {
			return nil, fmt.Errorf("failed to select applet: %w", err)
		}

		yc := yubikey.NewCard(c)
		sts, err := yc.Status()
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

// Close closes the OpenPGP card handle.
func (c *Card) Close() error {
	if c.tx != nil {
		if err := c.tx.Close(); err != nil {
			return err
		}
	}

	return nil
}

func (c *Card) getAll() error {
	if _, err := c.GetApplicationRelatedData(); err != nil {
		return err
	}

	if _, err := c.GetCardholder(); err != nil {
		return err
	}

	if _, err := c.GetSecuritySupportTemplate(); err != nil {
		return err
	}

	if c.Capabilities.Flags&CapKDF != 0 {
		var err error
		if c.kdf, err = c.GetKDF(); err != nil {
			return err
		}
	}

	return nil
}

// Select selects the OpenPGP applet.
//
// See: OpenPGP Smart Card Application - Section 7.2.1 SELECT
func (c *Card) Select() error {
	_, err := send(c.tx, iso.InsSelect, 0x04, 0x00, iso.AidOpenPGP)
	return err
}

// GetApplicationRelatedData fetches the application related data from the card.
func (c *Card) GetApplicationRelatedData() (ar *ApplicationRelated, err error) {
	resp, err := c.getData(tagApplicationRelated)
	if err != nil {
		return ar, err
	}

	ar = &ApplicationRelated{}
	if err := ar.Decode(resp); err != nil {
		return nil, err
	}

	c.ApplicationRelated = ar

	return ar, nil
}

// GetSecuritySupportTemplate fetches the the security template from the card.
func (c *Card) GetSecuritySupportTemplate() (sst *SecuritySupportTemplate, err error) {
	resp, err := c.getData(tagSecuritySupportTemplate)
	if err != nil {
		return sst, err
	}

	sst = &SecuritySupportTemplate{}
	if err := sst.Decode(resp); err != nil {
		return nil, err
	}

	c.SecuritySupportTemplate = sst

	return sst, nil
}

// GetCardholder fetches the card holder information from the card.
func (c *Card) GetCardholder() (ch *Cardholder, err error) {
	resp, err := c.getData(tagCardholderRelated)
	if err != nil {
		return ch, err
	}

	ch = &Cardholder{}
	if err := ch.Decode(resp); err != nil {
		return nil, err
	}

	c.Cardholder = ch

	return ch, nil
}

func (c *Card) GetPasswordStatus() (*PasswordStatus, error) {
	resp, err := c.getData(tagPasswordStatus)
	if err != nil {
		return nil, err
	}

	s := &PasswordStatus{}
	if err := s.Decode(resp); err != nil {
		return nil, err
	}

	c.PasswordStatus = *s

	return s, nil
}

func (c *Card) SetCardholder(ch Cardholder) error {
	if err := c.SetName(ch.Name); err != nil {
		return fmt.Errorf("failed to set name: %w", err)
	}

	if err := c.SetLanguage(ch.Language); err != nil {
		return fmt.Errorf("failed to set language: %w", err)
	}

	if err := c.SetSex(ch.Sex); err != nil {
		return fmt.Errorf("failed to set sex: %w", err)
	}

	return nil
}

func (c *Card) GetLoginData() (string, error) {
	b, err := c.getData(tagLoginData)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (c *Card) GetPublicKeyURL() (*url.URL, error) {
	b, err := c.getData(tagPublicKeyURL)
	if err != nil {
		return nil, err
	}

	if len(b) == 0 {
		return nil, nil //nolint
	}

	return url.Parse(string(b))
}

func (c *Card) GetCardholderCertificates() ([][]byte, error) {
	return c.getAllData(tagCerts)
}

func (c *Card) GetCardholderCertificate(key KeyRef) ([]byte, error) {
	order := []KeyRef{KeyAuthn, KeyDecrypt, KeySign}
	index := slices.Index(order, key)
	if index < 0 {
		return nil, ErrUnsupported
	}

	return c.getDataIndex(tagCerts, index)
}

func (c *Card) GetSignatureCounter() (int, error) {
	if _, err := c.GetSecuritySupportTemplate(); err != nil {
		return 0, err
	}

	return c.SecuritySupportTemplate.SignatureCounter, nil
}

func (c *Card) PrivateData(index int) ([]byte, error) {
	if c.Capabilities.Flags&CapPrivateDO == 0 {
		return nil, ErrUnsupported
	} else if index < 0 || index > 3 {
		return nil, errInvalidIndex
	}

	t := tagPrivateUse1 + tlv.Tag(index)
	return c.getData(t)
}

func (c *Card) SetName(name string) error {
	if len(name) >= 40 {
		return ErrInvalidLength
	}

	return c.putData(tagName, []byte(name))
}

func (c *Card) SetLoginData(login string) error {
	b := []byte(login)
	if maxObjLen := int(c.Capabilities.MaxLenSpecialDO); len(b) > maxObjLen {
		return fmt.Errorf("%w: max length is %d Bytes", ErrInvalidLength, maxObjLen)
	}

	return c.putData(tagLoginData, b)
}

func (c *Card) SetLanguage(lang string) error {
	if len(lang) < 2 || len(lang) > 8 {
		return ErrInvalidLength
	}

	return c.putData(tagLanguage, []byte(lang))
}

func (c *Card) SetSex(sex Sex) error {
	return c.putData(tagSex, []byte{byte(sex)})
}

func (c *Card) SetPublicKeyURL(url *url.URL) error {
	b := []byte(url.String())

	if maxObjLen := int(c.Capabilities.MaxLenSpecialDO); len(b) > maxObjLen {
		return fmt.Errorf("%w: max length is %d Bytes", ErrInvalidLength, maxObjLen)
	}

	return c.putData(tagPublicKeyURL, b)
}

func (c *Card) SetPrivateData(index int, b []byte) error {
	if c.Capabilities.Flags&CapPrivateDO == 0 {
		return ErrUnsupported
	} else if maxObjLen := int(c.Capabilities.MaxLenSpecialDO); len(b) > maxObjLen {
		return fmt.Errorf("%w: max length is %d Bytes", ErrInvalidLength, maxObjLen)
	} else if index < 0 || index > 3 {
		return errInvalidIndex
	}

	t := tagPrivateUse1 + tlv.Tag(index)
	return c.putData(t, b)
}

// Challenge generates a random number of cnt bytes.
//
// See: OpenPGP Smart Card Application - Section 7.2.15 GET CHALLENGE
func (c *Card) Challenge(cnt int) ([]byte, error) {
	if c.Capabilities.Flags&CapGetChallenge == 0 {
		return nil, ErrUnsupported
	} else if cnt > int(c.Capabilities.MaxLenChallenge) {
		return nil, errChallengeTooLong
	}

	return sendNe(c.tx, iso.InsGetChallenge, 0x00, 0x00, nil, cnt)
}

// FactoryReset resets the applet to its original state
//
// Access condition: Admin/PW3
//
//	Alternatively, we will try to block the Admin PIN by repeatedly calling VerifyPassword()
//	with a wrong password to enable TERMINATE DF without Admin PIN.
//
// See: OpenPGP Smart Card Application - Section 7.2.16 TERMINATE DF & 7.2.17 ACTIVATE FILE
func (c *Card) FactoryReset() error {
	switch LifeCycleStatus(c.HistoricalBytes.LifeCycleStatus) {
	case LifeCycleStatusNoInfo:
		return ErrUnsupported

	case LifeCycleStatusInitialized:

	case LifeCycleStatusOperational:
		if err := c.terminate(); err != nil {
			return fmt.Errorf("failed to terminate applet: %w", err)
		}
	}

	c.HistoricalBytes.LifeCycleStatus = byte(LifeCycleStatusInitialized)

	if err := c.activate(); err != nil {
		return fmt.Errorf("failed to activate applet: %w", err)
	}

	// Fetch application related data again after reset
	if err := c.getAll(); err != nil {
		return err
	}

	return nil
}

// See: OpenPGP Smart Card Application - Section 7.2.18 MANAGE SECURITY ENVIRONMENT
func (c *Card) ManageSecurityEnvironment(op SecurityOperation, key KeyRef) error {
	if c.Capabilities.CommandMSE == 0 {
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

	_, err := sendTLV(c.tx, iso.InsManageSecurityEnvironment, 0x41, byte(opRef.tag()), key.crt())
	return err
}

// See: OpenPGP Smart Card Application - Section 7.2.5 SELECT DATA
func (c *Card) selectData(t tlv.Tag, skip byte) error {
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
	if c.AID.Manufacturer == ManufacturerYubico {
		fwVersionNonStandardData := iso.Version{Major: 5, Minor: 4, Patch: 4}
		if fwVersionNonStandardData.Less(c.fwVersion) {
			data = append([]byte{0x06}, data...)
		}
	}

	_, err = sendNe(c.tx, insSelectData, skip, 0x04, data, iso.MaxLenRespDataStandard)
	return err
}

// See: OpenPGP Smart Card Application - Section 7.2.6 GET DATA
func (c *Card) getData(t tlv.Tag) ([]byte, error) {
	p1 := byte(t >> 8)
	p2 := byte(t)

	ne := iso.MaxLenRespDataStandard
	if ar := c.ApplicationRelated; ar != nil {
		ne = int(ar.LengthInfo.MaxResponseLength)
	}

	return sendNe(c.tx, iso.InsGetData, p1, p2, nil, ne)
}

// See: OpenPGP Smart Card Application - Section 7.2.7 GET NEXT DATA
func (c *Card) getNextData(t tlv.Tag) ([]byte, error) {
	p1 := byte(t >> 8)
	p2 := byte(t)

	ne := iso.MaxLenRespDataStandard
	if ar := c.ApplicationRelated; ar != nil {
		ne = int(ar.LengthInfo.MaxResponseLength)
	}

	return sendNe(c.tx, insGetNextData, p1, p2, nil, ne)
}

func (c *Card) getDataIndex(t tlv.Tag, i int) ([]byte, error) {
	if err := c.selectData(t, byte(i)); err != nil {
		return nil, err
	}

	return c.getData(t)
}

func (c *Card) getAllData(t tlv.Tag) (datas [][]byte, err error) {
	var data []byte

	for getNextData := c.getData; ; getNextData = c.getNextData {
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
func (c *Card) putData(t tlv.Tag, data []byte) error {
	p1 := byte(t >> 8)
	p2 := byte(t)

	_, err := send(c.tx, iso.InsPutData, p1, p2, data)
	return err
}

// See: OpenPGP Smart Card Application - Section 7.2.8 PUT DATA
func (c *Card) putDataTLV(tv tlv.TagValue) error {
	_, err := sendTLV(c.tx, iso.InsPutDataOdd, 0x3f, 0xff, tv)
	return err
}

// See: OpenPGP Smart Card Application - Section 7.2.17 ACTIVATE FILE
func (c *Card) activate() error {
	switch LifeCycleStatus(c.HistoricalBytes.LifeCycleStatus) {
	case LifeCycleStatusNoInfo:
		return ErrUnsupported

	case LifeCycleStatusOperational:
		return errAlreadyInitialized

	case LifeCycleStatusInitialized:
	}

	_, err := send(c.tx, iso.InsActivateFile, 0x00, 0x00, nil)
	return err
}

// See: OpenPGP Smart Card Application - Section 7.2.16 TERMINATE DF
func (c *Card) terminate() error {
	if c.HistoricalBytes.LifeCycleStatus == byte(LifeCycleStatusNoInfo) {
		return ErrUnsupported
	}

	for {
		// First try to terminate in case we already have PW3 unlocked
		if _, err := send(c.tx, iso.InsTerminateDF, 0x00, 0x00, nil); err == nil {
			break
		}

		// Get number of remaining PW3 attempts before blocking
		pwSts, err := c.GetPasswordStatus()
		if err != nil {
			return fmt.Errorf("failed to get password status: %w", err)
		}

		remainingAttempts := int(pwSts.AttemptsPW3)
		if remainingAttempts == 0 {
			remainingAttempts = 3
		}

		// We purposefully block PW3 here
		for i := 0; i < remainingAttempts; i++ {
			if err := c.VerifyPassword(PW3, DefaultPW3); err == nil {
				break
			}
		}
	}

	return nil
}

func sendNe(tx *iso.Transaction, ins iso.Instruction, p1, p2 byte, data []byte, ne int) ([]byte, error) {
	resp, err := tx.Send(&iso.CAPDU{
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

func send(tx *iso.Transaction, ins iso.Instruction, p1, p2 byte, data []byte) ([]byte, error) {
	return sendNe(tx, ins, p1, p2, data, 0)
}

//nolint:unparam
func sendTLV(tx *iso.Transaction, ins iso.Instruction, p1, p2 byte, value tlv.TagValue) ([]byte, error) {
	data, err := tlv.EncodeBER(value)
	if err != nil {
		return nil, err
	}

	return send(tx, ins, p1, p2, data)
}
