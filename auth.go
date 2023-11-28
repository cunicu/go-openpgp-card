// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp

import (
	"errors"
	"fmt"

	iso "cunicu.li/go-iso7816"
)

// VerifyPassword attempts to unlock a given password.
//
// Access condition: Always
// See: OpenPGP Smart Card Application - Section 7.2.2 VERIFY
func (c *Card) VerifyPassword(pwType byte, pw string) (err error) {
	var pwBuf []byte
	if c.kdf == nil {
		pwBuf = []byte(pw)
	} else {
		if pwBuf, err = c.kdf.DerivePassword(pwType, pw); err != nil {
			return fmt.Errorf("failed to derive password: %w", err)
		}
	}

	_, err = send(c.tx, iso.InsVerify, 0x00, pwType, pwBuf)
	return err
}

// ClearPasswordState clears the passwort unlock state from the card.
//
// Access condition: Always
// Note: Appears to be broken on YubiKey 5
// See: OpenPGP Smart Card Application - Section 7.2.2 VERIFY
func (c *Card) ClearPasswordState(pwType byte) error {
	_, err := send(c.tx, iso.InsVerify, 0xff, pwType, nil)
	return err
}

// PasswordState returns true if the given password is unlocked.
//
// Access condition: Always
// Note: Appears to be broken on YubiKey 5
// See: OpenPGP Smart Card Application - Section 7.2.2 VERIFY
func (c *Card) PasswordState(pwType byte) (bool, error) {
	_, err := send(c.tx, iso.InsVerify, 0x00, pwType, nil)
	var aErr *AuthError
	if errors.Is(err, iso.ErrSuccess) {
		return true, nil
	} else if errors.As(err, &aErr) {
		return false, nil
	}
	return false, err
}

// ChangePassword changes the user or admin password.
//
// Access condition: Always
// Access level: None (current password must be provided)
// See: OpenPGP Smart Card Application - Section 7.2.3 CHANGE REFERENCE DATA
func (c *Card) ChangePassword(pwType byte, pwCurrent, pwNew string) error {
	switch pwType {
	case PW1:
		if len(pwNew) < 6 || len(pwNew) > int(c.PasswordStatus.LengthPW1) {
			return ErrInvalidLength
		}

	case PW3:
		if len(pwNew) < 8 || len(pwNew) > int(c.PasswordStatus.LengthPW3) {
			return ErrInvalidLength
		}

	default:
		return errUnsupported
	}

	_, err := send(c.tx, iso.InsChangeReferenceData, 0x00, pwType, []byte(pwCurrent+pwNew))
	return err
}

// ChangeResettingCode sets the resetting code of the cards.
//
// Access condition: Admin/PW3
// See: OpenPGP Smart Card Application - Section 4.3.4 Resetting Code
func (c *Card) ChangeResettingCode(rc string) error {
	if len(rc) < 8 || len(rc) > int(c.PasswordStatus.LengthRC) {
		return ErrInvalidLength
	}

	return c.putData(tagResettingCode, []byte(rc))
}

func (c *Card) ClearResettingCode() error {
	return c.putData(tagResettingCode, nil)
}

// ResetRetryCounter reset the PIN retry counter and a new password.
//
// Access condition: Admin/PW3
// See: OpenPGP Smart Card Application - Section 7.2.4 RESET RETRY COUNTER
func (c *Card) ResetRetryCounter(newPw string) error {
	if len(newPw) < 6 {
		return ErrInvalidLength
	}

	_, err := send(c.tx, iso.InsResetRetryCounter, 0x02, PW1, []byte(newPw))
	return err
}

// ResetRetryCounterWithResettingCode resets the PIN retry counter using a reset code.
//
// Access condition: None (reset code is required)
// See: OpenPGP Smart Card Application - Section 7.2.4 RESET RETRY COUNTER
func (c *Card) ResetRetryCounterWithResettingCode(rc, newPw string) error {
	if len(newPw) < 6 {
		return ErrInvalidLength
	}

	_, err := send(c.tx, iso.InsResetRetryCounter, 0x00, PW1, []byte(rc+newPw))
	return err
}

// SetRetryCounters sets the number of PIN attempts to allow before blocking.
//
// Access condition: Admin/PW3
// Note: This is a YubiKey extensions
// Warning: On YubiKey NEO this will reset the PINs to their default values.
func (c *Card) SetRetryCounters(pw1, rc, pw3 byte) error {
	_, err := send(c.tx, insSetPINRetries, 0, 0, []byte{pw1, rc, pw3})
	return err
}
