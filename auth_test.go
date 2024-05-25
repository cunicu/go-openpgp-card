// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp_test

import (
	"fmt"
	"testing"

	iso "cunicu.li/go-iso7816"
	"github.com/stretchr/testify/require"

	opc "cunicu.li/go-openpgp-card"
)

func TestVerifyPassword(t *testing.T) {
	for pwType, pw := range map[byte]string{
		opc.PW1: opc.DefaultPW1,
		opc.PW3: opc.DefaultPW3,
	} {
		testName := fmt.Sprintf("pw%d", pwType-0x80)
		t.Run(testName, func(t *testing.T) {
			withCard(t, true, func(t *testing.T, c *opc.Card) {
				require := require.New(t)

				err := c.VerifyPassword(pwType, "wrong")
				require.ErrorIs(err, iso.ErrIncorrectData)

				err = c.VerifyPassword(pwType, pw)
				require.NoError(err)

				err = c.VerifyPassword(pwType, pw)
				require.NoError(err)
			})
		})
	}
}

func TestChangePassword(t *testing.T) {
	withCard(t, true, func(t *testing.T, c *opc.Card) {
		require := require.New(t)

		err := c.ChangePassword(opc.PW1, opc.DefaultPW1, "hallo")
		require.ErrorIs(err, opc.ErrInvalidLength)

		err = c.ChangePassword(opc.PW1, "wrong", "hallohallo")
		require.ErrorIs(err, iso.ErrSecurityStatusNotSatisfied)

		err = c.ChangePassword(opc.PW1, opc.DefaultPW1, "hallohallo")
		require.NoError(err)

		err = c.VerifyPassword(opc.PW1, "hallohallo")
		require.NoError(err)
	})
}

func TestResetRetryCounter(t *testing.T) {
	withCard(t, true, func(t *testing.T, c *opc.Card) {
		require := require.New(t)

		require.Equal(byte(3), c.PasswordStatus.AttemptsPW1, "Initial attempts are not as expected")

		err := c.VerifyPassword(opc.PW1, "some wrong password")
		require.ErrorIs(err, iso.ErrSecurityStatusNotSatisfied)

		sts, err := c.GetPasswordStatus()
		require.NoError(err)
		require.Equal(byte(2), sts.AttemptsPW1)

		err = c.VerifyPassword(opc.PW3, opc.DefaultPW3)
		require.NoError(err)

		err = c.ResetRetryCounter(opc.DefaultPW1)
		require.NoError(err)

		sts, err = c.GetPasswordStatus()
		require.NoError(err)
		require.Equal(byte(3), sts.AttemptsPW1)
	})
}

func TestResetRetryCounterWithResettingCode(t *testing.T) {
	withCard(t, true, func(t *testing.T, c *opc.Card) {
		require := require.New(t)

		err := c.ChangeResettingCode("my reset code")
		require.NoError(err, "Failed to setup resetting code")

		require.Equal(byte(3), c.PasswordStatus.AttemptsPW1, "Initial attempts are not as expected")

		err = c.VerifyPassword(opc.PW1, "some wrong password")
		require.ErrorIs(err, iso.ErrSecurityStatusNotSatisfied)

		sts, err := c.GetPasswordStatus()
		require.NoError(err)
		require.Equal(byte(2), sts.AttemptsPW1)

		err = c.ResetRetryCounterWithResettingCode("my reset code", opc.DefaultPW1)
		require.NoError(err)

		sts, err = c.GetPasswordStatus()
		require.NoError(err)
		require.Equal(byte(3), sts.AttemptsPW1)
	})
}

func TestSetRetryCounters(t *testing.T) {
	withCard(t, true, func(t *testing.T, c *opc.Card) {
		require := require.New(t)

		require.Equal(byte(3), c.PasswordStatus.AttemptsPW1, "Initial attempts are not as expected")

		err := c.VerifyPassword(opc.PW3, opc.DefaultPW3)
		require.NoError(err)

		err = c.SetRetryCounters(11, 12, 13)
		require.NoError(err)

		// Check that resetting code attempts are zero when not resetting code is set
		sts, err := c.GetPasswordStatus()
		require.NoError(err)
		require.Equal(byte(0), sts.AttemptsRC)

		err = c.ChangeResettingCode("my reset code")
		require.NoError(err, "Failed to setup resetting code")

		// Once set, we get the correct number
		sts, err = c.GetPasswordStatus()
		require.NoError(err)
		require.Equal(byte(11), sts.AttemptsPW1)
		require.Equal(byte(12), sts.AttemptsRC)
		require.Equal(byte(13), sts.AttemptsPW3)

		// Try if the new counters are in effect
		for i := 0; i < 5; i++ {
			err = c.VerifyPassword(opc.PW1, "some wrong password")
			require.ErrorIs(err, iso.ErrSecurityStatusNotSatisfied)
		}

		sts, err = c.GetPasswordStatus()
		require.NoError(err)
		require.Equal(byte(11-5), sts.AttemptsPW1)
		require.Equal(byte(12), sts.AttemptsRC)
		require.Equal(byte(13), sts.AttemptsPW3)
	})
}
