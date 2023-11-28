// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0
package openpgp_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	pgp "cunicu.li/go-openpgp-card"
)

func TestGenerateKey(t *testing.T) {
	cases := []struct {
		slot pgp.Slot
		attr pgp.AlgorithmAttributes
	}{
		// {pgp.SlotSign, pgp.EC(pgp.CurveANSIx9p256r1)},
		// {pgp.SlotDecrypt, pgp.EC(pgp.CurveANSIx9p384r1)},
		// {pgp.SlotAuthn, pgp.EC(pgp.CurveANSIx9p521r1)},
		// {pgp.SlotSign, pgp.RSA(2048)},
		// {pgp.SlotDecrypt, pgp.RSA(2048)},
		{pgp.SlotAuthn, pgp.RSA(2048)},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%s", tc.slot, tc.attr), func(t *testing.T) {
			withCard(t, true, func(t *testing.T, c *pgp.Card) {
				require := require.New(t)

				_, err := c.GenerateKey(tc.slot, tc.attr)
				require.NoError(err)
			})
		})
	}
}

// func TestImportKey(t *testing.T) {
// 	withCard(t, true, func(t *testing.T, c *pgp.Card) {
// 	})
// }

// func TestEncipherAES(t *testing.T) {
// 	withCard(t, true, func(t *testing.T, c *pgp.Card) {
// 	})
// }

func TestSupportedAlgorithms(t *testing.T) {
	withCard(t, false, func(t *testing.T, c *pgp.Card) {
		require := require.New(t)

		algs, err := c.SupportedAlgorithms()
		require.NoError(err)

		for slot, algs := range algs {
			for _, alg := range algs {
				if alg.Algorithm == pgp.AlgPubkeyRSA {
					t.Logf("%s %s-%d (%d)", slot, alg.Algorithm, alg.LengthModulus, alg.LengthExponent)
				} else {
					t.Logf("%s %s %s", slot, alg.Algorithm, alg.Curve())
				}
			}
		}
	})
}

func TestAlgorithmAttributes(t *testing.T) {
	withCard(t, false, func(t *testing.T, c *pgp.Card) {
		require := require.New(t)

		attrs, err := c.AlgorithmAttributes(pgp.SlotSign)
		require.NoError(err)

		t.Log(attrs)
	})
}
