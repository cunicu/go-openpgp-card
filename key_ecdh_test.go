// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp_test

import (
	"crypto/ecdh"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	opc "cunicu.li/go-openpgp-card"
)

//nolint:gochecknoglobals
var ecdhCurves = []opc.Curve{
	opc.CurveANSIx9p256r1,
	opc.CurveANSIx9p384r1,
	opc.CurveANSIx9p521r1,
	opc.CurveX25519,
}

func testGenerateKeyECDH(t *testing.T) {
	for _, curve := range ecdhCurves {
		t.Run(curve.String(), func(t *testing.T) {
			withCard(t, true, func(t *testing.T, c *opc.Card) {
				require := require.New(t)

				sk, err := c.GenerateKey(opc.KeyDecrypt, opc.EC(curve))
				if errors.Is(err, opc.ErrUnsupportedKeyType) {
					t.Skip(err)
				}

				require.NoError((err))

				skECDH, ok := sk.(*opc.PrivateKeyECDH)
				require.True(ok)

				pkECDH, ok := skECDH.Public().(*ecdh.PublicKey)
				require.True(ok)

				require.Equal(curve.ECDH(), pkECDH.Curve())

				ki := c.Keys[opc.KeyDecrypt]
				require.Equal(opc.KeyDecrypt, ki.Reference)
				require.Equal(opc.KeyGenerated, ki.Status)
				require.Equal(curve.OID(), ki.AlgAttrs.OID)
				if curve == opc.CurveX25519 {
					require.Equal(opc.AlgPubkeyEdDSA, ki.AlgAttrs.Algorithm)
				} else {
					require.Equal(opc.AlgPubkeyECDH, ki.AlgAttrs.Algorithm)
				}
			})
		})
	}
}

func testImportKeyECDH(t *testing.T) {
	for _, curve := range ecdhCurves {
		t.Run(curve.String(), func(t *testing.T) {
			withCard(t, true, func(t *testing.T, c *opc.Card) {
				require := require.New(t)

				skImport, err := curve.ECDH().GenerateKey(c.Rand)
				require.NoError(err)

				sk, err := c.ImportKey(opc.KeyDecrypt, skImport)
				if errors.Is(err, opc.ErrUnsupportedKeyType) {
					t.Skip(err)
				}

				require.NoError(err)

				skECDH, ok := sk.(*opc.PrivateKeyECDH)
				require.True(ok)

				pkECDH, ok := skECDH.Public().(*ecdh.PublicKey)
				require.True(ok)

				require.Equal(curve.ECDH(), pkECDH.Curve())

				ki := c.Keys[opc.KeyDecrypt]
				require.Equal(opc.KeyDecrypt, ki.Reference)
				require.Equal(opc.KeyImported, ki.Status)
				require.Equal(curve.OID(), ki.AlgAttrs.OID)
				if curve == opc.CurveX25519 {
					require.Equal(opc.AlgPubkeyEdDSA, ki.AlgAttrs.Algorithm)
				} else {
					require.Equal(opc.AlgPubkeyECDH, ki.AlgAttrs.Algorithm)
				}
			})
		})
	}
}

func TestSharedKeyECDH(t *testing.T) {
	for _, curve := range ecdhCurves {
		t.Run(curve.String(), func(t *testing.T) {
			withCard(t, true, func(t *testing.T, c *opc.Card) {
				require := require.New(t)

				skAlice, err := c.GenerateKey(opc.KeyDecrypt, opc.EC(curve))
				require.NoError(err)

				skAliceECDH, ok := skAlice.(*opc.PrivateKeyECDH)
				require.True(ok)

				pkAlice := skAliceECDH.Public()
				pkAliceECDH, ok := pkAlice.(*ecdh.PublicKey)
				require.True(ok)

				skBobECDH, err := curve.ECDH().GenerateKey(c.Rand)
				require.NoError(err)

				pkBob := skBobECDH.Public()
				pkBobECDH, ok := pkBob.(*ecdh.PublicKey)
				require.True(ok)

				ss1, err := skBobECDH.ECDH(pkAliceECDH)
				require.NoError(err)

				err = c.VerifyPassword(opc.PW1forPSO, opc.DefaultPW1)
				require.NoError(err)

				ss2, err := skAliceECDH.ECDH(pkBobECDH)
				require.NoError(err)

				require.Equal(ss1, ss2)
			})
		})
	}
}
