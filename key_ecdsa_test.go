// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp_test

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	opc "cunicu.li/go-openpgp-card"
)

//nolint:gochecknoglobals
var ecdsaCurves = []opc.Curve{
	opc.CurveANSIx9p256r1,
	opc.CurveANSIx9p384r1,
	opc.CurveANSIx9p521r1,
}

func testGenerateKeyECDSA(t *testing.T) {
	for _, curve := range ecdsaCurves {
		t.Run(curve.String(), func(t *testing.T) {
			withCard(t, true, func(t *testing.T, c *opc.Card) {
				require := require.New(t)

				sk, err := c.GenerateKey(opc.KeySign, opc.EC(curve))
				if errors.Is(err, opc.ErrUnsupportedKeyType) {
					t.Skip(err)
				}

				require.NoError((err))

				skECDSA, ok := sk.(*opc.PrivateKeyECDSA)
				require.True(ok)

				pkECDSA, ok := skECDSA.Public().(*ecdsa.PublicKey)
				require.True(ok)

				require.Equal(curve.ECDSA(), pkECDSA.Curve)

				ki := c.Keys[opc.KeySign]
				require.Equal(opc.KeySign, ki.Reference)
				require.Equal(opc.KeyGenerated, ki.Status)
				require.Equal(opc.AlgPubkeyECDSA, ki.AlgAttrs.Algorithm)
				require.Equal(curve.OID(), ki.AlgAttrs.OID)
			})
		})
	}
}

func testImportKeyECDSA(t *testing.T) {
	for _, curve := range ecdsaCurves {
		t.Run(curve.String(), func(t *testing.T) {
			withCard(t, true, func(t *testing.T, c *opc.Card) {
				require := require.New(t)

				skImport, err := ecdsa.GenerateKey(curve.ECDSA(), c.Rand)
				require.NoError(err)

				sk, err := c.ImportKey(opc.KeySign, skImport)
				if errors.Is(err, opc.ErrUnsupportedKeyType) {
					t.Skip(err)
				}

				require.NoError(err)

				skECDSA, ok := sk.(*opc.PrivateKeyECDSA)
				require.True(ok)

				pkECDSA, ok := skECDSA.Public().(*ecdsa.PublicKey)
				require.True(ok)

				require.Equal(curve.ECDSA(), pkECDSA.Curve)

				ki := c.Keys[opc.KeySign]
				require.Equal(opc.KeySign, ki.Reference)
				require.Equal(opc.KeyImported, ki.Status)
				require.Equal(opc.AlgPubkeyECDSA, ki.AlgAttrs.Algorithm)
				require.Equal(curve.OID(), ki.AlgAttrs.OID)
			})
		})
	}
}

func testSignECDSA(t *testing.T) {
	for _, curve := range ecdsaCurves {
		t.Run(curve.String(), func(t *testing.T) {
			withCard(t, true, func(t *testing.T, c *opc.Card) {
				require := require.New(t)

				skAlice, err := c.GenerateKey(opc.KeySign, opc.EC(curve))
				require.NoError(err)

				skECDSA, ok := skAlice.(*opc.PrivateKeyECDSA)
				require.True(ok)

				pk := skECDSA.Public()

				pkECDSA, ok := pk.(*ecdsa.PublicKey)
				require.True(ok)

				data := make([]byte, 21422)
				_, err = c.Rand.Read(data)
				require.NoError(err)

				err = c.VerifyPassword(opc.PW1, opc.DefaultPW1)
				require.NoError(err)

				for _, ht := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
					h := ht.New()
					_, err := h.Write(data)
					require.NoError(err)

					digest := h.Sum(nil)

					_, err = skECDSA.Sign(nil, digest[:len(digest)-1], nil)
					require.ErrorIs(err, opc.ErrInvalidLength)

					ds, err := skECDSA.Sign(nil, digest, nil)
					require.NoError(err)

					ok = ecdsa.VerifyASN1(pkECDSA, digest, ds)
					require.True(ok)
				}
			})
		})
	}
}
