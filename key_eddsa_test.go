// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp_test

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	opc "cunicu.li/go-openpgp-card"
)

//nolint:gochecknoglobals
var eddsaCurves = []opc.Curve{opc.CurveEd25519}

func testGenerateKeyEdDSA(t *testing.T) {
	for _, curve := range eddsaCurves {
		t.Run(curve.String(), func(t *testing.T) {
			withCard(t, true, func(t *testing.T, c *opc.Card) {
				require := require.New(t)

				sk, err := c.GenerateKey(opc.KeySign, opc.EC(curve))
				if errors.Is(err, opc.ErrUnsupportedKeyType) {
					t.Skip(err)
				}

				require.NoError((err))

				skEdDSA, ok := sk.(*opc.PrivateKeyEdDSA)
				require.True(ok)

				_, ok = skEdDSA.Public().(ed25519.PublicKey)
				require.True(ok)

				ki := c.Keys[opc.KeySign]
				require.Equal(opc.KeySign, ki.Reference)
				require.Equal(opc.KeyGenerated, ki.Status)
				require.Equal(opc.AlgPubkeyEdDSA, ki.AlgAttrs.Algorithm)
				require.Equal(curve.OID(), ki.AlgAttrs.OID)
			})
		})
	}
}

func testImportKeyEdDSA(t *testing.T) {
	for _, curve := range eddsaCurves {
		t.Run(curve.String(), func(t *testing.T) {
			withCard(t, true, func(t *testing.T, c *opc.Card) {
				require := require.New(t)

				_, skImport, err := ed25519.GenerateKey(c.Rand)
				require.NoError(err)

				sk, err := c.ImportKey(opc.KeySign, skImport)
				if errors.Is(err, opc.ErrUnsupportedKeyType) {
					t.Skip(err)
				}

				require.NoError(err)

				skEdDSA, ok := sk.(*opc.PrivateKeyEdDSA)
				require.True(ok)

				_, ok = skEdDSA.Public().(ed25519.PublicKey)
				require.True(ok)

				ki := c.Keys[opc.KeySign]
				require.Equal(opc.KeySign, ki.Reference)
				require.Equal(opc.KeyImported, ki.Status)
				require.Equal(opc.AlgPubkeyEdDSA, ki.AlgAttrs.Algorithm)
				require.Equal(curve.OID(), ki.AlgAttrs.OID)
			})
		})
	}
}

func testSignEdDSA(t *testing.T) {
	withCard(t, true, func(t *testing.T, c *opc.Card) {
		require := require.New(t)

		sk, err := c.GenerateKey(opc.KeySign, opc.EC(opc.CurveEd25519))
		require.NoError(err)

		skEdDSA, ok := sk.(*opc.PrivateKeyEdDSA)
		require.True(ok)

		pk := skEdDSA.Public()

		pkEdDSA, ok := pk.(ed25519.PublicKey)
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

			_, err = skEdDSA.Sign(nil, digest[:len(digest)-1], nil)
			require.ErrorIs(err, opc.ErrInvalidLength)

			ds, err := skEdDSA.Sign(nil, digest, nil)
			require.NoError(err)

			ok = ed25519.Verify(pkEdDSA, digest, ds)
			require.True(ok)
		}
	})
}
