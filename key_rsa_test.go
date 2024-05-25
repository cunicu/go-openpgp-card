// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp_test

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"

	"cunicu.li/go-iso7816/drivers/pcsc"
	"github.com/stretchr/testify/require"

	opc "cunicu.li/go-openpgp-card"
)

//nolint:gochecknoglobals
var rsaBits = []int{1024, 2048, 3072, 4096}

func testGenerateKeyRSA(t *testing.T) {
	for _, bits := range rsaBits {
		t.Run(fmt.Sprintf("%d", bits), func(t *testing.T) {
			withCard(t, true, func(t *testing.T, c *opc.Card) {
				require := require.New(t)

				sk, err := c.GenerateKey(opc.KeySign, opc.RSA(bits))
				if errors.Is(err, opc.ErrUnsupportedKeyType) {
					t.Skip(err)
				}

				require.NoError(err)

				skRSA, ok := sk.(*opc.PrivateKeyRSA)
				require.True(ok)
				require.Equal(bits, skRSA.Bits())

				ki := c.Keys[opc.KeySign]
				require.Equal(opc.KeySign, ki.Reference)
				require.Equal(opc.KeyGenerated, ki.Status)
				require.Equal(opc.AlgPubkeyRSA, ki.AlgAttrs.Algorithm)
				require.Equal(bits, ki.AlgAttrs.LengthModulus)
			})
		})
	}
}

func testImportKeyRSA(t *testing.T) {
	for _, bits := range rsaBits {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			withCard(t, true, func(t *testing.T, c *opc.Card) {
				require := require.New(t)

				if _, ok := c.Base().(*pcsc.Card); !ok {
					t.Skip("RSA key generation is not deterministic. Mocked tests are broken")
				}

				skImport, err := rsa.GenerateKey(rand.Reader, bits)
				require.NoError(err)

				sk, err := c.ImportKey(opc.KeySign, skImport)
				if errors.Is(err, opc.ErrUnsupportedKeyType) {
					t.Skip(err)
				}

				require.NoError(err)

				skRSA, ok := sk.(*opc.PrivateKeyRSA)
				require.True(ok)
				require.Equal(bits, skRSA.Bits())

				ki := c.Keys[opc.KeySign]
				require.Equal(opc.KeySign, ki.Reference)
				require.Equal(opc.KeyImported, ki.Status)
				require.Equal(opc.AlgPubkeyRSA, ki.AlgAttrs.Algorithm)
				require.Equal(bits, ki.AlgAttrs.LengthModulus)
			})
		})
	}
}

func testSignRSA(*testing.T) {
}
