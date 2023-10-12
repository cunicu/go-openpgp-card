// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp_test

import (
	"os"
	"testing"

	"cunicu.li/go-openpgp-card"
	"github.com/ebfe/scard"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCard(t *testing.T) {
	t.Run("FactoryReset", func(t *testing.T) { withCard(t, testFactoryReset) })

	t.Run("VerifyPassword", func(t *testing.T) { withCard(t, testVerifyPassword) })

	t.Run("ChangePassword", func(t *testing.T) { withCard(t, testChangePassword) })

	t.Run("ApplicationRelated", func(t *testing.T) { withCard(t, testGetApplicationRelated) })

	t.Run("CardHolder", func(t *testing.T) { withCard(t, testCardholder) })

	t.Run("GetChallenge", func(t *testing.T) { withCard(t, testGetChallenge) })
}

func withCard(t *testing.T, test func(*testing.T, *openpgp.Card)) {
	require := require.New(t)

	ctx, err := scard.EstablishContext()
	require.NoError(err)

	readers, err := ctx.ListReaders()
	require.NoError(err)
	require.True(len(readers) >= 1)

	sc, err := ctx.Connect(readers[0], scard.ShareShared, scard.ProtocolAny)
	require.NoError(err)

	card, err := openpgp.NewCard(sc)
	require.NoError(err)

	defer card.Close()

	test(t, card)
}

func testGetApplicationRelated(t *testing.T, card *openpgp.Card) {
	require := require.New(t)

	ar, err := card.GetApplicationRelatedData()
	require.NoError(err)

	err = yaml.NewEncoder(os.Stdout).Encode(&ar)
	require.NoError(err)
}

func testCardholder(t *testing.T, card *openpgp.Card) {
	require := require.New(t)

	ch, err := card.GetCardholder()
	require.NoError(err)

	err = yaml.NewEncoder(os.Stdout).Encode(&ch)
	require.NoError(err)
}

func testGetChallenge(t *testing.T, card *openpgp.Card) {
	require := require.New(t)

	rnd1, err := card.GetChallenge(16)
	require.NoError(err)
	require.Len(rnd1, 16)

	rnd2, err := card.GetChallenge(16)
	require.NoError(err)
	require.Len(rnd2, 16)

	require.NotEqual(rnd1, rnd2)
}

func testChangePassword(t *testing.T, card *openpgp.Card) {
	require := require.New(t)

	err := card.ChangePassword(openpgp.PW1, openpgp.DefaultPW1, "hallo")
	require.EqualError(err, "invalid length")

	err = card.ChangePassword(openpgp.PW1, "wrong", "hallohallo")
	require.EqualError(err, "security status not satisfied")

	err = card.ChangePassword(openpgp.PW1, openpgp.DefaultPW1, "hallohallo")
	require.NoError(err)

	err = card.ChangePassword(openpgp.PW1, "hallohallo", "hallohallo2")
	require.NoError(err)

	err = card.ChangePassword(openpgp.PW1, "hallohallo2", openpgp.DefaultPW1)
	require.NoError(err)
}

func testVerifyPassword(t *testing.T, card *openpgp.Card) {
	require := require.New(t)

	for pwType, pw := range map[byte]string{
		// openpgp.PW1: openpgp.DefaultPW1,
		// openpgp.PW2: openpgp.DefaultPW1,
		openpgp.PW3: openpgp.DefaultPW3,
	} {
		err := card.CheckPasswordState(pwType, "wrong")
		require.EqualError(err, "incorrect parameters in the command")

		err = card.VerifyPassword(pwType, pw)
		require.NoError(err)

		err = card.CheckPasswordState(pwType, pw)
		require.NoError(err)

		err = card.ClearPasswordState(pwType)
		require.NoError(err)

		err = card.CheckPasswordState(pwType, "")
		require.Error(err, openpgp.Error(0x6a80))
	}
}

func testFactoryReset(t *testing.T, card *openpgp.Card) {
	require := require.New(t)

	err := card.VerifyPassword(openpgp.PW3, openpgp.DefaultPW3)
	require.NoError(err)

	err = card.FactoryReset()
	require.NoError(err)
}

func testSecuritySupportTemplate(t *testing.T, card *openpgp.Card) {
	require := require.New(t)

	sst, err := card.GetSecuritySupportTemplate()
	require.NoError(err)

	err = yaml.NewEncoder(os.Stdout).Encode(&sst)
	require.NoError(err)
}
