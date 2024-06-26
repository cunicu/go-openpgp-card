// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp_test

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/filter"
	"cunicu.li/go-iso7816/test"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"

	opc "cunicu.li/go-openpgp-card"
)

func TestFactoryReset(t *testing.T) {
	withCard(t, true, func(t *testing.T, c *opc.Card) {
		require := require.New(t)

		err := c.ChangePassword(opc.PW3, opc.DefaultPW3, "somepass")
		require.NoError(err)

		t.Log("Password changed")

		err = c.FactoryReset()
		require.NoError(err)

		err = c.VerifyPassword(opc.PW3, opc.DefaultPW3)
		require.NoError(err)
	})
}

func TestFactoryResetWithDefaultPW(t *testing.T) {
	withCard(t, false, func(t *testing.T, c *opc.Card) {
		require := require.New(t)

		err := c.FactoryReset()
		require.NoError(err)
	})
}

func TestCardHolder(t *testing.T) {
	withCard(t, true, func(t *testing.T, c *opc.Card) {
		require := require.New(t)

		// Initial cardholder infos are empty after reset
		ch, err := c.GetCardholder()
		require.NoError(err)
		require.Empty(ch.Name)
		require.Empty(ch.Language)
		require.Equal(ch.Sex, opc.SexNotApplicable)

		t.Log(spew.Sdump(ch))

		// Authenticate before changing cardholder data
		err = c.VerifyPassword(opc.PW3, opc.DefaultPW3)
		require.NoError(err)

		err = c.SetCardholder(opc.Cardholder{
			Name:     "Steffen Vogel",
			Language: "de",
			Sex:      opc.SexMale,
		})
		require.NoError(err)

		ch, err = c.GetCardholder()
		require.NoError(err)
		require.Equal(ch.Name, "Steffen Vogel")
		require.Equal(ch.Language, "de")
		require.Equal(ch.Sex, opc.SexMale)

		t.Log(spew.Sdump(ch))
	})
}

func TestLoginData(t *testing.T) {
	withCard(t, true, func(t *testing.T, c *opc.Card) {
		require := require.New(t)

		login, err := c.GetLoginData()
		require.NoError(err)
		require.Empty(login)

		// Authenticate before changing cardholder data
		err = c.VerifyPassword(opc.PW3, opc.DefaultPW3)
		require.NoError(err)

		err = c.SetLoginData("stv0g")
		require.NoError(err)

		login, err = c.GetLoginData()
		require.NoError(err)
		require.Equal("stv0g", login)
	})
}

func TestPublicKeyURL(t *testing.T) {
	withCard(t, true, func(t *testing.T, c *opc.Card) {
		require := require.New(t)

		someURL, err := url.Parse("http://example.com/my_key.asc")
		require.NoError(err)

		pkURL, err := c.GetPublicKeyURL()
		require.NoError(err)
		require.Nil(pkURL)

		// Authenticate before changing cardholder data
		err = c.VerifyPassword(opc.PW3, opc.DefaultPW3)
		require.NoError(err)

		err = c.SetPublicKeyURL(someURL)
		require.NoError(err)

		pkURL, err = c.GetPublicKeyURL()
		require.NoError(err)
		require.Equal(someURL.String(), pkURL.String())
	})
}

func TestPrivateData(t *testing.T) {
	for index := 0; index < 4; index++ {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			withCard(t, true, func(t *testing.T, c *opc.Card) {
				var err error
				require := require.New(t)

				switch index {
				case 0, 2:
					err = c.VerifyPassword(opc.RC, opc.DefaultPW1)
				case 1, 3:
					err = c.VerifyPassword(opc.PW3, opc.DefaultPW3)
				}
				require.NoError(err)

				err = c.SetPrivateData(index, []byte{0xca, 0xfe, 0xba, 0xbe})
				require.NoError(err)

				data, err := c.PrivateData(index)
				require.NoError(err)
				require.Equal([]byte{0xca, 0xfe, 0xba, 0xbe}, data)
			})
		})
	}
}

func TestApplicationRelated(t *testing.T) {
	withCard(t, false, func(t *testing.T, c *opc.Card) {
		require := require.New(t)

		ar, err := c.GetApplicationRelatedData()
		require.NoError(err)

		t.Log(spew.Sdump(ar))
	})
}

func TestSecuritySupportTemplate(t *testing.T) {
	withCard(t, false, func(t *testing.T, c *opc.Card) {
		require := require.New(t)

		sst, err := c.GetSecuritySupportTemplate()
		require.NoError(err)

		t.Log(spew.Sdump(sst))
	})
}

func TestChallenge(t *testing.T) {
	withCard(t, false, func(t *testing.T, c *opc.Card) {
		require := require.New(t)

		require.Less(uint16(16), c.Capabilities.MaxLenChallenge)

		t.Logf("c.Capabilities.MaxLenChallenge = %d", c.Capabilities.MaxLenChallenge)

		// Bug: something is fishy here (at least) for macOS which returns a truncated
		// response for the full supported challenge length
		l := int(c.Capabilities.MaxLenChallenge - 16)

		rnd1, err := c.Challenge(l)
		require.NoError(err)
		require.Len(rnd1, l)

		rnd2, err := c.Challenge(l)
		require.NoError(err)
		require.Len(rnd2, l)

		require.NotEqual(rnd1, rnd2)
	})
}

func TestSignatureCounter(t *testing.T) {
	withCard(t, false, func(t *testing.T, c *opc.Card) {
		require := require.New(t)

		// TODO: Generate some signature to test incrementation

		ctr, err := c.GetSignatureCounter()
		require.NoError(err)
		require.Equal(0, ctr)
	})
}

func TestCardholderCertificates(t *testing.T) {
	withCard(t, false, func(t *testing.T, c *opc.Card) {
		require := require.New(t)

		chCerts, err := c.GetCardholderCertificates()
		require.NoError(err)

		t.Log(spew.Sdump(chCerts))
	})
}

func TestCardholderCertificate(t *testing.T) {
	for _, key := range []opc.KeyRef{opc.KeyAuthn, opc.KeyDecrypt, opc.KeySign} {
		t.Run(key.String(), func(t *testing.T) {
			withCard(t, false, func(t *testing.T, c *opc.Card) {
				require := require.New(t)

				chCert, err := c.GetCardholderCertificate(key)
				require.NoError(err)

				t.Log(spew.Sdump(chCert))
			})
		})
	}
}

// constReader is an io.Reader yielding only null-bytes
// We use it as a random number generator for tests
// as we need a deterministic test outputs to satisfy
// the expected method call by your mocked smart-card.
//
// See: https://github.com/golang/go/issues/38548
type constReader struct{}

func (r *constReader) Read(p []byte) (int, error) {
	for i := 0; i < len(p); i++ {
		p[i] = 0xab
	}
	return len(p), nil
}

func withCard(t *testing.T, reset bool, cb func(*testing.T, *opc.Card)) {
	test.WithCard(t, filter.HasApplet(iso.AidOpenPGP), func(t *testing.T, c *iso.Card) {
		require := require.New(t)

		pc, err := opc.NewCard(c)
		require.NoError(err)

		pc.Clock = func() time.Time {
			return time.Unix(1701041348, 0)
		}

		pc.Rand = &constReader{}

		if reset {
			err = pc.FactoryReset()
			require.NoError(err)
		}

		cb(t, pc)

		err = pc.Close()
		require.NoError(err)

		err = c.Close()
		require.NoError(err)
	})
}
