// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/bits"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/encoding/tlv"
)

type privateKey interface {
	Fingerprint() []byte
}

type ECDHKey interface {
	SharedKey(peer ECPublicKey) ([]byte, error)
}

func (c *Card) ImportKey(_ /*slot*/ Slot, _ /*private*/ crypto.PrivateKey) error {
	return errUnsupported
}

func (c *Card) GenerateKey(slot Slot, attrs AlgorithmAttributes) (crypto.PrivateKey, error) {
	if err := c.changeAlgAttrs(slot, attrs); err != nil {
		return nil, fmt.Errorf("failed to change algorithm attributes: %w", err)
	}

	sk, err := c.generateAsymmetricKeyPair(slot, true)
	if err != nil {
		return nil, err
	}

	i := &c.Keys[slot]

	i.Status = StatusKeyGenerated
	i.GenerationTime = c.Clock()
	i.Fingerprint = sk.Fingerprint()

	ts := make([]byte, 4)
	binary.BigEndian.PutUint32(ts, uint32(i.GenerationTime.Unix()))

	if err := c.putData(slot.tagGenTime(), ts); err != nil {
		return nil, fmt.Errorf("failed to store key generation time: %w", err)
	}

	if err := c.putData(slot.tagFpr(), i.Fingerprint); err != nil {
		return nil, fmt.Errorf("failed to store key fingerprint: %w", err)
	}

	switch sk := sk.(type) {
	case *rsaPrivateKey:
		sk.info = *i
	case *ecdhPrivateKey:
		sk.info = *i
	}

	return sk, nil
}

func (c *Card) PrivateKey(slot Slot) (crypto.PrivateKey, error) {
	return c.generateAsymmetricKeyPair(slot, false)
}

func (c *Card) AlgorithmAttributes(slot Slot) (attrs AlgorithmAttributes, err error) {
	if c.ApplicationRelated, err = c.GetApplicationRelatedData(); err != nil {
		return attrs, err
	}

	return c.Keys[slot].AlgAttrs, nil
}

func (c *Card) SupportedAlgorithms() (map[Slot][]AlgorithmAttributes, error) {
	algs := map[Slot][]AlgorithmAttributes{}

	algInfo, err := c.getData(tagAlgInfo)
	if err != nil {
		return nil, err
	}

	// TODO: Fix?
	if len(algInfo) >= 4 {
		algInfo[3] -= 2
	}

	tvs, err := tlv.DecodeBER(algInfo)
	if err != nil {
		return nil, errUnmarshal
	}

	_, tvs, ok := tvs.Get(tagAlgInfo)
	if !ok {
		return nil, errUnmarshal
	}

	for _, tv := range tvs {
		var slot Slot
		switch tv.Tag {
		case tagAlgAttrsSign:
			slot = SlotSign
		case tagAlgAttrsDecrypt:
			slot = SlotDecrypt
		case tagAlgAttrsAuthn:
			slot = SlotAuthn
		case tagAlgAttrsAttest:
			slot = SlotAttest
		}

		var algAttrs AlgorithmAttributes
		if err := algAttrs.Decode(tv.Value); err != nil {
			return nil, errUnmarshal
		}

		algs[slot] = append(algs[slot], algAttrs)
	}

	return algs, nil
}

// BlockCipher returns a block cipher object for symmetric AES de/encipherment.
func (c *Card) BlockCipher() *BlockCipher {
	return &BlockCipher{c}
}

// ImportKeyAES stores an AES key for symmetric encryption on the card.
// The Key length must be 16 or 32 Byte for AES128 and AES256 respectively.
// For encryption and decryption, use the block cipher object returned by [Card.BlockCipher].
func (c *Card) ImportKeyAES(key []byte) error {
	if c.Capabilities.Flags&CapAES == 0 {
		return fmt.Errorf("%w: AES en/decryption is not supported", ErrUnsupported)
	}

	if len(key) != 16 && len(key) != 32 {
		return fmt.Errorf("%w: AES key length must be either 16 or 32 Bytes", ErrInvalidLength)
	}

	return c.putData(tagKeyAES, key)
}

func (c *Card) algorithmAttributesFromPrivateKey(sk crypto.PrivateKey) (aa AlgorithmAttributes, err error) {
	switch sk := sk.(type) {
	case *rsa.PrivateKey:
		aa.LengthModulus = sk.N.BitLen()

	case *ecdsa.PrivateKey:
		aa.OID = curveFromECDSA(sk.Curve).OID()

	case *ecdh.PrivateKey:
		aa.OID = curveFromECDH(sk.Curve()).OID()

	case ed25519.PrivateKey:
		aa.OID = CurveEd25519.OID()

	default:
		return aa, ErrUnsupportedKeyAttrs
	}

	return aa, nil
}

func (c *Card) findCompatibleAlgorithmAttributes(key KeyRef, attrs AlgorithmAttributes) (aa AlgorithmAttributes, err error) {
	asByKey, err := c.SupportedAlgorithms()
	if err != nil {
		return aa, fmt.Errorf("failed to get supported algorithm attributes: %w", err)
	}

	as, ok := asByKey[key]
	if !ok {
		return aa, ErrUnsupportedKeyAttrs
	}

	for _, a := range as {
		if a.Compatible(attrs) {
			return a, nil
		}
	}

	return aa, ErrUnsupportedKeyAttrs
}

func (c *Card) changeAlgAttrs(slot Slot, attrs AlgorithmAttributes) error {
	if c.Keys[slot].AlgAttrs.Equal(attrs) {
		return nil
	} else if c.Capabilities.Flags&CapAlgAttrsChangeable == 0 {
		return fmt.Errorf("%w: %s key is fixed to %s", errAlgAttrsNotChangeable, slot, c.Keys[slot].AlgAttrs)
	}

	if err := c.putData(slot.tagAlgAttrs(), attrs.Encode()); err != nil {
		return err
	}

	// Update attributes
	c.Keys[slot].AlgAttrs = attrs

	return nil
}

// See: OpenPGP Smart Card Application - Section 7.2.14 GENERATE ASYMMETRIC KEY PAIR
func (c *Card) generateAsymmetricKeyPair(slot Slot, generate bool) (privateKey, error) {
	i := c.Keys[slot]
	if !generate && i.Status == StatusKeyNotPresent {
		return nil, errKeyNotPresent
	}

	p1 := byte(0x81)
	if generate {
		p1 = 0x80
	}

	resp, err := send(c.tx, insGenerateAsymmetricKeyPair, p1, 0, slot.crt())
	if err != nil {
		return nil, err
	}

	tvs, err := tlv.DecodeBER(resp)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnmarshal, err)
	}

	switch i.AlgAttrs.Algorithm {
	case AlgPubkeyRSAEncOnly, AlgPubkeyRSASignOnly, AlgPubkeyRSA:
		pk, err := decodeRSAPublic(tvs)
		if err != nil {
			return nil, err
		}

		return &rsaPrivateKey{
			card:   c,
			info:   i,
			public: pk,
			slot:   slot,
		}, nil

	case AlgPubkeyECDH, AlgPubkeyECDSA:
		pk, err := decodeECPublic(tvs, i.AlgAttrs.Curve())
		if err != nil {
			return nil, err
		}

		return &ecdhPrivateKey{
			card:   c,
			info:   i,
			public: pk,
			slot:   slot,
		}, nil

	default:
		return nil, errUnsupported
	}
}

// Some helpers for creating algorithm attributes

func RSA(bits int) AlgorithmAttributes {
	return AlgorithmAttributes{
		Algorithm:      AlgPubkeyRSA,
		LengthModulus:  uint16(bits),
		LengthExponent: 17,
	}
}

func EC(curve Curve) AlgorithmAttributes {
	return AlgorithmAttributes{
		Algorithm: AlgPubkeyECDH,
		OID:       oidByCurve[curve],
	}
}

func appendMPI(b []byte, i *big.Int) []byte {
	b = append(b, byte(i.BitLen()>>8), byte(i.BitLen()))
	b = append(b, i.Bytes()...)
	return b
}

func appendBytesMPI(b, o []byte) []byte {
	for len(o) != 0 && o[0] == 0 {
		o = o[1:] // Strip leading zero bytes
	}

	var l uint16
	if len(o) > 0 {
		l = 8*uint16(len(o)-1) + uint16(bits.Len8(o[0]))
	}

	b = append(b, byte(l>>8), byte(l))
	b = append(b, o...)
	return b
}

func appendKDF(b []byte, h AlgHash, c AlgSymmetric) []byte {
	return append(b, 3, 0x01, byte(h), byte(c))
}
