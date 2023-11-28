// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/bits"

	"cunicu.li/go-iso7816"
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

// EncryptAES encrypts a plain text with an AES-key stored in a special DO (D5).
//
// See: OpenPGP Smart Card Application - Section 7.2.12 PSO: ENCIPHER
func (c *Card) EncryptAES(pt []byte) (ct []byte, err error) {
	if c.Capabilities.Flags&CapAES == 0 {
		return nil, errUnsupported
	}

	if n := len(pt) % 16; n != 0 {
		return nil, fmt.Errorf("%w: plaintext length must be multiple of AES block size (16 bytes)", ErrInvalidLength)
	}

	return send(c.tx, iso7816.InsPerformSecurityOperation, 0x86, 0x80, pt)
}

// DecryptAES encrypts a plain text with an AES-key stored in a special DO (D5).
//
// See: OpenPGP Smart Card Application - Section 7.2.12 PSO: ENCIPHER
func (c *Card) DecryptAES(pt []byte) (ct []byte, err error) {
	if c.Capabilities.Flags&CapAES == 0 {
		return nil, errUnsupported
	}

	if n := len(pt) % 16; n != 0 {
		return nil, fmt.Errorf("%w: plaintext length must be multiple of AES block size (16 bytes)", ErrInvalidLength)
	}

	return send(c.tx, iso7816.InsPerformSecurityOperation, 0x86, 0x80, pt)
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
