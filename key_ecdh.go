// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp

import (
	"crypto"
	"crypto/ecdh"
	"crypto/sha1" //nolint:gosec
	"encoding/binary"
	"fmt"
	"io"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/encoding/tlv"
)

var (
	_ crypto.Signer    = (*ecdhPrivateKey)(nil)
	_ crypto.Decrypter = (*ecdhPrivateKey)(nil)
)

type ECPublicKey interface {
	Curve() Curve
	Bytes() []byte
	Equal(x crypto.PublicKey) bool
}

type ecdhPublicKey struct {
	*ecdh.PublicKey
}

func (k *ecdhPublicKey) Curve() Curve {
	switch k.PublicKey.Curve() {
	case ecdh.P256():
		return CurveANSIx9p256r1
	case ecdh.P384():
		return CurveANSIx9p384r1
	case ecdh.P521():
		return CurveANSIx9p521r1
	case ecdh.X25519():
		return CurveX25519
	default:
		panic(errUnsupportedCurve)
	}
}

type ecdhPrivateKey struct {
	card   *Card
	slot   Slot
	info   KeyInfo
	public *ecdhPublicKey
}

func (k *ecdhPrivateKey) Public() crypto.PublicKey {
	return k.public
}

// SharedSecret performs a ECDH operation on the card.
//
// See: OpenPGP Smart Card Application - Section 7.2.11 PSO: DECIPHER
func (k *ecdhPrivateKey) SharedKey(peer ECPublicKey) ([]byte, error) {
	if peer.Curve() != k.public.Curve() {
		return nil, errMismatchingAlgorithms
	}

	data, err := tlv.EncodeBER(
		tlv.New(tagCipher,
			tlv.New(tagPublicKey,
				tlv.New(tagExternalPublicKey, peer.Bytes()),
			),
		),
	)
	if err != nil {
		return nil, err
	}

	return send(k.card.tx, iso.InsPerformSecurityOperation, 0x80, 0x86, data)
}

// See: OpenPGP Smart Card Application - Section 7.2.10 PSO: COMPUTE DIGITAL SIGNATURE
func (k *ecdhPrivateKey) Sign(_ io.Reader, _ /*digest*/ []byte, _ /*opts*/ crypto.SignerOpts) (signature []byte, err error) {
	if c := k.public.Curve(); c == CurveX25519 || c == CurveX448 {
		return nil, errUnsupported
	}

	return nil, errUnsupported
}

// See: OpenPGP Smart Card Application - Section 7.2.11 PSO: DECIPHER
func (k *ecdhPrivateKey) Decrypt(_ io.Reader, _ /*msg*/ []byte, _ /*opts*/ crypto.DecrypterOpts) (plaintext []byte, err error) {
	return nil, errUnsupported
}

func (k ecdhPrivateKey) Fingerprint() []byte {
	buf := []byte{
		0x99, // Prefix
		0, 0, // Packet length
		0x04,       // Version
		0, 0, 0, 0, // Creation timestamp
		byte(k.info.AlgAttrs.Algorithm),
	}

	buf = append(buf, k.info.AlgAttrs.OID...)
	buf = appendBytesMPI(buf, k.public.Bytes())
	buf = appendKDF(buf, AlgHashSHA512, AlgSymAES256) // same default values as Sequoia

	binary.BigEndian.PutUint16(buf[1:], uint16(len(buf)-3))                   // Fill in packet length
	binary.BigEndian.PutUint32(buf[4:], uint32(k.info.GenerationTime.Unix())) // Fill in generation timestamp

	digest := sha1.New() //nolint:gosec
	digest.Write(buf)

	return digest.Sum(nil)
}

func decodeECPublic(tvs tlv.TagValues, curve Curve) (*ecdhPublicKey, error) {
	_, tvs, ok := tvs.Get(tagPublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: public key", errMissingTag)
	}

	p, _, ok := tvs.Get(tagPublicKeyEC)
	if !ok {
		return nil, fmt.Errorf("%w: points", errMissingTag)
	}

	var ecdhCurve ecdh.Curve
	switch curve {
	case CurveANSIx9p256r1:
		ecdhCurve = ecdh.P256()
	case CurveANSIx9p384r1:
		ecdhCurve = ecdh.P384()
	case CurveANSIx9p521r1:
		ecdhCurve = ecdh.P521()
	case CurveX25519:
		ecdhCurve = ecdh.X25519()
	default:
		return nil, errUnsupportedCurve
	}

	pk, err := ecdhCurve.NewPublicKey(p)
	if err != nil {
		return nil, err
	}

	return &ecdhPublicKey{pk}, nil
}
