// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"cunicu.li/go-iso7816/encoding/tlv"
)

var (
	_ crypto.Signer    = (*rsaPrivateKey)(nil)
	_ crypto.Decrypter = (*rsaPrivateKey)(nil)
)

type rsaPublicKey struct {
	*rsa.PublicKey

	private *rsaPrivateKey
}

type rsaPrivateKey struct {
	card   *Card
	info   KeyInfo
	slot   Slot
	public *rsa.PublicKey
}

func (k *rsaPrivateKey) Public() crypto.PublicKey {
	return k.public
}

// See: OpenPGP Smart Card Application - Section 7.2.10 PSO: COMPUTE DIGITAL SIGNATURE
func (k *rsaPrivateKey) Sign(_ io.Reader, _ /*digest*/ []byte, _ /*opts*/ crypto.SignerOpts) (signature []byte, err error) {
	return nil, errUnsupported
}

// See: OpenPGP Smart Card Application - Section 7.2.11 PSO: DECIPHER
func (k *rsaPrivateKey) Decrypt(_ io.Reader, _ /*msg*/ []byte, _ /*opts*/ crypto.DecrypterOpts) (plaintext []byte, err error) {
	return nil, errUnsupported
}

func (k rsaPrivateKey) Fingerprint() []byte {
	buf := []byte{
		0x99, // Prefix
		0, 0, // Packet length
		0x04,       // Version
		0, 0, 0, 0, // Creation timestamp
		byte(k.info.AlgAttrs.Algorithm),
	}

	buf = appendMPI(buf, k.public.N)
	buf = appendMPI(buf, big.NewInt(int64(k.public.E)))

	binary.BigEndian.PutUint16(buf[1:], uint16(len(buf)-3))                   // Fill in packet length
	binary.BigEndian.PutUint32(buf[4:], uint32(k.info.GenerationTime.Unix())) // Fill in creation timestamp

	digest := sha1.New() // nolint:gosec
	digest.Write(buf)

	return digest.Sum(nil)
}

func decodeRSAPublic(tvs tlv.TagValues) (*rsa.PublicKey, error) {
	_, tvs, ok := tvs.Get(tagPublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: public key", errMissingTag)
	}

	mod, _, ok := tvs.Get(tagModulus)
	if !ok {
		return nil, fmt.Errorf("%w modulus", errUnmarshal)
	}

	exp, _, ok := tvs.Get(tagExponent)
	if !ok {
		return nil, fmt.Errorf("%w exponent", errUnmarshal)
	}

	var n, e big.Int
	n.SetBytes(mod)
	e.SetBytes(exp)

	if !e.IsInt64() {
		return nil, fmt.Errorf("%w: returned exponent too large: %s", ErrInvalidLength, e.String())
	}

	return &rsa.PublicKey{N: &n, E: int(e.Int64())}, nil
}
