// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"

	"golang.org/x/crypto/openpgp/s2k" //nolint:deprecated
)

var (
	errUnsupportedKDFAlg     = errors.New("unsupported algorithm")
	errUnsupportedKDFHashAlg = errors.New("unsupported hash algorithm")
	errMissingKDFParams      = errors.New("missing parameters")
	errMissingKDFSalt        = errors.New("missing salt")
)

const (
	kdfAlgNone          = 0x00
	kdfAlgIterSaltedS2K = 0x01

	kdfHashAlgSHA256 = 0x08
	kdfHashAlgSHA512 = 0x0A
)

var kdfHashes = map[byte]hash.Hash{
	kdfHashAlgSHA256: sha256.New(),
	kdfHashAlgSHA512: sha512.New(),
}

func (c *Card) derivePassword(pwType byte, pw string) (string, error) {
	if c.kdf == nil {
		return "", errMissingKDFParams
	}

	switch c.kdf.Algorithm {
	case kdfAlgNone:
		return pw, nil

	case kdfAlgIterSaltedS2K:
		hash, ok := kdfHashes[c.kdf.HashAlgorithm]
		if !ok {
			return "", errUnsupportedKDFHashAlg
		}

		var salt []byte
		switch pwType {
		case PW1:
			salt = c.kdf.SaltPW1
		case PW3:
			salt = c.kdf.SaltPW3
		case RC:
			salt = c.kdf.SaltRC
		default:
			return "", errMissingKDFSalt
		}

		out := make([]byte, hash.Size())
		s2k.Iterated(out, hash, []byte(pw), salt, c.kdf.Iterations)

		return string(out), nil
	}

	return "", errUnsupportedKDFAlg
}
