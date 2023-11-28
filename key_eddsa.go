// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp

import (
	"crypto/ed25519"
	"crypto/sha1" //nolint:gosec
	"encoding/binary"
)

//nolint:unused
type eddsaPublicKey struct {
	ed25519.PublicKey
}

//nolint:unused
type eddsaPrivateKey struct {
	card   *Card
	slot   Slot
	info   KeyInfo
	public *eddsaPublicKey
}

//nolint:unused
func (k eddsaPrivateKey) Fingerprint() []byte {
	buf := []byte{
		0x99, // Prefix
		0, 0, // Packet length
		0x04,       // Version
		0, 0, 0, 0, // Creation timestamp
		byte(k.info.AlgAttrs.Algorithm),
	}

	buf = append(buf, k.info.AlgAttrs.OID...)
	buf = append(buf, k.public.PublicKey...)

	binary.BigEndian.PutUint16(buf[1:], uint16(len(buf)-3))                   // Fill in packet length
	binary.BigEndian.PutUint32(buf[4:], uint32(k.info.GenerationTime.Unix())) // Fill in generation timestamp

	digest := sha1.New() //nolint:gosec
	digest.Write(buf)

	return digest.Sum(nil)
}
