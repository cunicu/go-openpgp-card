// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package s2k

import (
	"errors"
	"hash"
)

var ErrInvalidSaltLength = errors.New("invalid salt length")

// Package s2k implements the various OpenPGP string-to-key transforms as
// specified in RFC 4800 section 3.7.1.

// Iterated writes to out the result of computing the Iterated and Salted S2K
// function (RFC 4880, section 3.7.1.3) using the given hash, input passphrase,
// salt and iteration count.
func Iterated(out []byte, h hash.Hash, in []byte, salt [8]byte, iterations int) {
	combined := append([]byte{}, salt[:]...)
	combined = append(combined, in...)

	for pass := 0; len(out) > 0; pass++ {
		h.Reset()
		for i := 0; i < pass; i++ {
			h.Write([]byte{0})
		}

		cLen := len(combined)

		count := iterations
		if count < cLen {
			count = cLen
		}

		for count > cLen {
			h.Write(combined)
			count -= cLen
		}

		h.Write(combined[:count])

		sz := h.Size()
		if sz > len(out) {
			sz = len(out)
		}

		copy(out, h.Sum(nil)[:sz])
		out = out[sz:]
	}
}
