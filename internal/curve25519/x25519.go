// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package curve25519 implements the new proposed API for
// golang.org/x/crypto/curve25519 from golang.org/issue/32670.
package curve25519

import (
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const (
	// ScalarSize is the size of the scalar input to X25519.
	ScalarSize = 32
	// PointSize is the size of the point input to X25519.
	PointSize = 32
)

// Basepoint is the canonical Curve25519 generator.
var Basepoint []byte

func init() {
	Basepoint = []byte{
		0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

func checkBasepoint() {
	if subtle.ConstantTimeCompare(Basepoint, []byte{
		0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}) != 1 {
		panic("curve25519: global Basepoint value was modified")
	}
}

// X25519 returns the result of the scalar multiplication (scalar * point),
// according to RFC 7748, Section 5. scalar, point and the return value are
// slices of 32 bytes.
//
// scalar can be egenrated at random, for example with crypto/rand. point should
// be either Basepoint or the output of an X25519 call.
//
// If point is Basepoint (but not if it's a different slice with the same
// contents) a precomputed implementation might be used for performance.
func X25519(scalar, point []byte) ([]byte, error) {
	// Outline the body of function, to let the allocation be inlined in the
	// caller, and possibly avoid escaping to the heap.
	var dst [32]byte
	return x25519(&dst, scalar, point)
}

func x25519(dst *[32]byte, scalar, point []byte) ([]byte, error) {
	var in [32]byte
	if l := len(scalar); l != 32 {
		return nil, fmt.Errorf("bad scalar length: %d, expected %d", l, 32)
	}
	if l := len(point); l != 32 {
		return nil, fmt.Errorf("bad point length: %d, expected %d", l, 32)
	}
	copy(in[:], scalar)
	if &point[0] == &Basepoint[0] {
		checkBasepoint()
		curve25519.ScalarBaseMult(dst, &in)
	} else {
		var base, zero [32]byte
		copy(base[:], point)
		curve25519.ScalarMult(dst, &in, &base)
		if subtle.ConstantTimeCompare(dst[:], zero[:]) == 1 {
			// TODO: test this codepath with all low order points.
			return nil, fmt.Errorf("bad input point: low order point")
		}
	}
	return dst[:], nil
}
