package api

import (
	. "math/bits"
	"unsafe"
)

// Copyright © 2022 Matthew R Bonnette. Licensed under the Apache-2.0 license.
// Important sub-functions called by the algorithm in calcuating the hash.

/*
func (s *state) pcgmcg128xslrr64() uint64 {
	hi, lo := Mul64(s.lo, pcgLo)
	hi += pcgHi*s.lo + pcgLo*s.hi
	s.hi, s.lo = hi, lo
	return RotateLeft64(hi^lo, int(hi>>58))
}

func (s *state) jsf64() uint64 {
	a, b, c, d := s.a, s.b, s.c, s.d
	s.a = b ^ RotateLeft64(c, 13)
	s.b = c + RotateLeft64(d, 37)
	s.c = a - RotateLeft64(b, 7) + d
	s.d = a - RotateLeft64(b, 7) + b ^ RotateLeft64(c, 13)
	return s.d
}

func (s *state) xoroshiro128ss() uint64 {
	hi, lo := s.hi, s.lo
	s.hi = RotateLeft64(hi, 24) ^ lo ^ hi ^ (lo^hi)<<16
	s.lo = RotateLeft64(lo, 37)
	return RotateLeft64(hi*5, 7) * 9
}
*/

type state struct {
	hi, lo uint64
}

const pcgHi, pcgLo = 2549297995355413924, 4865540595714422341

func (s *state) forward() uint64 {
	a, b := Mul64(s.lo, pcgLo)
	a += pcgHi*s.lo + pcgLo*s.hi
	aa := RotateLeft64(a^b, int(a>>58))

	c, d := Mul64(b, pcgLo)
	c += pcgHi*b + pcgLo*a
	bb := RotateLeft64(c^d, int(c>>58))

	e, f := Mul64(d, pcgLo)
	e += pcgHi*d + pcgLo*c
	cc := RotateLeft64(e^f, int(e>>58))

	// g, h := Mul64(f, pcgLo)
	// g += pcgHi*f + pcgLo*e
	// dd := RotateLeft64(g^h, int(g>>58))

	// e = bb ^ RotateLeft64(cc, 13)
	// f = cc + RotateLeft64(dd, 37)
	// g = aa - RotateLeft64(bb, 7) + dd
	a = aa - RotateLeft64(bb, 7) + bb ^ RotateLeft64(cc, 13)

	// i := e - RotateLeft64(f, 7) + f ^ RotateLeft64(g, 13)

	// o.hi = RotateLeft64(h, 24) ^ i ^ h ^ (h^i)<<16
	// o.lo = RotateLeft64(i, 37)
	return RotateLeft64(a*5, 7) * 9
}

func (s *state) backward() uint64 {
	a, b := s.hi, s.lo
	c := RotateLeft64(a, 24) ^ b ^ a ^ (a^b)<<16
	d := RotateLeft64(b, 37)
	aa := RotateLeft64(a*5, 7) * 9

	e := RotateLeft64(c, 24) ^ d ^ c ^ (c^d)<<16
	f := RotateLeft64(d, 37)
	bb := RotateLeft64(c*5, 7) * 9

	g := RotateLeft64(e, 24) ^ f ^ e ^ (e^f)<<16
	// h := RotateLeft64(f, 37)
	cc := RotateLeft64(e*5, 7) * 9

	dd := RotateLeft64(g*5, 7) * 9

	a = bb ^ RotateLeft64(cc, 13)
	b = cc + RotateLeft64(dd, 37)
	c = aa - RotateLeft64(bb, 7) + dd
	d = aa - RotateLeft64(bb, 7) + bb ^ RotateLeft64(cc, 13)

	e = a - RotateLeft64(b, 7) + b ^ RotateLeft64(c, 13)

	f, g = Mul64(e, pcgLo)
	f += pcgHi*e + pcgLo*d
	return RotateLeft64(f^g, int(f>>58))
}

func goPopcnt(src []byte) uint64 {
	ln, count := len(src), uint64(0)

	for i := ln / 8; i >= 0; i-- {
		count += uint64(OnesCount64(*(*uint64)(unsafe.Pointer(&src[i<<3]))))
	}
	for i := ln & 7; i > 0; i-- {
		count += uint64(OnesCount8(src[ln-i]))
	}

	return count
}
