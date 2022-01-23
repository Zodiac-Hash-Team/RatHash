package api

import (
	"math/big"
	"sync"
	"unsafe"
)

// N.B.: This project is currently InDev.
// Copyright © 2022 Matthew R Bonnette. Licensed under the Apache-2.0 license.
// This file is the reference Go implementation of the RatHash function as contrived by its original
// author. RatHash's developer thanks The Go Authors and the designers of any third-party software
// utilized in this project.

const counter uint64 = 0x9e3779b97f4a7c15

func Sum(msg []byte, ln int) []byte {
	/* Checks that the requested digest length meets the function's requirements */
	if ln < 256 || ln&63 != 0 {
		panic("invalid input: digest length")
	}

	// EXTENSION OR INITIALIZATION
	product := new(big.Int)
	sums := make([]uint64, ln>>6)

	if len(msg) < ln>>2 {
		/* Math on small inputs with specific numbers of leading zeroes can be correctly performed
		by prepending `msg` with a bit. */
		msg = product.SetBytes(append([]byte{1}, msg...)).Mul(ePrimes[(ln-256)>>6], product).Bytes()
	} else {
		tmp := product.SetUint64(counter).Mul(ePrimes[(ln-256)>>6], product).Bytes()[:ln>>3]
		for i := ln>>6 - 1; i >= 0; i-- {
			/* Sums is only modified prior to compression for large inputs */
			sums[i] = *(*uint64)(unsafe.Pointer(&tmp[i<<3]))
		}
	}

	// PARALLEL COMPRESSION OF MESSAGE
	c := coordinates{}
	c.msg = msg
	c.ln = ln
	c.wg = new(sync.WaitGroup)
	c.bSize = len(msg) / (ln >> 3) << 3
	mRem := len(msg) - ln>>6*c.bSize
	c.bRem = mRem / 8
	c.rem = mRem & 7

	c.wg.Add(ln >> 6)
	for i := ln>>6 - 1; i >= 0; i-- {
		go compressBlock(i, sums[i], c)
	}
	c.wg.Wait()

	digest := make([]byte, ln>>3)
	for i := ln>>6 - 1; i >= 0; i-- {
		digest[0+i<<3] = byte(sums[i])
		digest[1+i<<3] = byte(sums[i] >> 8)
		digest[2+i<<3] = byte(sums[i] >> 16)
		digest[3+i<<3] = byte(sums[i] >> 24)
		digest[4+i<<3] = byte(sums[i] >> 32)
		digest[5+i<<3] = byte(sums[i] >> 40)
		digest[6+i<<3] = byte(sums[i] >> 48)
		digest[7+i<<3] = byte(sums[i] >> 56)
	}

	// COMPUTE HASH OF HASH
	msg = product.SetBytes(append([]byte{1}, digest...)).Mul(ePrimes[(ln-256)>>6], product).Bytes()

	c.msg = msg
	c.bSize = len(msg) / (ln >> 3) << 3
	mRem = len(msg) - ln>>6*c.bSize
	c.bRem = mRem / 8 << 3
	c.rem = mRem & 7

	c.wg.Add(ln >> 6)
	for i := ln>>6 - 1; i >= 0; i-- {
		go compressBlock(i, 0, c)
	}
	c.wg.Wait()

	// COMBINE HASHES
	for i := ln>>6 - 1; i >= 0; i-- {
		digest[0+i<<3] ^= byte(sums[i])
		digest[1+i<<3] ^= byte(sums[i] >> 8)
		digest[2+i<<3] ^= byte(sums[i] >> 16)
		digest[3+i<<3] ^= byte(sums[i] >> 24)
		digest[4+i<<3] ^= byte(sums[i] >> 32)
		digest[5+i<<3] ^= byte(sums[i] >> 40)
		digest[6+i<<3] ^= byte(sums[i] >> 48)
		digest[7+i<<3] ^= byte(sums[i] >> 56)
	}

	return digest
}

type coordinates struct {
	msg       []byte
	ln        int
	wg        *sync.WaitGroup
	bSize     int /* block size in bytes */
	bRem      int /* 64-bit words unaccounted for */
	rem       int /* bytes unaccounted for, excluding bRem */
	collector chan results
}

type results struct {
	index int
	value uint64
}

func compressBlock(i int, sum uint64, c coordinates) {
	s, weyl := state{}, counter

	if i == c.ln>>6-1 {
		switch c.rem {
		case 0:
			s.lo = *(*uint64)(unsafe.Pointer(&c.msg[c.bSize*(i+1)-7])) + weyl
		default:
			for ; c.rem > 0; c.rem-- {
				s.lo <<= 8
				s.lo |= uint64(c.msg[c.bSize*(i+1)-c.rem])
			}
			s.lo += weyl
		}
		s.hi = sum
		sum -= s.forward() //^ s.backward()

		for i2 := c.bSize + c.bRem - 16; i2 >= 0; i2 -= 8 {
			weyl += counter
			s.lo += *(*uint64)(unsafe.Pointer(&c.msg[i*c.bSize+i2])) + weyl
			s.hi += sum
			sum -= s.forward() //^ s.backward()
		}
	} else {
		for i2 := c.bSize - 8; i2 >= 0; i2 -= 8 {
			weyl += counter
			s.lo += *(*uint64)(unsafe.Pointer(&c.msg[i*c.bSize+i2])) + weyl
			s.hi += sum
			sum -= s.forward() //^ s.backward()
		}
	}

	c.wg.Add(-1)
	//collector <- results{i, sum}
}
