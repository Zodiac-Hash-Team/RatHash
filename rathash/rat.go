package rathash

import (
	"math/big"
	"sync"
	"unsafe"
)

// N.B.: This project is currently InDev.
// Copyright © 2021 Matthew R Bonnette. Licensed under a BSD-3-Clause license.
// This file is the reference Go implementation of the RatHash function as contrived by its original
// author. RatHash's developer thanks The Go Authors and the developers of any third-party software
// utilized in this project.

type xoshiro256starstar struct {
	s0, s1, s2, s3, counter uint64
}

const (
	up, charm, top  = 30, 27, 31
	down, twoDown   = 0x9e3779b97f4a7c15, down & (1<<63 - 1) << 1
	strange, bottom = 0xbf58476d1ce4e5b9, 0x94d049bb133111eb
)

// Method seed01 overwrites the current internal state of `x` using a variation of Sebastiano
// Vigna's SplitMix64 PRNG algorithm with seed `a`; its outcome is dependent on the previous state.
// The original source can be found at https://xoroshiro.di.unimi.it/splitmix64.c.
func (x *xoshiro256starstar) seed01(a uint64) {
	/* Will be inlined */
	x.counter += twoDown
	s0 := x.s0 + a + x.counter - down
	s0 = (s0 ^ s0>>up) * strange
	s0 = (s0 ^ s0>>charm) * bottom
	x.s0 = s0 ^ s0>>top

	s1 := x.s1 + a + x.counter
	s1 = (s1 ^ s1>>up) * strange
	s1 = (s1 ^ s1>>charm) * bottom
	x.s1 = s1 ^ s1>>top
}

// Method seed23 overwrites the current internal state of `x` using a variation of Sebastiano
// Vigna's SplitMix64 PRNG algorithm with seed `b`; its outcome is dependent on the previous state.
// The original source can be found at https://xoroshiro.di.unimi.it/splitmix64.c.
func (x *xoshiro256starstar) seed23(b uint64) {
	/* Will be inlined */
	x.counter += twoDown
	s2 := x.s2 + b + x.counter - down
	s2 = (s2 ^ s2>>up) * strange
	s2 = (s2 ^ s2>>charm) * bottom
	x.s2 = s2 ^ s2>>top

	s3 := x.s3 + b + x.counter
	s3 = (s3 ^ s3>>up) * strange
	s3 = (s3 ^ s3>>charm) * bottom
	x.s3 = s3 ^ s3>>top
}

// Method next updates the internal state of and returns the next value in the deterministic
// sequence based on `z` using David Blackman's and Sebastiano Vigna's xoshiro256** PRNG algorithm.
// The original source can be found at https://xoroshiro.di.unimi.it/xoshiro256starstar.c.
func (x *xoshiro256starstar) next() uint64 {
	/* Will be inlined */
	s0, s1, s2, s3 := x.s0, x.s1, x.s2, x.s3
	x.s0 ^= s3 ^ s1
	x.s1 ^= s2 ^ s0
	x.s2 ^= s0 ^ s1<<17
	x.s3 = (s3^s1)<<45 | (s3^s1)>>19
	return (s1*5<<7 | s1*5>>57) * 9
}

func Sum(msg []byte, ln int) []byte {
	/* Checks that the requested digest length meets the function's requirements */
	if ln < 256 || ln&63 != 0 {
		panic("invalid input: digest length")
	}

	// EXTENSION *OR* INITIALIZATION
	/* Nothing-up-my-sleeve number phiE19 in decimal for easy verification */
	const phiE19, ceiling = 16180339887498948482, len(primes) - 1
	product, prime, width := new(big.Int), new(big.Int), 64
	/* Initializes to zero and is only modified prior to compression for large inputs */
	sums := make([]uint64, ln>>6)
	mSize := len(msg)

	if mSize < ln>>1 {
		/* For small inputs, the algorithm is made sensitive to length-extension and insensitive to
		all-zero inputs by prepending `msg` with the bytes of phiE19. They are in hexadecimel for
		easy verification. */
		width = product.SetBytes(
			append([]byte{0xe0, 0x8c, 0x1d, 0x66, 0x8b, 0x75, 0x6f, 0x82}, msg...)).BitLen()
		for i := 1; width < ln<<2 && i <= ceiling; i++ {
			width = product.Mul(product, prime.SetUint64(primes[i])).BitLen()
		}
		for two := big.NewInt(2); width < ln<<2; {
			for prime.Add(prime, two).ProbablyPrime(1) == false {
			}
			width = product.Mul(product, prime).BitLen()
		}
		msg = product.Bytes()
		mSize = len(msg) /* Updates mSize */
	} else {
		product.SetUint64(phiE19)
		for i := 1; width < ln && i <= ceiling; i++ {
			width = product.Mul(product, prime.SetUint64(primes[i])).BitLen()
		}
		for two := big.NewInt(2); width < ln; {
			for prime.Add(prime, two).ProbablyPrime(1) == false {
			}
			width = product.Mul(product, prime).BitLen()
		}
		tmp := product.Bytes()[:ln>>3] /* Truncates to the correct byte count */
		for i := ln>>6 - 1; i >= 0; i-- {
			/* Little-endian byte order */
			sums[i] = *(*uint64)(unsafe.Pointer(&tmp[i<<3]))
		}
	}

	// PARALLEL COMPRESSION OF MESSAGE
	var wg sync.WaitGroup
	bSize := (mSize / (ln >> 3)) << 3
	mRem := mSize - (ln >> 6 * bSize)
	bRem := mRem / 8
	rem := mRem & 7

	for i := ln>>6 - 1; i >= 0; i-- {
		wg.Add(1)
		go func(i int) {
			prng, sum := xoshiro256starstar{}, sums[i]

			if i == ln>>6-1 {
				switch rem {
				case 7:
					prng.seed23(uint64(msg[bSize*(i+1)-7]))
				case 6:
					prng.seed23(uint64(msg[bSize*(i+1)-7]) |
						uint64(msg[bSize*(i+1)-6])<<8)
				case 5:
					prng.seed23(uint64(msg[bSize*(i+1)-7]) |
						uint64(msg[bSize*(i+1)-6])<<8 |
						uint64(msg[bSize*(i+1)-5])<<16)
				case 4:
					prng.seed23(uint64(msg[bSize*(i+1)-7]) |
						uint64(msg[bSize*(i+1)-6])<<8 |
						uint64(msg[bSize*(i+1)-5])<<16 |
						uint64(msg[bSize*(i+1)-4])<<24)
				case 3:
					prng.seed23(uint64(msg[bSize*(i+1)-7]) |
						uint64(msg[bSize*(i+1)-6])<<8 |
						uint64(msg[bSize*(i+1)-5])<<16 |
						uint64(msg[bSize*(i+1)-4])<<24 |
						uint64(msg[bSize*(i+1)-3])<<32)
				case 2:
					prng.seed23(uint64(msg[bSize*(i+1)-7]) |
						uint64(msg[bSize*(i+1)-6])<<8 |
						uint64(msg[bSize*(i+1)-5])<<16 |
						uint64(msg[bSize*(i+1)-4])<<24 |
						uint64(msg[bSize*(i+1)-3])<<32 |
						uint64(msg[bSize*(i+1)-2])<<40)
				case 1:
					prng.seed23(uint64(msg[bSize*(i+1)-7]) |
						uint64(msg[bSize*(i+1)-6])<<8 |
						uint64(msg[bSize*(i+1)-5])<<16 |
						uint64(msg[bSize*(i+1)-4])<<24 |
						uint64(msg[bSize*(i+1)-3])<<32 |
						uint64(msg[bSize*(i+1)-2])<<40 |
						uint64(msg[bSize*(i+1)-1])<<48)
				default:
					prng.seed23(*(*uint64)(unsafe.Pointer(&msg[bSize*(i+1)-7])))
				}
				prng.seed01(sum)
				sum += prng.next() ^ prng.next() ^ prng.next() ^ ((prng.s1*5<<7 | prng.s1*5>>57) * 9)

				for i2 := bSize>>3 + bRem - 2; i2 >= 0; i2-- {
					prng.seed23(*(*uint64)(unsafe.Pointer(&msg[i*bSize+i2<<3])))
					prng.seed01(sum)
					sum += prng.next() ^ prng.next() ^ prng.next() ^ ((prng.s1*5<<7 | prng.s1*5>>57) * 9)
				}
			} else {
				for i2 := bSize>>3 - 1; i2 >= 0; i2-- {
					prng.seed23(*(*uint64)(unsafe.Pointer(&msg[i*bSize+i2<<3])))
					prng.seed01(sum)
					sum += prng.next() ^ prng.next() ^ prng.next() ^ ((prng.s1*5<<7 | prng.s1*5>>57) * 9)
				}
			}

			sums[i] = sum
			wg.Done()
		}(i)
	}
	wg.Wait()

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
	for i := ln>>6 - 1; i >= 0; i-- {
		sums[i] = 0
	}

	width = product.SetBytes(
		append([]byte{0xe0, 0x8c, 0x1d, 0x66, 0x8b, 0x75, 0x6f, 0x82}, digest...)).BitLen()
	for i := 1; width < ln<<2 && i <= ceiling; i++ {
		width = product.Mul(product, prime.SetUint64(primes[i])).BitLen()
	}
	for two := big.NewInt(2); width < ln<<2; {
		for prime.Add(prime, two).ProbablyPrime(1) == false {
		}
		width = product.Mul(product, prime).BitLen()
	}
	msg = product.Bytes()
	mSize = len(msg)

	bSize = (mSize / (ln >> 3)) << 3
	mRem = mSize - (ln >> 6 * bSize)
	bRem = mRem / 8
	rem = mRem & 7

	for i := ln>>6 - 1; i >= 0; i-- {
		wg.Add(1)
		go func(i int) {
			prng, sum := xoshiro256starstar{}, sums[i]

			if i == ln>>6-1 {
				switch rem {
				case 7:
					prng.seed23(uint64(msg[bSize*(i+1)-7]))
				case 6:
					prng.seed23(uint64(msg[bSize*(i+1)-7]) |
						uint64(msg[bSize*(i+1)-6])<<8)
				case 5:
					prng.seed23(uint64(msg[bSize*(i+1)-7]) |
						uint64(msg[bSize*(i+1)-6])<<8 |
						uint64(msg[bSize*(i+1)-5])<<16)
				case 4:
					prng.seed23(uint64(msg[bSize*(i+1)-7]) |
						uint64(msg[bSize*(i+1)-6])<<8 |
						uint64(msg[bSize*(i+1)-5])<<16 |
						uint64(msg[bSize*(i+1)-4])<<24)
				case 3:
					prng.seed23(uint64(msg[bSize*(i+1)-7]) |
						uint64(msg[bSize*(i+1)-6])<<8 |
						uint64(msg[bSize*(i+1)-5])<<16 |
						uint64(msg[bSize*(i+1)-4])<<24 |
						uint64(msg[bSize*(i+1)-3])<<32)
				case 2:
					prng.seed23(uint64(msg[bSize*(i+1)-7]) |
						uint64(msg[bSize*(i+1)-6])<<8 |
						uint64(msg[bSize*(i+1)-5])<<16 |
						uint64(msg[bSize*(i+1)-4])<<24 |
						uint64(msg[bSize*(i+1)-3])<<32 |
						uint64(msg[bSize*(i+1)-2])<<40)
				case 1:
					prng.seed23(uint64(msg[bSize*(i+1)-7]) |
						uint64(msg[bSize*(i+1)-6])<<8 |
						uint64(msg[bSize*(i+1)-5])<<16 |
						uint64(msg[bSize*(i+1)-4])<<24 |
						uint64(msg[bSize*(i+1)-3])<<32 |
						uint64(msg[bSize*(i+1)-2])<<40 |
						uint64(msg[bSize*(i+1)-1])<<48)
				default:
					prng.seed23(*(*uint64)(unsafe.Pointer(&msg[bSize*(i+1)-7])))
				}
				prng.seed01(sum)
				sum += prng.next() ^ prng.next() ^ prng.next() ^ ((prng.s1*5<<7 | prng.s1*5>>57) * 9)

				for i2 := bSize>>3 + bRem - 2; i2 >= 0; i2-- {
					prng.seed23(*(*uint64)(unsafe.Pointer(&msg[i*bSize+i2<<3])))
					prng.seed01(sum)
					sum += prng.next() ^ prng.next() ^ prng.next() ^ ((prng.s1*5<<7 | prng.s1*5>>57) * 9)
				}
			} else {
				for i2 := bSize>>3 - 1; i2 >= 0; i2-- {
					prng.seed23(*(*uint64)(unsafe.Pointer(&msg[i*bSize+i2<<3])))
					prng.seed01(sum)
					sum += prng.next() ^ prng.next() ^ prng.next() ^ ((prng.s1*5<<7 | prng.s1*5>>57) * 9)
				}
			}

			sums[i] = sum
			wg.Done()
		}(i)
	}
	wg.Wait()

	// COMBINE HASHES
	for i := ln>>6 - 1; i >= 0; i-- {
		digest[0+i<<3] ^= byte(sums[i])
		digest[1+i<<3] += byte(sums[i] >> 8)
		digest[2+i<<3] ^= byte(sums[i] >> 16)
		digest[3+i<<3] += byte(sums[i] >> 24)
		digest[4+i<<3] ^= byte(sums[i] >> 32)
		digest[5+i<<3] += byte(sums[i] >> 40)
		digest[6+i<<3] ^= byte(sums[i] >> 48)
		digest[7+i<<3] += byte(sums[i] >> 56)
	}

	return digest
}
