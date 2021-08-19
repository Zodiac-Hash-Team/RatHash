package rathash

import (
	"math/big"
	"math/bits"
	"sync"
	"unsafe"
)

// N.B.: This project is currently InDev.
// Copyright © 2021 Matthew R Bonnette. Licensed under a BSD-3-Clause license.
// This file is the reference Go implementation of the RatHash function as contrived by its original
// author. RatHash's developer thanks The Go Authors and the developers of any third-party software
// utilized in this project.

type zipper struct {
	s [4]uint64
}

// Method seed overwrites the current internal state of `z` using a variation of Sebastiano Vigna's
// SplitMix64 PRNG algorithm with seeds `a` and `b`; its outcome is dependent on the previous state.
// The original source can be found at https://xoroshiro.di.unimi.it/splitmix64.c.
func (z *zipper) seed(a, b uint64) {
	const one, two, three = 0x9e3779b97f4a7c15, 0xbf58476d1ce4e5b9, 0x94d049bb133111eb
	z.s[0] ^= a + one
	z.s[0] = (z.s[0] ^ z.s[0]>>30) * two
	z.s[0] = (z.s[0] ^ z.s[0]>>27) * three
	z.s[0] ^= z.s[0] >> 31
	z.s[1] ^= a + one + one
	z.s[1] = (z.s[1] ^ z.s[1]>>30) * two
	z.s[1] = (z.s[1] ^ z.s[1]>>27) * three
	z.s[1] ^= z.s[1] >> 31

	z.s[2] ^= b + one
	z.s[2] = (z.s[2] ^ z.s[2]>>30) * two
	z.s[2] = (z.s[2] ^ z.s[2]>>27) * three
	z.s[2] ^= z.s[2] >> 31
	z.s[3] ^= b + one + one
	z.s[3] = (z.s[3] ^ z.s[3]>>30) * two
	z.s[3] = (z.s[3] ^ z.s[3]>>27) * three
	z.s[3] ^= z.s[3] >> 31
}

// Method next updates the internal state of and returns the next value in the deterministic
// sequence based on `z` using David Blackman's and Sebastiano Vigna's xoshiro256** PRNG algorithm.
// The original source can be found at https://xoroshiro.di.unimi.it/xoshiro256starstar.c.
func (z *zipper) next() uint64 {
	s0, s1, s2, s3 := z.s[0], z.s[1], z.s[2], z.s[3]
	z.s[0] = s0 ^ s3 ^ s1
	z.s[1] = s1 ^ s2 ^ s0
	z.s[2] = (s1 << 17) ^ s2 ^ s0
	z.s[3] = bits.RotateLeft64(s3^s1, 45)
	return bits.RotateLeft64(s1*5, 7) * 9
}

func Sum(msg, mac []byte, ln int) []byte {
	var sum1, sum2 []byte
	if mac != nil {
		/* MACs called to the function must be at least the size of the output. */
		if len(mac) < ln>>3 {
			panic("invalid input: MAC length too short")
		} else {
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				sum1 = halfsum(msg, ln)
				wg.Done()
			}()
			go func() {
				sum2 = halfsum(mac, ln)
				wg.Done()
			}()
			wg.Wait()
		}
	} else {
		sum1 = halfsum(msg, ln)
		sum2 = halfsum(sum1, ln)
	}
	for i := ln>>3 - 1; i >= 0; i-- {
		sum1[i] ^= sum2[i]
	}

	return sum1
}

func halfsum(msg []byte, ln int) []byte {
	/* Checks that the requested digest length meets the function's requirements */
	if ln < 256 || ln&63 != 0 {
		panic("invalid input: digest length")
	}
	const phiE19 uint64 = 16180339887498948482 /* In decimal for easy verification */
	/* Initializes to zero, but *may* be modified prior to compression */
	sums := make([]uint64, ln>>6)
	mSize := len(msg)

	// EXTENSION *OR* INITIALIZATION
	const ceiling = len(primes) - 1
	if mSize < ln>>1 {
		/* For small inputs, the algorithm is made sensitive to length-extension and insensitive to
		all-zero inputs by prepending `msg` with the bytes of phiE19. They are in hexadecimel for
		easy verification. */
		product := new(big.Int).SetBytes(
			append([]byte{0xe0, 0x8c, 0x1d, 0x66, 0x8b, 0x75, 0x6f, 0x82}, msg...))
		prime, width := new(big.Int), product.BitLen()
		for i := 1; (width < ln<<2 || width&63 != 0) && i <= ceiling; i++ {
			width = product.Mul(product, prime.SetUint64(primes[i])).BitLen()
		}
		for two := big.NewInt(2); width < ln<<2 || width&63 != 0; {
			for prime.Add(prime, two).ProbablyPrime(1) == false {
			}
			width = product.Mul(product, prime).BitLen()
		}
		msg = product.Bytes()
		mSize = len(msg) /* Updates mSize */
	} else {
		product, prime, width := new(big.Int).SetUint64(phiE19), new(big.Int), 64
		for i := 1; width < ln && i <= ceiling; i++ {
			width = product.Mul(product, prime.SetUint64(primes[i])).BitLen()
		}
		for two := big.NewInt(2); width < ln; {
			for prime.Add(prime, two).ProbablyPrime(1) == false {
			}
			width = product.Mul(product, prime).BitLen()
		}
		tmp := product.Bytes()[:ln>>3] /* Truncates to the correct byte count */
		for i := range sums {
			/* Little-endian byte order */
			sums[i] = *(*uint64)(unsafe.Pointer(&tmp[i<<3]))
		}
	}

	// PARALLEL COMPRESSION
	var wg sync.WaitGroup
	bSize := (mSize / (ln >> 3)) << 3
	mRem := mSize - (ln >> 6 * bSize)
	rem := mRem & 7

	for i := ln>>6 - 1; i >= 0; i-- {
		wg.Add(1)
		go func(i int) {
			var word uint64
			bRem, sum := mRem/8, sums[i]

			if i == ln>>6-1 {
				switch rem {
				case 7:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56) ^ phiE19
				case 6:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48) ^ phiE19
				case 5:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48|
							uint64(msg[bSize*(i+1)-5])<<40) ^ phiE19
				case 4:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48|
							uint64(msg[bSize*(i+1)-5])<<40|
							uint64(msg[bSize*(i+1)-4])<<32) ^ phiE19
				case 3:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48|
							uint64(msg[bSize*(i+1)-5])<<40|
							uint64(msg[bSize*(i+1)-4])<<32|
							uint64(msg[bSize*(i+1)-3])<<24) ^ phiE19
				case 2:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48|
							uint64(msg[bSize*(i+1)-5])<<40|
							uint64(msg[bSize*(i+1)-4])<<32|
							uint64(msg[bSize*(i+1)-3])<<24|
							uint64(msg[bSize*(i+1)-2])<<16) ^ phiE19
				case 1:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48|
							uint64(msg[bSize*(i+1)-5])<<40|
							uint64(msg[bSize*(i+1)-4])<<32|
							uint64(msg[bSize*(i+1)-3])<<24|
							uint64(msg[bSize*(i+1)-2])<<16|
							uint64(msg[bSize*(i+1)-1])<<8) ^ phiE19
				default:
					/* Little-endian byte order */
					word = *(*uint64)(unsafe.Pointer(&msg[bSize*(i+1)-7]))
				}
			} else {
				/* Little-endian byte order */
				word = *(*uint64)(unsafe.Pointer(&msg[bSize*(i+1)-7]))
				bRem = 0
			}
			prng := new(zipper)
			prng.seed(sum, word)
			sum += prng.next() ^ prng.next() ^ prng.next() ^ prng.next()

			for i2 := bSize>>3 + bRem - 2; i2 >= 0; i2-- {
				/* Little-endian byte order */
				prng.seed(sum, *(*uint64)(unsafe.Pointer(&msg[i*bSize+i2<<3])))
				sum += prng.next() ^ prng.next() ^ prng.next() ^ prng.next()
			}
			sums[i] = sum
			wg.Done()
		}(i)
	}
	wg.Wait()

	// DIGEST FORMATION
	digest := make([]byte, ln>>3)
	for i := ln>>6 - 1; i >= 0; i-- {
		digest[0+i<<3] = byte(sums[i] >> 56)
		digest[1+i<<3] = byte(sums[i] >> 48)
		digest[2+i<<3] = byte(sums[i] >> 40)
		digest[3+i<<3] = byte(sums[i] >> 32)
		digest[4+i<<3] = byte(sums[i] >> 24)
		digest[5+i<<3] = byte(sums[i] >> 16)
		digest[6+i<<3] = byte(sums[i] >> 8)
		digest[7+i<<3] = byte(sums[i])
	}

	return digest
}
