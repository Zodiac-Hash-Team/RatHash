package rathash

import (
	"math/big"
	"math/bits"
	"sync"
	"unsafe"
)

// N.B.: This project is currently InDev.
// Copyright © 2021 Matthew R Bonnette. Licensed under a BSD-3-Clause license.
/* This file is the reference Go implementation of the RatHash function as contrived by its original
author. RatHash's developer thanks The Go Authors and the developers of any third-party libraries
utilized in this project. */

func Sum(msg []byte, ln int) []byte {
	/* Checks that the requested digest length meets the function's requirements */
	if ln < 256 || ln&63 != 0 {
		panic("invalid input: digest length")
	}
	const phiE19 uint64 = 16180339887498948482
	var (
		mSize = len(msg)
		/* Initializes to zero, but *may* be modified prior to compression */
		sums   = make([]uint64, ln>>6)
		group  sync.WaitGroup
		digest []byte
	)

	// EXTENSION *OR* INITIALIZATION
	const ceiling = len(primes) - 1
	if mSize < ln>>1 {
		/* For small inputs, the algorithm is made sensitive to length-extension and insensitive to
		all-zero inputs by prepending `msg` with the bytes of phiE19. */
		msg = append([]byte{224, 140, 29, 102, 139, 117, 111, 130}, msg...)
		product, prime, two := big.NewInt(0).SetBytes(msg), big.NewInt(0), big.NewInt(2)
		for i := 1; product.BitLen() < ln<<2 || product.BitLen()&63 != 0; i++ {
			if i > ceiling {
				prime.Add(prime, two)
				for prime.ProbablyPrime(1) != true {
					prime.Add(prime, two)
				}
				product.Mul(product, prime)
				continue
			}
			prime.SetUint64(primes[i])
			product.Mul(product, prime)
		}
		msg = product.Bytes()
		mSize = len(msg) /* Updates mSize */
	} else {
		product, prime, two := big.NewInt(0).SetUint64(phiE19), big.NewInt(0), big.NewInt(2)
		for i := 1; product.BitLen() < ln; i++ {
			if i > ceiling {
				prime.Add(prime, two)
				for prime.ProbablyPrime(1) != true {
					prime.Add(prime, two)
				}
				product.Mul(product, prime)
				continue
			}
			prime.SetUint64(primes[i])
			product.Mul(product, prime)
		}
		tmp := product.Bytes()[:ln>>3] /* Truncates to the correct byte count */
		for i := range sums {
			/* Little-endian byte order */
			sums[i] = *(*uint64)(unsafe.Pointer(&tmp[i<<3]))
		}
	}

	// PARALLEL COMPRESSION
	const fermat5, loMask, hiMask uint64 = 4294967297, 0xffffffff00000000, 0x00000000ffffffff
	bSize := (mSize / (ln >> 3)) << 3
	mRem := mSize - (ln >> 6 * bSize)
	rem := mRem & 7

	for i := ln>>6 - 1; i >= 0; i-- {
		group.Add(1)
		go func(i int) {
			var word, hi, lo, weyl uint64
			bRem, sum := mRem/8, sums[i]

			if i == ln>>6-1 {
				switch rem {
				case 7:
					word = bits.ReverseBytes64(uint64(msg[bSize*(i+1)-7])<<56) + phiE19
				case 6:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48) + phiE19
				case 5:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48|
							uint64(msg[bSize*(i+1)-5])<<40) + phiE19
				case 4:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48|
							uint64(msg[bSize*(i+1)-5])<<40|
							uint64(msg[bSize*(i+1)-4])<<32) + phiE19
				case 3:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48|
							uint64(msg[bSize*(i+1)-5])<<40|
							uint64(msg[bSize*(i+1)-4])<<32|
							uint64(msg[bSize*(i+1)-3])<<24) + phiE19
				case 2:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48|
							uint64(msg[bSize*(i+1)-5])<<40|
							uint64(msg[bSize*(i+1)-4])<<32|
							uint64(msg[bSize*(i+1)-3])<<24|
							uint64(msg[bSize*(i+1)-2])<<16) + phiE19
				case 1:
					word = bits.ReverseBytes64(
						uint64(msg[bSize*(i+1)-7])<<56|
							uint64(msg[bSize*(i+1)-6])<<48|
							uint64(msg[bSize*(i+1)-5])<<40|
							uint64(msg[bSize*(i+1)-4])<<32|
							uint64(msg[bSize*(i+1)-3])<<24|
							uint64(msg[bSize*(i+1)-2])<<16|
							uint64(msg[bSize*(i+1)-1])<<8) + phiE19
				default:
					/* Little-endian byte order */
					word = *(*uint64)(unsafe.Pointer(&msg[bSize*(i+1)-7]))
				}
			} else {
				/* Little-endian byte order */
				word = *(*uint64)(unsafe.Pointer(&msg[bSize*(i+1)-7]))
				bRem = 0
			}
			for i2 := bits.OnesCount64(word) >> 1; i2 > 0; i2-- {
				hi, lo = bits.Mul64(word, word)
				word = (lo&loMask | hi&hiMask) + weyl
				weyl += fermat5
			}
			sum ^= word

			for i2 := bSize>>3 + bRem - 2; i2 >= 0; i2-- {
				word = *(*uint64)(unsafe.Pointer(&msg[i*bSize+i2<<3]))
				weyl = 0
				for i3 := bits.OnesCount64(word) >> 1; i3 > 0; i3-- {
					hi, lo = bits.Mul64(word, word)
					word = (lo&loMask | hi&hiMask) + weyl
					weyl += fermat5
				}
				sum ^= word
			}
			sums[i] = sum
			group.Done()
		}(i)
	}
	group.Wait()

	// COMBINATION & DIGEST FORMATION
	for i := ln >> 6; i > 0; i-- {
		ultima := ln>>6 - 1
		penult := ultima - 1
		for penult != -1 {
			sums[penult] ^= sums[ultima]
			ultima--
			penult--
		}
		sums[ln>>6-1] ^= sums[0]
	}

	digest = make([]byte, ln>>3)
	for i := range sums {
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
